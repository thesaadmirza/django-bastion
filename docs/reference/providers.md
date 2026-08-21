# Provider matrix

Five provider profiles ship in the quirks registry. They are not equally proven, and the differences
between them are the kind you otherwise meet one at a time during a rollout.

This page says which claims were verified, and how. A row marked from the specification is a reasonable
reading of a document, not a test result.

## How far each profile has been proven

| Provider | Verified how |
|---|---|
| `entra` | **Live.** Discovery, JWKS, key parsing and claim quirks run against Microsoft's endpoints, plus a real tenant during a deployment |
| `google` | **Discovery only.** The live discovery document is public and was read; no sign-in has been driven through it |
| `okta` | From the specification and vendor documentation. No live tenant |
| `keycloak` | From the specification and vendor documentation. No live instance |
| `generic` | Spec defaults. Correct for very little in practice — name your provider |

Nobody should read "from the specification" as broken. It means the failure mode is undiscovered, and the
first person to run it will find out.

## What each provider gives you

| | `entra` | `google` | `okta` | `keycloak` | `generic` |
|---|---|---|---|---|---|
| Account key | `oid` | `sub` | `sub` | `sub` | `sub` |
| Group claim | yes, configured | **none** | yes, off by default | yes | assumed |
| Group values | object GUIDs | — | display names | path or name | unknown |
| Detects a truncated group list | yes, overage pointer | — | **no** | yes | no |
| `end_session_endpoint` | yes | **no** | yes | yes | depends |
| `email_verified` | **absent**, `xms_edov` instead | yes | yes | yes | if sent |
| Tenant boundary | `tid` | `hd` | none | none | none |
| RFC 9207 `iss` | **not advertised** | advertised | depends | depends | depends |

The bold entries are the ones that change what you can build.

## The three that cost the most time

**Google sends no group claim.** Not "sometimes" — the OIDC ID token has no group membership in it, and
the live discovery document lists no group or role claim. So `staff_groups` and `superuser_groups` cannot
match anything, and a Google connection authenticates people without ever granting staff. Group
membership needs an Admin SDK Directory call, which this package does not make.

That is reported as *empty and incomplete*, not empty. The difference matters: marking it complete would
assert this person belongs to no groups, which lets a mapping rule strip privileges on evidence that was
never gathered. Incomplete blocks escalation and leaves existing privileges alone.

**On Google, assign roles locally.** Set `is_staff` on the Django user, or grant through a Django group.
Keep `staff_groups` and `superuser_groups` empty on that connection so nothing implies otherwise.

**Google publishes no `end_session_endpoint`.** Logging out clears the local session and the Google
session survives, so the next click on a protected URL signs the person straight back in with no prompt.
`supports_rp_initiated_logout` reports this, and the logged-out page says so rather than implying a
sign-out that did not happen.

**Okta does not emit `groups` by default,** and above 100 groups it errors on the filter rather than
sending an overage marker. A fresh integration therefore looks like a person in no groups instead of
raising, and a truncated list is not detectable from the token. Add the groups claim to the authorization
server, and confirm one login carries it before relying on mapping.

## MFA

`require_mfa` reads `amr`. **None of the `amr` behaviour below is verified against a live tenant** —
`amr` does not appear in a discovery document, so it cannot be checked without signing in.

| Provider | `amr` values treated as a second factor |
|---|---|
| `entra` | `mfa`, `multipleauthn`, `hwk`, `swk`, `fido`, `wia` |
| `okta` | `mfa`, `otp`, `hwk`, `swk`, `sms`, `kba` |
| `google`, `keycloak`, `generic` | `mfa`, `otp`, `hwk`, `swk` |

`amr` is opt-in on several providers. Where it is absent, `require_mfa` fails closed and refuses everyone,
which is the correct direction and an outage if you turn it on without checking. Drive one sign-in and
look at the claim before enabling it.

## Adding a provider

`REGISTRY` in `protocols/oidc/quirks.py` maps an identifier to a `ProviderQuirks` subclass. A new entry
needs a row here, and a test asserts that: a provider in the registry with no row, or a row naming a
provider that is not registered, fails the suite.
