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
| `keycloak` | **Live.** A full sign-in driven against Keycloak 26 over TLS: discovery, JWKS, PKCE, the code exchange, group mapping from the full-path claim, and a back-channel logout Keycloak itself posted back |
| `generic` | Spec defaults until configured, and correct for very little until then. [Name your claims](#using-a-provider-that-is-not-listed) or name your provider |

Nobody should read "from the specification" as broken. It means the failure mode is undiscovered, and the
first person to run it will find out.

What "live" bought on Keycloak, since the point of the distinction is that it finds things: the group
claim is absent from the token until a group membership mapper is added to the client, and `sid` only
arrives once *Backchannel logout session required* is on. Both are described below and neither was
discoverable from the specification.

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
| How `--check-registration` sees success | served form | sign-in redirect | unproven | unproven | served form |

The bold entries are the ones that change what you can build.

**The registration probe reports success only on positive evidence.** Three things count: a redirect
back to your own callback URL, a sign-in form in the response body, or a redirect to a sign-in path
the provider's profile names. Nothing counts as success for the absence of an error.

That last route exists because Google serves no form. It answers a good authorization request with a
302 to `/v3/signin/identifier`, so there is no HTML to read and every correctly registered URI was
reported inconclusive. The path is versioned and Google has moved it before; when it moves again the
verdict returns to inconclusive rather than becoming wrong. Okta and Keycloak are unproven here for
the same reason their rows above say so — nobody has run the probe against one and recorded what
came back.

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

## Using a provider that is not listed

Five profiles ship and there are far more than five identity providers. The ones that are missing are
missing in the same way every time: every claim is present, under a name this package has never heard of.

So `generic` is configurable. Point it at the names your provider actually uses, through `quirks_kwargs`:

```python
"corp": {
    "provider": "generic",
    "issuer": "https://example.auth0.com/",
    "client_id": env("BASTION_CLIENT_ID"),
    "client_secret": env("BASTION_CLIENT_SECRET"),
    "quirks_kwargs": {
        "groups_claim": "https://example.com/groups",
        "groups_format": "display_name",
        "expected_claims": {"org_id": "org_abc123"},
    },
    "staff_groups": ["django-staff"],
},
```

| Key | Default | What it is for |
|---|---|---|
| `subject_claim` | `sub` | The stable identifier. Change it where `sub` is pairwise per client and something else is stable |
| `groups_claim` | `groups` | Where group membership lives |
| `groups_format` | `unknown` | What the values mean: `opaque_id`, `display_name`, `full_path`, `qualified`, `sid` |
| `email_claim` | `email` | Where the address lives |
| `email_verified_claim` | `email_verified` | Where the provider's opinion of it lives |
| `mfa_methods` | `mfa`, `otp`, `hwk`, `swk` | `amr` values that count as a second factor. Replaces the defaults rather than adding to them |
| `expected_claims` | none | Claims pinned to exact values. The generic form of the tenant boundary `entra` and `google` hardcode |

**The names are declared, never sniffed.** Nothing inspects a token to work out which claim looks like a
group list. Guessing that is how a package ends up granting staff from a claim an attacker influenced, so
the only supported answer is that somebody reads their provider's documentation and writes the name down.

**Pin your tenant if the provider serves more than one.** Without `expected_claims`, a multi-tenant
provider issues perfectly valid tokens for organisations you have never heard of, and every other check in
this package agrees they are valid. Auth0 organisations, Cognito user pools and Zitadel orgs all need this.

Shapes taken from vendor documentation, and each is covered by a test:

| Provider | `quirks_kwargs` |
|---|---|
| Auth0 | `{"groups_claim": "https://yourapp/groups", "groups_format": "display_name"}` |
| AWS Cognito | `{"groups_claim": "cognito:groups", "groups_format": "display_name"}` |
| Ping Identity | `{"groups_claim": "memberOf", "groups_format": "qualified"}` |
| Zitadel | `{"groups_claim": "urn:zitadel:iam:org:project:roles", "groups_format": "display_name"}` |
| Authentik | none — it is already spec-shaped |

These are **from documentation, not from a live tenant**, the same standard `okta` and `keycloak` are held
to. The first person to run one will find whatever is wrong; the issue tracker is the right place for it.

## When configuration is not enough

Some quirks are not a claim name. A subject assembled from two claims, a group list that arrives
base64-encoded, a vendor that signals truncation its own way — those need code.

Subclass `ProviderQuirks` and give `provider` the import path:

```python
"provider": "myproject.idp.AcmeQuirks",
```

Refused at startup, with the reason, unless it names a `ProviderQuirks` subclass — so a typo pointing at
something unrelated fails on `manage.py check` rather than at somebody's first login.

## Adding a provider to this package

`REGISTRY` in `protocols/oidc/quirks.py` maps an identifier to a `ProviderQuirks` subclass. A new entry
needs a row here, and a test asserts that: a provider in the registry with no row, or a row naming a
provider that is not registered, fails the suite.

A profile earns its place by carrying something configuration cannot express. A provider whose only
difference is where its groups live does not need one — that is what `groups_claim` is for, and a profile
that only sets a claim name is a maintenance obligation in exchange for nothing.
