# Settings

Everything lives under a single `BASTION` dict. That is deliberate: allauth
ships around 134 flat top-level names across six prefixes and three casing
conventions, and mozilla-django-oidc ships 39 including a near-duplicate pair.
One namespace stays reviewable.

**Settings hold code-level extension points and defaults. The database holds
per-connection instance config. No key may be set in both.** allauth's
three-way duality between `APP`, `APPS` and the `SocialApp` model produces
`MultipleObjectsReturned` from a getter, and avoiding that is worth a rule.

## Top level

```python
BASTION = {
    "IDENTITY": {...},
    "CONNECTIONS": {...},
    "ADMIN": {...},
    "AUDIT": {...},
    "BREAK_GLASS": {...},
    "SUCCESS_URL": "/",
}
```

That is all of it. Every key is listed on this page, and a test holds the list
still — see the [deprecation policy](deprecation-policy.md) for what a rename
does and how long an old name keeps failing loudly.

## `IDENTITY`

| Key | Default | Meaning |
|---|---|---|
| `KEY` | `("issuer", "subject")` | What accounts are keyed on. **A startup check refuses anything else.** Email is mutable at the provider; keying on it is a live CVE in two shipping packages |
| `LINKING_POLICY` | `"subject_only"` | `"verified_email_once"` adopts an existing local account on first sign-in, then pins to the subject. For migrating a user table that already has administrators in it. See [Linking an existing user table](#linking-an-existing-user-table) |
| `LINKABLE_EMAIL_DOMAINS` | `[]` | Domains an adoption may cross, e.g. `["example.com"]`. Only read under `verified_email_once`, where it is **required**: `bastion.E029` refuses the policy with an empty list, because the pin is the control that makes it safe |
| `REQUIRE_VERIFIED_EMAIL` | `True` | Refuses a login the provider has **explicitly** marked unverified. `Verified.UNKNOWN` passes, which is the whole reason the tri-state exists: Entra emits no `email_verified` at all, so treating absent as unverified would refuse every Entra login. The name promises more than the behaviour, deliberately, because the alternative fails closed on providers that simply do not say |

### Linking an existing user table

The default never adopts a local account. That is not caution for its own sake:
matching an incoming assertion to a local user by email is django-allauth
CVE-2025-65431, seen in the wild against Okta and NetIQ, and it is the reason
`KEY` is `(issuer, subject)`.

The gap that leaves is real, though, and every project with existing
administrators lives in it. Without linking, each of them gets a second account
on their first SSO sign-in — username taken from the provider's subject, which
for Google is a long number — while the account holding their permissions,
groups and history sits next to it, stranded, waiting for somebody to reconcile
the two by hand.

`"verified_email_once"` closes that, once, under five conditions that are all
necessary:

```python
BASTION = {
    "IDENTITY": {
        "LINKING_POLICY": "verified_email_once",
        "LINKABLE_EMAIL_DOMAINS": ["example.com"],
    },
}
```

1. **The provider says the address is verified.** `Verified.UNKNOWN` is not
   enough here, unlike `REQUIRE_VERIFIED_EMAIL`: that setting refuses a login
   the provider called a lie, while this one hands over an existing account,
   and "the provider did not say" cannot carry that. Entra emits no
   `email_verified` at all, so Entra adopts nothing — use the connection's
   quirks profile and a one-off management step there instead.
2. **The domain is pinned.** Without the pin, anyone who can prove an address at
   any domain the provider will federate can claim the local account that holds
   it.
3. **Exactly one local account holds the address.** `User.email` has no unique
   constraint, so two matches means picking at random. Two matches refuses and
   records why.
4. **That account has no federated identity yet.** Linking happens once. Every
   sign-in afterwards is keyed on `(issuer, subject)` like any other.
5. **That account is not a break-glass account.** The emergency route exists for
   the morning the provider is wrong or unavailable; an account the provider can
   claim through is not that.

### Seeing what it would do first

```console
$ python manage.py bastion_link_preview
```

Walks the local user table and says, per account, what a first sign-in would
do: which would be adopted, which are ambiguous because two accounts share an
address, and which are skipped and why. `--eligible-only` narrows it,
`--json` makes it reviewable in a ticket.

Every eligible row is **conditional on the provider marking that address
verified**, which arrives in the assertion and cannot be known beforehand. The
report says so rather than implying certainty. Entra emits no `email_verified`
at all, so an Entra deployment adopts nothing however the report reads.

There is no apply mode, and there will not be one. Adoption happens at sign-in
against a verified assertion; a command that linked accounts without one would
be matching identities by email, which is the vulnerability this whole design
avoids.

Every outcome is audited. An adoption is a `user.identity_linked` record at
`warning` severity carrying `context.adopted_local_account`, and a refusal to
adopt is the same event type with `outcome=denied` and the reason — because
"linking is on and matched nobody" and "linking is off" look identical from the
outside otherwise.

## `CONNECTIONS`

One entry per provider. Keys map to `Connection` fields.

| Key | Required | Meaning |
|---|---|---|
| `issuer` | yes | Must match the discovery document exactly, trailing slash included |
| `client_id` | yes | |
| `client_secret` | no | Omit for a public client; PKCE then carries the whole defence |
| `provider` | no | `generic`, `entra`, `okta`, `google`, `keycloak`. **The generic profile has no useful behaviour for groups or MFA** — name your provider |
| `quirks_kwargs` | no | Provider-specific. `{"expected_tenant": ...}` for Entra, `{"hosted_domain": ...}` for Google |
| `scopes` | `("openid", "email", "profile")` | |
| `auth_method` | `client_secret_basic` | Or `client_secret_post`, `none` |
| `staff_groups` | `()` | Membership grants `is_staff`. **Promote-only.** Needs a group claim: on Google there is none, so this can never match and roles are assigned locally — see [the provider matrix](providers.md) |
| `superuser_groups` | `()` | Membership grants `is_superuser`. **Two-way** — revoked when the group goes. Same group-claim requirement as above |
| `require_mfa` | `False` | Refuses logins whose assertion shows no second factor. Verify with one sign-in first; `amr` is opt-in on several providers |
| `require_privileged_user` | `False` | Refuse a session entirely to anyone who is neither `is_staff` nor `is_superuser`, rather than authenticating them without privileges. **It reads the flags, not the group claim** — which is why it is the switch to reach for on a provider that publishes no groups at all, Google being the one that matters. Without it every account in the tenant authenticates, holds a Django session, and is stopped only at the admin door. Was `require_group_match`; that key is now refused with a message naming this one, rather than accepted and ignored |
| `persist_refused_identities` | `True` | Whether an identity this connection refuses still gets a `User` row. On by default: the row is the audit trail, and ticking `is_staff` on it is how the first administrator is onboarded. Off means the refusal happens before anything is written, so nobody the provider will authenticate can append to your user table by attempting a login they cannot complete. Only consulted when `require_privileged_user` is on. **Do not turn it off on a connection with no group lists** — nothing could then grant a flag at first sign-in and no row would survive to grant one on; `bastion_doctor` warns about exactly that combination |
| `require_s256` | `True` | Refuses a provider that advertises a PKCE method set **without** S256. A provider that advertises nothing is not refused: the field is optional under RFC 8414 and Entra omits it. Lower this only for a provider whose metadata understates it, and record why |
| `store_id_token` | `False` | Keeps the compact ID token in the session so logout can send `id_token_hint`. Without it the provider may ask the person to confirm the sign-out, which Keycloak does. The cost is a credential in the session store, which is why it is opt-in |
| `post_logout_redirect_uri` | `None` | Where the provider sends the browser after logout. **Must be registered at the provider.** Nothing is sent when unset, deliberately: an unregistered value makes the provider refuse the logout outright rather than fall back, so the provider's own confirmation page is the safer default |

### Extension points

Three more keys take objects rather than data. `settings.py` is Python, so they
are reachable from a settings module that builds one — and they are how the
package is driven from a test, where the fake provider is injected rather than
served.

| Key | Default | Meaning |
|---|---|---|
| `transport` | `UrllibTransport()` | What performs discovery, JWKS and token requests. Replace it for a proxy, a pinned CA bundle, or a fake. Anything with `get_json` and `post_form` |
| `transactions` | `CacheTransactionStore()` | Where the `state` record lives between the authorization request and the callback. The default is Django's cache, which with the per-process `LocMemCache` means a callback can land on a worker that has never heard of the transaction — use a shared cache with more than one worker |
| `validation` | `ValidationPolicy()` | Clock skew tolerance and the rest of the token-validation policy |

`bastion.testing` sets the first two, which is what lets an integration be
tested with no certificate and no local HTTPS server. See
[testing your integration](../how-to/testing-your-integration.md).

### Refused logins still create rows

Worth knowing before you turn `require_privileged_user` on, because it is
surprising: resolution and provisioning happen **before** that gate. A person
the connection refuses has already been given a `User` row and a
`FederatedIdentity` row by the time the refusal is rendered.

That is deliberate and it is useful. The row is the audit trail, and ticking
`is_staff` on it is how the first administrator is onboarded — they sign in, are
refused, and somebody grants the account that just appeared. The cost is that
anybody the identity provider will authenticate can append to your user table by
attempting a login they cannot complete, which on a large tenant is a lot of
rows.

`persist_refused_identities = False` moves the refusal in front of the writes.
The decision is then taken from the claims alone — an identity may provision
when the group claim would grant it staff or superuser through this connection —
so on a connection with no group lists it refuses everyone and leaves no row to
grant anything on. `bastion_doctor` warns about that combination rather than
letting it be discovered during an onboarding.

### Logout

`POST /sso/logout/`, and the admin's own Log out button, end the local session
and then send the browser to the provider's `end_session_endpoint`.

The order is the property: the local session is destroyed first and
unconditionally, so a provider that is unreachable still leaves the person
signed out here. When the provider publishes no `end_session_endpoint` at all,
which is Google, a page says the provider session is still live rather than
redirecting somewhere that implies it is not. The `auth.logout` audit record
carries `context.rp_initiated` to tell the two apart afterwards.

`GET` is refused with a 405. A `GET` that signs people out is reachable from any
third-party page, and on this route it would also bounce the browser at the
provider.

The staff/superuser asymmetry is deliberate: a provider hiccup should not lock
every administrator out of the admin, but a revoked superuser must lose it at
once.

### `SUCCESS_URL`

Where a login lands when nothing said where to go. `/` by default.

A `next` parameter wins over it, having already been host-checked by
`safe_redirect_url` on the way out. The setting itself is **not** validated
against the request host, deliberately: it is deployer configuration rather than
request input, and host-checking it would break the legitimate case of landing
people on a separate front end after sign-in.

`BREAK_GLASS["SUCCESS_URL"]` is a separate value for the emergency route and
defaults to `/admin/`.

## `ADMIN`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `True` | When false, or when no connections exist, the stock password login is served |
| `connection` | `None` | Which connection the admin uses. `None` means the only one |
| `local_login` | `"breakglass_only"` | What a local password is allowed to be in this project, and the answer `bastion.E023` is asking for. `"breakglass_only"`: a password reaches the site only through break-glass, so a `ModelBackend` subclass alongside SSO with break-glass off is refused. `"never"`: no password path at all, refused regardless of break-glass. `"elsewhere"`: passwords serve other parts of this project — a customer portal, an API — and the admin is protected by the SSO admin site rather than by their absence. That last one turns the error into `bastion.W031` rather than silence, because it cannot be verified from here: `AUTHENTICATION_BACKENDS` is global, and any login view in the project can put a password-authenticated session in front of an admin whose own permission test only asks for `is_staff` |
| `require_mfa` | `False` | Refuses **admin** access when the session's assertion showed no second factor, checked on every admin request rather than only at sign-in. Distinct from the per-connection `require_mfa`, which refuses the login outright: use this one when a single factor is enough for the rest of the site. **Verify the claim arrives before turning it on** — `amr` is opt-in on several providers, and this defaults off for that reason |

## `AUDIT`

| Key | Default | Meaning |
|---|---|---|
| `SINKS` | `["bastion.audit.sinks.DatabaseSink"]` | Add `LoggingSink` or your own to ship elsewhere. **The strongest tamper control is a sink under different administrative control** |
| `RETENTION_DAYS` | `365` | Satisfies every regime that names a number. A default, not a requirement — see [data inventory](../security/data-inventory.md) |

## `BREAK_GLASS`

**Advanced, and off by default.** This is an unauthenticated credential
endpoint — the most sensitive surface in the package — so it is deliberately
absent from the quickstart and from the tutorial. Arrive at it by deciding you
need an emergency route, not by following a getting-started page.

Most projects do not. A cloud console that can flip a flag, a shell on the box,
or a second provider all answer "the IdP is down" without adding a login route.

**Do not enable it to satisfy `bastion.E023`.** That check is asking what your
password path is *for*, and the answer for a portal or an API is
`ADMIN["local_login"] = "elsewhere"`. Turning on an emergency credential route
to quiet a check means standing up the surface for the one reason that is not a
reason — and it is what happened to the deployment that reported this.

| Key | Default | Meaning |
|---|---|---|
| `ENABLED` | `False` | Off. See above before changing it |
| `ALERT_SINKS` | `[]` | Callables taking `subject` and `detail`, fired synchronously. **A startup check refuses enabled-with-none** |
| `ALLOWED_NETWORKS` | `[]` | CIDRs. Empty means anywhere, which `bastion.W032` and the doctor both warn about — a warning rather than an error, because an allowlist your office is in is one the hotel you are in at 3am is not. Entries that are not networks are refused outright by `bastion.E102`: `ipaddress` raises on them inside the branch deciding whether to answer an unauthenticated caller |
| `MAX_FAILURES_PER_IP` | `5` | Credential failures from one address before that address is refused. `0` turns the throttle off |
| `FAILURE_WINDOW_SECONDS` | `900` | How far back those failures are counted |
| `SUCCESS_URL` | `"/admin/"` | |

The throttle keys on the source address and never on the account. Locking the
account is what an ordinary login should do and what this one must not: anyone
able to reach the form could then disable emergency access by failing against
it, without needing a valid password.

Failures are counted out of the audit table rather than a cache, so the count
holds across workers and survives a restart. That makes the database sink a
dependency: `manage.py check` fails with `bastion.E101` if the throttle is on
and `bastion.audit.sinks.DatabaseSink` is not configured, rather than leaving a
security control quietly doing nothing.

## Django settings this package cares about

Not ours, but checked:

| Setting | Required value | Why |
|---|---|---|
| `SESSION_COOKIE_SECURE` | `True` | Deploy check errors otherwise |
| `CSRF_COOKIE_SECURE` | `True` | Deploy check errors otherwise |
| `SESSION_COOKIE_HTTPONLY` | `True` | Deploy check errors otherwise |
| `SECURE_HSTS_SECONDS` | non-zero | Deploy check errors otherwise |
| `SESSION_ENGINE` | not `signed_cookies` | Warned. Sessions cannot be individually revoked otherwise |
| `AUTHENTICATION_BACKENDS` | includes a bastion backend | Errors if a `ModelBackend` **subclass** is present alongside without break-glass configured or `ADMIN["local_login"]` declaring why. Backends are imported and tested with `issubclass`, so a `UsernameOrEmailBackend` counts: deleting the parent from the list while keeping the subclass closes nothing |
| `SECURE_PROXY_SSL_HEADER` | correct for your proxy | Not checkable from here — nothing in this process knows what your proxy sends. `bastion_doctor` prints the absolute callback URL it would build and says which setting the scheme came from, so an `http://` where you expected `https://` is one glance rather than a day |

## Check ids

Silenceable individually via `SILENCED_SYSTEM_CHECKS`. Stable; do not renumber.

Some subjects appear twice, as an `E` and a `W` on the same number. That is
deliberate and it is the same finding at two severities: `E027` is a connection
that is wrong, `W027` is one that is merely unfinished or that nothing in the
project can reach. A half-configured environment should boot and say why, and a
typo in a connection nobody is using should not take the site down; a value that
is wrong everywhere still refuses. `bastion_doctor` fails on all of them, which
is the gate to put in a deployment pipeline.

| Id | Meaning |
|---|---|
| `bastion.E022` | Insecure cookie or missing HSTS |
| `bastion.E023` | Password fallback alongside SSO with no break-glass and no declared reason |
| `bastion.E024` | `ADMIN["local_login"]` is not a known value |
| `bastion.E026` | Identity key is not `(issuer, subject)` |
| `bastion.E027` | A connection entry is malformed, and something in this project can reach it |
| `bastion.W027` | A connection entry is incomplete, or is malformed but unreachable |
| `bastion.E028` | The admin names a connection that is not configured, while SSO is live |
| `bastion.W028` | The admin names a connection that is not configured, while SSO is off |
| `bastion.E029` | `IDENTITY["LINKING_POLICY"]` is unknown, or is `verified_email_once` with no pinned domains |
| `bastion.E100` | Break-glass enabled with no alert sink |
| `bastion.E101` | Break-glass throttling on with no audit database sink to count from |
| `bastion.E102` | `ALLOWED_NETWORKS` has an entry that is not a network |
| `bastion.W030` | Session engine cannot revoke individual sessions |
| `bastion.W031` | A password backend serves other parts of the project, declared via `ADMIN["local_login"]` |
| `bastion.W032` | Break-glass enabled with an empty `ALLOWED_NETWORKS` |

## Not yet implemented

Declared nowhere, on purpose. Shipping a config surface that does nothing is
worse than not having one.

- `PIPELINE`, `USER_RESOLVER`, `USER_PROVISIONER`, `GROUP_RECONCILER` — arrive
  with the rule engine
- `MAPPING`, including `STRICT`, `MANAGED_GROUPS` and the `RULES` predicate
  tree — v0.2. Group-to-flag mapping in v0.1 is per-connection, through
  `staff_groups` and `superuser_groups`
- `ADMIN["reauth_max_age"]` — step-up re-authentication is not built
- `BACKEND` — the backend is loaded from `AUTHENTICATION_BACKENDS`, and never
  from here
- `SCIM` — not built

`MAPPING`, `ADMIN["reauth_max_age"]` and `BACKEND` were declared and read by
nothing until recently, which is the failure this section's own rule exists to
prevent: a deployment could set them and get silence. They are names now, not
settings. See the [deprecation policy](deprecation-policy.md).
