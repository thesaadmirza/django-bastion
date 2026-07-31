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
    "MAPPING": {...},
    "BACKEND": "bastion.backends.SSOBackend",
    "SUCCESS_URL": "/",
}
```

## `IDENTITY`

| Key | Default | Meaning |
|---|---|---|
| `KEY` | `("issuer", "subject")` | What accounts are keyed on. **A startup check refuses anything else.** Email is mutable at the provider; keying on it is a live CVE in two shipping packages |
| `LINKING_POLICY` | `"subject_only"` | `"verified_email_once"` links an existing account on first login when the address is verified, then pins to the subject. For migrating an existing user table |
| `REQUIRE_VERIFIED_EMAIL` | `True` | |

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
| `staff_groups` | `()` | Membership grants `is_staff`. **Promote-only** |
| `superuser_groups` | `()` | Membership grants `is_superuser`. **Two-way** — revoked when the group goes |
| `require_mfa` | `False` | Refuses logins whose assertion shows no second factor. Verify with one sign-in first; `amr` is opt-in on several providers |
| `require_group_match` | `False` | Refuse sign-in entirely with no matching group, rather than authenticating without privileges |
| `require_s256` | `True` | Refuses a provider that advertises a PKCE method set **without** S256. A provider that advertises nothing is not refused: the field is optional under RFC 8414 and Entra omits it. Lower this only for a provider whose metadata understates it, and record why |
| `store_id_token` | `False` | Keeps the compact ID token in the session so logout can send `id_token_hint`. Without it the provider may ask the person to confirm the sign-out, which Keycloak does. The cost is a credential in the session store, which is why it is opt-in |
| `post_logout_redirect_uri` | `None` | Where the provider sends the browser after logout. **Must be registered at the provider.** Nothing is sent when unset, deliberately: an unregistered value makes the provider refuse the logout outright rather than fall back, so the provider's own confirmation page is the safer default |

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

## `ADMIN`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `True` | When false, or when no connections exist, the stock password login is served |
| `connection` | `None` | Which connection the admin uses. `None` means the only one |

## `AUDIT`

| Key | Default | Meaning |
|---|---|---|
| `SINKS` | `["bastion.audit.sinks.DatabaseSink"]` | Add `LoggingSink` or your own to ship elsewhere. **The strongest tamper control is a sink under different administrative control** |
| `RETENTION_DAYS` | `365` | Satisfies every regime that names a number. A default, not a requirement — see [data inventory](../security/data-inventory.md) |

## `BREAK_GLASS`

| Key | Default | Meaning |
|---|---|---|
| `ENABLED` | `False` | |
| `ALERT_SINKS` | `[]` | Callables taking `subject` and `detail`, fired synchronously. **A startup check refuses enabled-with-none** |
| `ALLOWED_NETWORKS` | `[]` | CIDRs. Empty means anywhere, which the doctor warns about |
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
| `AUTHENTICATION_BACKENDS` | includes a bastion backend | Errors if `ModelBackend` is present alongside without break-glass configured |
| `SECURE_PROXY_SSL_HEADER` | correct for your proxy | Not checked, and getting it wrong makes the callback URL wrong |

## Check ids

Silenceable individually via `SILENCED_SYSTEM_CHECKS`. Stable; do not renumber.

| Id | Meaning |
|---|---|
| `bastion.E022` | Insecure cookie or missing HSTS |
| `bastion.E023` | Password fallback alongside SSO with no break-glass |
| `bastion.E026` | Identity key is not `(issuer, subject)` |
| `bastion.E100` | Break-glass enabled with no alert sink |
| `bastion.E101` | Break-glass throttling on with no audit database sink to count from |
| `bastion.W030` | Session engine cannot revoke individual sessions |

## Not yet implemented

Declared nowhere, on purpose. Shipping a config surface that does nothing is
worse than not having one.

- `PIPELINE`, `USER_RESOLVER`, `USER_PROVISIONER`, `GROUP_RECONCILER` — arrive
  with the rule engine
- `MAPPING["RULES"]` — the predicate tree, v0.2
- `SCIM` — not built
