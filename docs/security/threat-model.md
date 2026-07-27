# Threat model

This page is written before the code it describes, on purpose. It is the document a security team will
read first, and the out-of-scope section at the bottom is what makes the rest of it believable.

Last reviewed: 2026-07-27. Reviewed at every minor release.

## What this package is

A governance layer above a protocol implementation. Signature verification, XML canonicalization and JOSE
primitives are delegated to authlib, pysaml2 and python-ldap. We assert their configuration, re-check
their output structurally, and own everything that happens after an assertion validates.

That division matters for reading this document: some controls below are ours to enforce, some belong to
a library we configure, and some belong to whoever deploys us. Each one says which.

## Trust boundaries

```
 [ browser ] --(1)-- [ your Django app + bastion ] --(2)-- [ identity provider ]
                             |                                       |
                            (3)                                     (4)
                             |                                       |
                      [ your database ]                    [ SCIM push, inbound ]
```

1. **Browser to app.** Hostile. Everything in the request is attacker-controlled, including headers that
   look internal.
2. **App to IdP.** Semi-trusted. We chose the IdP, but responses arrive over a channel the browser can
   influence (redirects, POST bindings), and the IdP itself can be compromised or misconfigured.
3. **App to database.** Trusted. If this boundary is breached, nothing here helps.
4. **SCIM inbound.** Hostile until the bearer token is verified. The token is a superuser-equivalent
   credential.

## Assets

| Asset | Why an attacker wants it |
|---|---|
| A staff or superuser session | Full read/write on every registered model |
| The claims-to-role mapping rules | Editing one rule grants standing access, quietly |
| Break-glass credentials | Bypasses SSO by design, so it bypasses every IdP-side control |
| SCIM bearer tokens | Create, modify and deactivate any account |
| The audit log | Not to read, but to edit, to remove evidence of the above |
| IdP client secrets and signing certificates | Forge assertions for every user |

## Threats, by boundary

The complete enumeration lives in [FOUNDATIONS.md](../../FOUNDATIONS.md) §2, with 37 numbered invariants
and the adversarial test corpus that proves each one. This page summarises the shape.

### Browser to app

| Threat | Control | Enforced by |
|---|---|---|
| Session fixation across the SSO round trip | Pre-auth session is explicitly flushed before `login()`. Django's `login()` only calls `cycle_key()` when no session key is present, so re-login as the same user rotates nothing | us |
| Open redirect via `next` or `RelayState` | `url_has_allowed_host_and_scheme` with an explicit allowlist. `RelayState` is an opaque server-side lookup key, never a URL | us |
| Callback CSRF | Single-use `state`, at least 128 bits, in a server-side transaction record | us |
| Trusted-proxy header spoofing | Refuses to start without both a CIDR allowlist and a shared secret or mTLS. Note `X-Auth-User` and `X-Auth_User` normalise to the same key | us, but see below |

### App to IdP

| Threat | Control | Enforced by |
|---|---|---|
| `alg: none`, algorithm confusion, key injection via `jwk`/`jku`/`x5c` | Asymmetric-only allowlist; keys resolved solely from discovery-derived JWKS; header key parameters stripped | us |
| XML signature wrapping | Identity re-extracted from the signed subtree, and the signed element's identity asserted to match the assertion we consume | us |
| Assertion replay | Shared, durable replay cache with atomic insert-or-fail, consulted before any user lookup | us |
| Unsigned assertion accepted | Startup refuses pysaml2's `want_assertions_signed=False` default, which ships insecure while its own metadata advertises otherwise | us, asserting the library |
| XXE and entity expansion | DTDs, external entities and network access disabled; size and depth capped | us and the library |
| IdP mix-up | RFC 9207 `iss` checked, plus a distinct `redirect_uri` per issuer | us |

### Authorization

| Threat | Control |
|---|---|
| Account takeover via mutable identifiers | Accounts key on `(issuer, subject)`. Email is never the join key |
| Privilege escalation from a truncated group list | `groups_complete=False` blocks any privilege-escalating effect while still permitting login. Entra silently truncates above 150 groups; Okta caps at 100 |
| Claims granting superuser directly | Structurally impossible. Claims map to Groups whose permissions are locally owned |
| Stale privileges after IdP-side removal | Deny-by-default re-evaluation on every login |

### Lifecycle

| Threat | Control |
|---|---|
| Deprovisioned user keeps a live session | Auth-hash rotation via `set_unusable_password()`, plus session-row deletion where the engine permits it. Setting `is_active=False` alone is **not** a session kill; it works only as a side effect of `ModelBackend.get_user()` |
| SCIM token used to mass-deactivate | Bulk operations above a threshold require a second factor |

## Out of scope

We do not defend against any of the following. If your threat model includes them, this package does not
change your position.

- **A compromised identity provider.** If the IdP asserts that an attacker is a member of your admin
  group, we grant admin. We faithfully record that we did.
- **A compromised Django `SECRET_KEY`.** Session integrity, the auth hash and signed cookies all derive
  from it.
- **A hostile `settings.py` or a hostile deployment.** Anyone who can change settings can disable the
  checks that enforce everything above.
- **Database write access.** Hash chaining detects casual tampering. It does not detect an adversary who
  recomputes the chain, and it does not prevent anything. The real control is shipping the log to a system
  under different administrative control.
- **Local privilege escalation, container escape, or host compromise.**
- **Denial of service** beyond the input size and depth caps we document.
- **The security of the IdP's own login page.** It is third-party content. This has an accessibility
  consequence too, covered in FOUNDATIONS.md §9.2.
- **Clock accuracy.** We record both `occurred_at` and `recorded_at` so skew is visible, but NTP is yours.
- **Application-level authorization beyond role assignment.** We decide who is staff. What staff can do is
  Django's permission system and your code.

## Residual risk we accept

- **Break-glass is a deliberate SSO bypass.** That is its purpose. We mitigate with time-boxing, mandatory
  justification, synchronous alerting and independent rate limiting, and we refuse to start if alerting is
  unconfigured. It remains the highest-value target in the system.
- **The SCIM endpoint is an authenticated write API for identities.** Per-tenant tokens, hashed at rest,
  optionally IP or mTLS bound, and structurally unable to grant superuser or touch break-glass accounts.
- **Trusted-proxy header authentication is safe only if the edge strips the header on every inbound
  request.** We verify what we can (source CIDR, shared secret) and fail closed on the rest, but a
  misconfigured proxy is a complete authentication bypass and no amount of application code fixes that.
  We document it loudly and refuse the convenient default.

## Reporting

See [SECURITY.md](../../SECURITY.md). If you find something in the "out of scope" list that you believe
should be in scope, that is a useful report too — say so and we will discuss it here rather than in a
closed issue.
