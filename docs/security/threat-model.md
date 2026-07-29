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
                             |
                            (3)
                             |
                      [ your database ]
```

1. **Browser to app.** Hostile. Everything in the request is attacker-controlled, including headers that
   look internal.
2. **App to IdP.** Semi-trusted. We chose the IdP, but responses arrive over a channel the browser can
   influence (redirects, POST bindings), and the IdP itself can be compromised or misconfigured.
3. **App to database.** Trusted. If this boundary is breached, nothing here helps.

There is no inbound boundary. SCIM would add one, and it is not built; when it is, this diagram grows a
fourth edge and the sections below grow with it.

## Assets

| Asset | Why an attacker wants it |
|---|---|
| A staff or superuser session | Full read/write on every registered model |
| `staff_groups` and `superuser_groups` in settings | Adding one group name grants standing access, quietly |
| Break-glass credentials | Bypasses SSO by design, so it bypasses every IdP-side control |
| The audit log | Not to read, but to edit, to remove evidence of the above |
| IdP client secrets | Exchange an authorization code as us |

## Threats, by boundary

Each threat below is backed by a test in the adversarial corpus under `tests/`, which mints the malformed
token or forged request directly rather than relying on a library to refuse to build one.

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
| Deprovisioning never reaches us at all | Nothing. Without SCIM there is no inbound signal, so removal takes effect at the next login and not before. Deployments that need faster than that have to drive it themselves |

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
- **The security of the IdP's own login page.** It is third-party content. It has an accessibility
  consequence too: WCAG Conformance Requirement 3 pulls any page in the process into the conformance
  claim, so an inaccessible provider login page is a barrier we cannot fix and must instead document.
- **Clock accuracy.** We record both `occurred_at` and `recorded_at` so skew is visible, but NTP is yours.
- **Application-level authorization beyond role assignment.** We decide who is staff. What staff can do is
  Django's permission system and your code.

## Residual risk we accept

- **Break-glass is a deliberate SSO bypass.** That is its purpose. A written reason is required to create
  one, both outcomes of every attempt are recorded at critical severity, alerting is synchronous, the
  account set can be restricted by network, and `manage.py check` fails with `bastion.E100` if break-glass
  is enabled with no alert sink. It remains the highest-value target in the system.

  Credential failures throttle the address they came from, five in fifteen minutes by default. They never
  throttle the account. That split is the whole point: if failures locked the account, anybody who could
  reach the form could switch off emergency access during the outage it exists for, and they would not
  need a valid password to do it. An address can be abandoned. The fire escape cannot.

  One control you might expect is still absent. There is no expiry on a grant, so an account created for
  one incident stays valid until somebody deactivates it; `bastion_breakglass list` and the staleness
  report exist so that "somebody" has something to work from.
- **The audit log is tamper-evident, not tamper-proof.** Hash chaining tells you the log was edited. It
  cannot stop the edit, and it cannot detect an adversary with database write access who recomputes the
  chain afterwards. Shipping to a system under different administrative control is the control that
  actually holds; the chain is what makes a discrepancy visible when you compare the two.

## Reporting

See [SECURITY.md](../../SECURITY.md). If you find something in the "out of scope" list that you believe
should be in scope, that is a useful report too — say so and we will discuss it here rather than in a
closed issue.
