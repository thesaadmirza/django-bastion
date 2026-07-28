# Foundations

A decision record for an open-source Django enterprise SSO and identity-governance package.

Working module name throughout: `django_sso`. The distribution name is unsettled; see §14.

Every decision below is traceable to research conducted 2026-07-27. Where a claim was not verified, it is
marked **[assumed]** rather than stated as fact. Where two sources disagreed, both are given.

---

## 1. Thesis and scope

### 1.1 The gap, verified

No package in the Django ecosystem has all three of:

1. a real connection/identity table,
2. DB-backed, per-tenant, hot-reloadable configuration,
3. a claims→role mapping engine richer than exact-string group names.

Source-level verification:

| Package | Has (1) | Has (2) | Has (3) |
|---|:--:|:--:|:--:|
| django-allauth | yes — `SocialAccount(provider, uid)` unique | partial — DB *and* settings merged at read time, `MultipleObjectsReturned` from a getter | **no** — SAML `attribute_mapping` targets only `uid/email/name`; single-valued extraction (`attribute_list[0]`) |
| mozilla-django-oidc | **no** — no identity table at all; nothing persists `sub` | no — 39 flat module-level settings read in `__init__` | **no** — `update_user()` is `return user` |
| mozilla-django-oidc-db | no — inherits upstream's gap | **yes** — `OIDCProvider`/`OIDCClient`, plugin registry, JSON-Schema `options` | partial — exact-string names, `superuser_group_names` as a bespoke field |
| djangosaml2 | no | no — opaque `SAML_CONFIG` passthrough | no |
| django-auth-ldap | no | no — settings only | **yes, and it is the best prior art** — `LDAPGroupQuery` is a `django.utils.tree.Node` with full boolean algebra |
| django-scim2 | n/a | n/a | n/a — SCIM only |

Two capabilities are absent from the **entire ecosystem**: an audit log, and break-glass access. A PyPI
check confirmed `django-breakglass`, `django-break-glass`, `django-emergency-access`, `django-jit-access`
and `django-privileged-access` all 404.

### 1.2 Positioning

> **This is not a protocol implementation. It is the governance layer above one.**

Protocol crypto is delegated. Our job is to assert its configuration, re-check its output structurally,
and own everything that happens after an assertion validates.

That division of labour is not a way of doing less work. §2.1 shows the CVE record of those libraries
reduces to nine recurring failure shapes, and a wrapper that calls `lib.verify()` and trusts the boolean
inherits all nine of them.

**Where the boundary sits differs by protocol, and the reason is worth stating.**

For **SAML and LDAP** it sits at the library level: `pysaml2`/`python3-saml` and `python-ldap`. XML
canonicalization and signature verification are genuinely hard, the attack surface is enormous, and
reimplementing them would be reckless.

For **OIDC it sits one level lower, at `cryptography`**, revised during implementation. Every policy
decision a JOSE library makes on our behalf is one we override anyway — we pin the algorithm allowlist,
refuse key material from the header, resolve keys ourselves, and reject unknown `crit`. What remains
delegated is encoding mechanics and the signature check. Meanwhile the CVE record for those libraries is
concentrated in precisely that policy layer: fail-open verification on an unrecognised algorithm, trusting
an embedded `jwk`, accepting `alg: none`, algorithm confusion. Wrapping a library while overriding all its
policy inherits its fail-open bugs and none of its judgement.

The encoding work this leaves us owning is about fifty lines — base64url padding, raw-to-DER for ECDSA,
PSS parameters — and is well understood.

The same reasoning then extended to the token endpoint, which was originally the justification for keeping
`authlib` as a dependency. Writing the exchange made clear it is a form POST and a JSON parse; the part
that genuinely needed care was never putting a response body into an exception or a log, which is exactly
what a general-purpose client does not do for you. So **there is no JOSE or OAuth library in the dependency
list at all.** The OIDC path needs `cryptography` and nothing else, and the HTTP transport is pluggable
with a standard-library default so embedding applications are not forced onto a particular client.

### 1.3 Non-goals

- We do not implement XML canonicalization, XML signature verification, or JOSE primitives.
- We do not implement MFA. We enforce and record its assertion (§9.4, §2.2).
- We are not an identity provider. No OP, no SAML IdP.
- We do not impose a tenancy strategy. `IdentityProvider.organization` is a nullable FK to a swappable
  model, defaulting to null. Schema-per-tenant (django-tenants) is viral and dictates the host project's
  entire migration story; an auth library must not do that.
- We do not claim compliance certification for anything (§8.6).

---

## 2. Threat model and security invariants

### 2.1 The nine failure shapes

The CVE record for our delegated libraries is not a list of unrelated bugs. Each shape below has recurred
across at least three independent libraries.

| # | Shape | Representative instances |
|---|---|---|
| F1 | **Fail-open verification** — unknown algorithm returns "valid" | Authlib `_verify_hash` returns `True` on unknown alg (CVE-2026-28498); xmlsec1 HMAC truncation to 0 bits (CVE-2009-0217); Authlib `alg:none` (CVE-2026-28802) |
| F2 | **Key material taken from the attacker-controlled message** | Authlib trusts embedded `jwk` header (CVE-2026-27962, critical); pysaml2/xmlsec1 "accepts any type of key found within the given document" (CVE-2021-21239) |
| F3 | **Algorithm family not pinned** (RSA public key used as HMAC secret) | PyJWT CVE-2017-11424, -2022-29217, -2026-48526, -2026-48523; python-jose CVE-2024-33663; SignXML CVE-2025-48994 |
| F4 | **Verifier and consumer disagree about the document** (XSW, parser differential) | pysaml2 CVE-2021-21238; python-saml CVE-2016-1000252; comment-truncation CVE-2017-11427…11430, CVE-2018-0489; attribute pollution / void canonicalization CVE-2025-66567/66568 |
| F5 | **Insecure-by-default configuration** | pysaml2 `want_assertions_signed=False` *while its own metadata advertises `WantAssertionsSigned="true"`* — open since 2017; python3-saml `strict=False` |
| F6 | **Mutable identifier used for authorization** | django-allauth CVE-2025-65431 (Okta, NetIQ); PyJWT issuer partial match CVE-2024-53861 |
| F7 | **Unbounded resource consumption inside the crypto path** | JWE `zip=DEF` bomb CVE-2025-62706; oversized JOSE segments CVE-2025-61920; JWKS fetch amplification via `kid` CVE-2026-48524; XXE CVE-2016-10127, lxml CVE-2026-41066 |
| F8 | **Open redirect in the return-URL parameter** | Authlib CVE-2026-41479, -2026-44681; django-allauth CVE-2026-27982 |
| F9 | **Lifecycle gap — valid token, dead account** | django-allauth CVE-2025-65430 (tokens accepted for inactive users) |

Maintenance signal worth acting on: authlib has 24 OSV entries, 11 of them in the last 15 months. Any
version floor we pin goes stale within a quarter, so dependency alerting has to be wired in from day one.

Absence of advisories is not evidence of safety. `djangosaml2`, `mozilla-django-oidc`, `django-auth-ldap`,
`python3-saml` and the `xmlsec` PyPI binding each have **zero** OSV entries. For `xmlsec` in particular the
real attack surface is `libxmlsec1`/`libxml2`, tracked under OS package names — **a `pip-audit` run will
never see them.** Requires an OS-package scanner (Trivy/Grype) in addition.

### 2.2 Security invariants

Default-on. Each is phrased as a testable assertion. `PKG` = we enforce in code; `LIB` = delegated but we
assert configuration; `DEP` = deployer, and we fail startup if unverifiable.

**Cryptographic verification**

1. Every JWT decode passes an explicit, non-empty algorithm allowlist containing **only asymmetric**
   algorithms. `assert "none" not in allowed and not any(a.startswith("HS") for a in allowed)`. `PKG`
2. No verification key is ever sourced from the token or document. `jwk`, `jku`, `x5u`, `x5c` are stripped
   before verification; `ds:KeyInfo` is ignored for trust. `PKG`
3. The key resolver **raises** on unresolved `kid`. It never returns `None`, and no code path reads "no
   key" as "no signature required". `PKG`
4. Any verification helper that cannot compute a result returns **failure**. No `if not x: return True`. `PKG`
5. `at_hash`/`c_hash` are computed by us from the pinned algorithm; "cannot compute" is a failure. `PKG`
6. XML signature algorithms restricted to RSA/ECDSA with SHA-256 or stronger. SHA-1 and all HMAC-based XML
   signature algorithms rejected **before** the document reaches xmlsec. `PKG`
7. Any token carrying an unrecognised `crit` header member is rejected. `PKG`

**Message binding**

8. Every OIDC authorization request carries `state` (≥128 bits CSPRNG), `nonce` (≥128 bits), and PKCE
   `S256`, **including for confidential clients**. `PKG`
9. `state`, `nonce`, `code_verifier` live in a **server-side** transaction record keyed by an opaque id,
   TTL ≤10 minutes, single-use, deleted atomically on consumption. `PKG`
10. RFC 9207 `iss` required and exact-matched when the provider advertises support; a distinct
    `redirect_uri` is registered per issuer regardless (mix-up defence). `PKG`
11. `nonce` validated against the ID token from the **token endpoint**; all tokens discarded on failure. `PKG`
12. `iss` exact match, `aud` contains `client_id`, no untrusted extra audiences, and `azp == client_id`
    whenever `aud` is multi-valued. **This last is stricter than the spec — see §14.** `PKG`
13. UserInfo claims discarded entirely unless `userinfo.sub == id_token.sub` (OIDC Core §5.3.2, verbatim MUST). `PKG`
14. Every SAML Response is bound to a server-side pending-request record via `InResponseTo`. `PKG`
15. `Assertion/@ID` inserted into a **shared, durable** replay cache with atomic insert-or-fail *before* any
    user lookup. Retention ≥ `NotOnOrAfter` + skew. Must survive process restart. `PKG`
16. Identity attributes are re-extracted from the **signed subtree**, and we assert the signed subtree's
    element identity matches the assertion we consume. This is the XSW defence. `PKG`
17. `Destination`, `Recipient`, `AudienceRestriction`, `NotBefore`, `NotOnOrAfter` all present and
    validated. Missing → reject. `PKG`
18. NameID elements containing any child node other than a single text node are rejected. **Do not rely on
    pysaml2's comment immunity** — it is an accident of `xml.etree.ElementTree` discarding comments, not a
    designed guarantee, and evaporates silently if the parser changes. `PKG`
19. XML parsed with DTDs, external entities and network access disabled, under byte-size and nesting-depth
    caps. `PKG` + `LIB`

**Configuration assertions (Django system checks, deploy-blocking)**

20. Startup fails if `want_response_signed` or `want_assertions_signed` is not `True`, if
    `allow_unsolicited` is `True` without an explicit per-IdP opt-in, or if IdP trust is fingerprint-based. `PKG`→`LIB`
21. Startup fails if a trusted-proxy backend is enabled without **both** `trusted_proxy_cidrs` and a
    shared-secret/mTLS assertion. `PKG`
22. Startup fails in production if `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` or
    `SESSION_COOKIE_HTTPONLY` is falsy, or `SECURE_HSTS_SECONDS == 0`. Django's defaults are all wrong for
    this use case. `PKG` check, `DEP` fix
23. Startup fails if an SSO backend and `ModelBackend` are both enabled with no break-glass allowlist. `PKG`
24. Startup fails if a delegated library is below its advisory floor. Re-pin every release. `PKG`
25. Startup **warns** if any configured auth backend's `get_user()` does not call `user_can_authenticate()`
    — see §7.3 for why this is a session-invalidation correctness issue, not hygiene. `PKG`

**Identity and lifecycle**

26. Accounts are keyed on `(issuer, immutable_subject)`. Email, `preferred_username`, UPN and any display
    attribute are **never** the join key and never grant authorization. `PKG`
27. JIT-provisioned users always get `set_unusable_password()`. `PKG`
28. Mapping is deny-by-default. An unmapped claim grants nothing; claim loss revokes on next login;
    `is_superuser` **can never be granted by claim mapping**. `PKG`
29. `is_active`, and for admin `is_staff`, re-evaluated on **every request** from an SSO-backed session, not
    cached from login (this is exactly django-allauth CVE-2025-65430). `PKG`
30. Deprovision synchronously deletes sessions, revokes refresh tokens, and emits an audit record. `PKG`
31. `groups_complete == False` is a **hard failure for privilege escalation**, while still permitting login.
    You cannot grant staff or superuser off a truncated group list. No existing package does this. `PKG`

**Redirect and transport**

32. Every return URL passes `url_has_allowed_host_and_scheme(allowed_hosts={request.get_host(), *extra},
    require_https=request.is_secure())`. Note this allowlist is **not** `ALLOWED_HOSTS`. `PKG`
33. RelayState is an opaque server-side lookup key, never a URL. `PKG`
34. Callback responses carry `Referrer-Policy: no-referrer` and redirect off the callback URL immediately. `PKG`
35. The pre-auth session is **explicitly flushed** after validating the assertion and before `login()`. See
    §7.3 — `login()` does not reliably rotate. `PKG`

**Audit**

36. Every authentication decision — success, failure, and *reason* — emits an append-only record. Audit
    writes are not conditional on the auth succeeding. `PKG`
37. Break-glass logins emit a distinct high-severity event and are rate-limited independently of SSO. `PKG`

### 2.3 Anti-requirements: what we refuse to make easy

| # | Refused | Rationale |
|---|---|---|
| A1 | Any `verify=False` / `insecure=True` / `skip_signature_check` flag | Every such flag reaches production. Test doubles belong in the test suite, not the API |
| A2 | `alg: none`, even in the code flow with explicit registration that OIDC Core permits | Deliberate spec deviation, documented. Not worth the bug class (CVE-2026-28802) |
| A3 | HMAC ID-token signing (`HS*`) | Removes the entire algorithm-confusion class (F3) rather than guarding it |
| A4 | Fingerprint-based IdP certificate trust | Collision-prone; python3-saml's own docs warn against it |
| A5 | Email — or any IdP-mutable attribute — as the account join key | django-allauth CVE-2025-65431 |
| A6 | Auto-enabled IdP-initiated SSO | Removes `InResponseTo`, the only binding between assertion and browser transaction. Named, audited, per-IdP opt-in only |
| A7 | Trusted-proxy header auth that "just works" on `runserver` | Convenience here is a remote pre-auth bypass |
| A8 | Granting `is_superuser` or `Permission` objects directly from claims | Claims are IdP-controlled. Map to Groups whose permission sets are locally owned and reviewable |
| A9 | A single "SSO or password, whichever works" backend chain | The point of enterprise SSO is that the password path is gone. Silent fallback is the control's negation |
| A10 | Storing transaction state only in a `SameSite=Lax` cookie | For SAML POST and OIDC `form_post` the cookie is not sent cross-site; teams then set `SameSite=None` globally and re-open CSRF everywhere |
| A11 | Arbitrary Python in the mapping engine | Authentik's own docs admit DB-write becomes RCE. Disqualifying for a governance product |
| A12 | Bulk SCIM operations that deactivate more than a threshold without a second factor | A compromised SCIM token otherwise becomes org-wide DoS in one request |
| A13 | Audit records editable or deletable through Django admin | The log is the artifact of record |
| A14 | Advertising an AAL we cannot substantiate | SP 800-63C: the RP may *report* the IdP's asserted `acr`/`amr`; it may not *claim* an AAL the assertion did not carry |

### 2.4 The adversarial test corpus

The security test suite is a deliverable, not a by-product. Minimum contents, each a regression for a named
CVE class:

- **OIDC (17 tests):** `alg:none`; RSA-public-key-as-HMAC; attacker `jwk` header self-consistently signed
  (assert the resolver *raised*, not that it returned `None`); unknown-alg fail-open `at_hash`; unknown
  `crit`; cross-transaction `state`; replayed `state`; code injection across transactions; PKCE downgrade at
  discovery; mix-up via wrong `iss`; multi-`aud` without `azp`; `iss` differing by trailing slash; UserInfo
  `sub` mismatch; JWKS fetch rate limit under 100 random `kid`s; `file://`/`data:` JWKS URI; JWE `zip` bomb
  and 10 MB token; four open-redirect `next` forms.
- **SAML (15 tests):** an **8-position XSW corpus** (signed assertion in `Extensions`, in a wrapper
  `Object`, sibling-before, sibling-after, nested inside the forgery, Response-level signature with swapped
  assertion, duplicated `ID`, `Reference URI` pointing at a wrapper); comment truncation; five XXE variants
  **with a socket guard asserting no outbound request**; signed-response-unsigned-assertion and vice versa;
  unsigned assertion under pysaml2's default → **assert the startup check fires**; `Destination` mismatch;
  wrong `AudienceRestriction`; three condition-window failures; replay across a **process restart**;
  missing/mismatched `InResponseTo`; `KeyInfo`-embedded cert absent from metadata; SHA-1 signature;
  attribute pollution and namespace redefinition.
- **Django (9 tests):** session key differs across all four login state combinations; state/nonce/verifier
  absent post-login; SCIM-deactivated user anonymous on the very next request **with the session row gone**;
  SSO user cannot authenticate at `/admin/login/` with any password; `PermissionDenied` aborts the backend
  chain; SSO backend never invoked by `authenticate(username=…, password=…)`; break-glass lockout plus
  timing tolerance over 1000 samples; admin denied when `is_staff` revoked mid-session; one test per system
  check asserting the specific check id fires.
- **Trusted proxy (4 tests):** header from outside the CIDR; `X_Auth_User` underscore variant; missing
  shared secret; `X-Forwarded-For` chain resolved Nth-from-right, never leftmost.
- **Meta (2):** `pip-audit`/OSV against the lockfile fails CI on any advisory; a source grep failing on
  `verify=False`, `insecure`, `strict=False`, `# nosec` outside the test tree.

---

## 3. Architecture

### 3.1 Four customization tiers

Strictly layered. Each tier is an escape hatch from the one above; none is required.

```
Tier 0  Declarative config      settings dict + DB rows      ~90% of users, zero Python
Tier 1  Ordered hook pipeline   import strings, composable   ~8%  insert/reorder steps
Tier 2  Small protocol ABCs     ≤5 methods each              ~2%  replace a subsystem
Tier 3  Signals                 observation only              audit, metrics, side effects
```

**Tier 0 is the product.** The evidence: mozilla-django-oidc is the most-subclassed auth package in Django
*precisely because it has no declarative layer* — every deployment hand-writes the same `update_user`.

**Tier 1** borrows python-social-auth's pipeline and fixes its fatal flaw — a **single typed context
dataclass** instead of `**kwargs` soup, which eliminates the "some step forgot to forward a key" bug class
and gives mypy/IDE support. Steps return `None`, a modified context, or an `HttpResponse` that halts. That
halt convention is how MFA step-up and consent screens work.

```python
SSO = {
  "PIPELINE": [
    "django_sso.pipeline.normalize_identity",     # protocol → IdentityClaims
    "django_sso.pipeline.verify_assertion",
    "django_sso.pipeline.resolve_user",           # (issuer, subject) → User
    "django_sso.pipeline.evaluate_mapping",       # → MappingDecision (pure)
    "django_sso.pipeline.enforce_authorization",  # honours deny effects
    "django_sso.pipeline.provision_user",
    "django_sso.pipeline.reconcile_groups",
    "django_sso.pipeline.audit",
  ],
}
```

Per-IdP pipeline override is supported: a SAML IdP legitimately needs different steps from a header proxy.

**Tier 2 rejects the god adapter.** django-allauth's `DefaultSocialAccountAdapter` has ~22 methods and
`DefaultAccountAdapter` has 71 (66 public); only one of each can be installed, so two libraries can never
both customize, and adding a method breaks every subclass in the wild. We ship six ABCs of ≤5 methods:
`IdentityProviderBackend`, `UserResolver`, `UserProvisioner`, `GroupReconciler`, `AuditSink`,
`ScimUserAdapter`/`ScimGroupAdapter`. Each is versioned independently; adding a method to one is a
minor-version-only change with a default implementation.

**Tier 3 constrains signals to notification.** They cannot deny access, cannot mutate the decision, and
exceptions are logged and swallowed. The community objection to signals is entirely about control flow, and
it disappears under that constraint.

Escape hatch from a hook: raise `ImmediateHttpResponse(response)`, borrowed from allauth. Its own docstring
gives the correct justification — signals have multiple handlers in undefined order, so flow interception
belongs in a single-dispatch hook.

### 3.2 `IdentityClaims`: the seam, honestly scoped

The IdP research invalidated the naive version of this. Normalization holds for about half the fields and
**fails hardest exactly where authorization decisions are made.**

```python
@dataclass(frozen=True)
class IdentityClaims:
    issuer: str
    subject: str
    subject_source: str          # "oid" | "sub" | "objectGUID" — recorded, never assumed
    email: str | None
    email_verified: Verified     # True | False | Unknown — tri-state, not bool
    display_name: str | None
    groups: tuple[str, ...]
    group_value_format: GroupFormat   # opaque_id | display_name | full_path | qualified_name | sid
    groups_complete: bool        # False on Entra overage, Okta >100, Google SAML >75
    mfa_satisfied: bool          # derived per provider; raw `amr` kept in `raw`
    authn_time: datetime | None  # genuinely optional — absent unless max_age requested
    raw: Mapping[str, Any]
```

Why each deviation from the obvious design:

- **`subject` cannot mean "the `sub` claim."** Entra's `sub` is **pairwise per application** — two of your
  apps see different `sub` for the same human. Entra needs `oid`+`tid`; AD FS needs `objectGUID` (never
  `upn`, which is mutable); Ping's `sub` is fully remappable by the deployment. `subject_source` is stored
  on the identity row so a config change is *detectable* rather than silently re-linking accounts.
- **`email_verified` must be tri-state.** Google emits it meaningfully; **Entra does not emit it at all**
  (nearest analogue `xms_edov`, different semantics). Defaulting `False` breaks every Entra login;
  defaulting `True` is a security hole.
- **`groups: tuple[str, ...]` alone is a design flaw.** The same list can hold GUIDs, display names,
  `/full/paths`, SIDs or `DOMAIN\name`, and may be truncated, capped, or entirely absent. Hence
  `group_value_format` and `groups_complete`.
- **`amr` is not cross-provider comparable.** Value sets barely overlap and emission is opt-in on Entra
  SAML, Google and Keycloak. Keep raw `amr` for audit; gate on the derived `mfa_satisfied`.

**The provider quirks layer is mandatory, not optional.** There is no useful "generic OIDC" default for
groups or MFA. Every provider ships a plugin implementing four capabilities: subject resolution, group
resolution + overage fetch, MFA derivation, step-up request construction.

**The portability claim, stated truthfully in the docs:** a mapping rule is portable across *protocols* for
a given provider, and only conditionally portable *across* providers — specifically, only across providers
sharing a `group_value_format`.

### 3.3 Configuration

Each of the rules below exists because a named package got it wrong first.

1. **One namespaced `SSO` dict.** Counter-examples: allauth ships **≈134 flat top-level setting names**
   across six prefixes with three casing conventions; mozilla-django-oidc ships **39 flat `OIDC_*` names**
   including a near-duplicate pair (`OIDC_OP_AUTHORIZATION_ENDPOINT` / `OIDC_OP_AUTH_ENDPOINT`) and one
   documented-but-never-read setting (`OIDC_VERIFY_JWT`).
2. **Strict separation: settings hold code-level extension points and defaults; the DB holds per-IdP
   instance config. No key can be set in both.** allauth's `APP`/`APPS`/`SocialApp` three-way duality
   produces real bugs — `list_apps()` merges DB and settings, and settings-derived `SocialApp` instances
   have `pk = None`, so `SocialToken.app` is silently left null (issue #2467, 16 👍). **A config object that
   cannot be an FK target must not be a model.**
3. **`dynamic_setting` descriptor, copied nearly verbatim from mozilla-django-oidc-db.** Lazy, typed,
   read-only, and the attribute name *is* the setting name.
4. **Validate at startup via `django.core.checks`**, never at first login, with stable ids
   (`django_sso.E001`) and `Tags.security` so `manage.py check --deploy` catches a missing signing cert
   before deploy. djangosaml2's opaque `SAML_CONFIG` passthrough is the named anti-pattern.

**`__init__` on an auth backend must be empty.** Django instantiates auth backends on *every permission
check*, so eager config reads there are both a correctness blocker (per-tenant config becomes structurally
impossible) and a performance hazard. This is upstream mozilla-django-oidc's original sin and is still open
as issue #495.

### 3.4 Data model

```python
class IdentityProvider(models.Model):     # the OP/IdP — reusable across clients
    identifier, protocol, issuer, enabled, organization (nullable FK, swappable)
    # discovery/metadata endpoints, JWKS, certs

class SSOConnection(models.Model):        # the RP/SP
    identifier = SlugField(unique=True)
    provider   = FK(IdentityProvider, on_delete=PROTECT)
    enabled    = BooleanField(default=False)      # gates backend candidacy
    options    = JSONField(schema=get_options_schema)   # per-plugin, JSON-Schema validated

class FederatedIdentity(models.Model):
    connection, subject, subject_source, user
    class Meta: unique_together = ("connection", "subject")
```

Splitting OP config from RP config (one Keycloak tenant, many client IDs) is mozilla-django-oidc-db's
design and is right. The `options` JSONField whose admin form is **generated from the registered plugin's
JSON Schema** means adding a protocol needs zero migrations.

Protocol plugins register through an explicit decorator registry with fail-fast duplicate detection and an
instantiable `Registry` class for test dependency injection — not allauth's import-scanning
`{app}.provider` mechanism, whose maintainer's own inline TODO calls it "way to magical and depends on the
import order."

**Design for N configs from commit one.** mozilla-django-oidc-db shipped a django-solo singleton, lived
with it from 0.2 to 0.23, then spent 0.24.0 tearing it out — and 2.0.1 was a hotfix for a *missing
migration* caused by removing the old model, with downstream told to squash or hand-edit migrations.
Multi-config is the shape of the problem, not a later feature.

---

## 4. The mapping engine

**Decision: a declarative, ordered rule table (Keycloak's shape) whose condition is a serializable predicate
tree (django-auth-ldap's shape), with per-rule `sync_mode`, a rich effect vocabulary, mandatory decision
tracing, and an import-string callable escape hatch.**

Rejected: JMESPath as the primary language. Grafana's operational failure is that `role_attribute_path`
silently yields the wrong role and nobody can explain why. The telling detail is that Grafana's own SAML
integration ships the opposite design, plain `role_values_admin` lists, which suggests neither approach
works alone. Also rejected: arbitrary Python in the DB (A11), and flags-by-group alone, which is neither
DB-configurable nor able to target anything but boolean fields.

JMESPath survives in exactly one narrow role: the claim **selector**, for extracting
`resource_access.myclient.roles`.

### 4.1 Model

```python
class MappingRule(models.Model):
    connection = FK(SSOConnection, null=True)   # null = applies to all
    name, order (db_index), enabled
    condition  = JSONField()    # predicate tree
    effects    = JSONField()    # list of effect objects
    stop       = BooleanField(default=False)
    sync_mode  = CharField(choices=["on_create", "every_login", "inherit"], default="inherit")
    class Meta: ordering = ["order", "pk"]
```

### 4.2 Condition: serializable predicate tree

```json
{"op": "and", "children": [
  {"claim": ["groups"], "test": "contains", "value": "eng-admins"},
  {"op": "not", "children": [
    {"claim": ["employment", "type"], "test": "eq", "value": "contractor"}]},
  {"claim": ["email"], "test": "endswith", "value": "@example.com"}
]}
```

Leaf tests: `eq ne in contains not_contains exists regex glob startswith endswith gt lt any_of all_of`.

**Claim addressing is `list[str]`, traversed with `glom` — not dotted strings.** The first prior-art report
recommended Keycloak's dotted-path-with-backslash-escaping; the source-level report overrides it, because
mozilla-django-oidc-db shipped dotted strings, broke on claim names containing literal dots, and fixed it
by moving to path lists (their issue #94). List-of-strings has no escaping rules to get wrong and is
migration-serializable via a `@deconstructible` default class (lambdas are not).

### 4.3 The Python mirror API

Conditions are constructible in code with operator overloading on `django.utils.tree.Node` — the same base
as `Q`, exactly as `LDAPGroupQuery` does — and round-trip to JSON:

```python
cond = (Claim("groups").contains("eng-admins")
        & ~Claim("employment", "type").eq("contractor"))
cond.to_json()            # → the DB row
Condition.from_json(d)    # → the same object
```

**This single decision resolves the settings-vs-DB duality that plagues allauth.** GitOps shops declare
rules in `SSO["MAPPING"]["RULES"]`; admin-UI shops edit them in the DB; both are the same object.
`SSO["MAPPING"]["MANAGED"] = "settings" | "db"` removes any ambiguity about which wins.

### 4.4 Effects

```json
[{"effect": "add_group",   "name": "sso-editors"},
 {"effect": "set_flag",    "field": "is_staff", "value": true},
 {"effect": "set_field",   "field": "first_name", "from_claim": ["given_name"]},
 {"effect": "deny",        "reason": "Contractors may not access the admin"},
 {"effect": "require_mfa"}]
```

`deny` is evaluated after all rules and always wins. `SSO["MAPPING"]["STRICT"] = True` (Grafana's
`role_attribute_strict`) denies when no rule matches, rather than silently provisioning a permissionless
user who then files a ticket.

### 4.5 Evaluation semantics: specified, not emergent

1. Rules evaluate in `order` ascending; **all** run unless one with `stop=True` matches.
2. Effects accumulate. Conflicts resolve `deny` > `set_flag(False)` > `set_flag(True)`; group adds union.
3. **Evaluation is pure.** It produces a `MappingDecision` and touches no database. Application is a
   separate step. This is what makes dry-run possible and what makes property-based testing tractable (§11.5).
4. `groups_complete == False` blocks any privilege-escalating effect (invariant 31).

### 4.6 The three differentiating features

**`explain()` on every evaluation, persisted with the audit event.**

```
rule #10 "Engineering admins"      MATCHED
  groups contains 'eng-admins'        → True  (claim value: ['eng-admins','all-staff'])
  NOT employment.type == 'contractor' → True  (claim value: 'fte')
  → add_group(sso-editors), set_flag(is_staff=True)
rule #20 "Contractors read-only"   no match
  employment.type == 'contractor'     → False
final: groups={sso-editors}, is_staff=True, denied=False
```

"Why does this person have staff access?" is the question every security review asks. Nothing in the
ecosystem can answer it.

**Dry run.** `manage.py sso_preview_mapping --connection okta --claims claims.json`, an admin paste-your-
claims page, and `--against-existing-users` to preview what a rule change would do to the whole directory
*before* saving.

**Reconciliation with ownership scoping.** `SSO["MAPPING"]["MANAGED_GROUPS"] = "prefix:sso-"`. The
reconciler only ever adds or removes groups within the managed set; a locally-created group is never
touched. This fixes a bug class present in both django-auth-ldap (`MIRROR_GROUPS` sets membership to
*exactly* match the directory on every login, wiping local groups — hence the `MIRROR_GROUPS_EXCEPT`
bolt-on) and NetBox.

### 4.7 Apply semantics: inherited wholesale from mozilla-django-oidc-db

Copy these four exactly. Each looks arbitrary until you hit the case that produced it.

- **`is_staff` is promote-only; `is_superuser` is two-way.** An IdP hiccup must not lock every admin out of
  the Django admin, but superuser revocation must be immediate.
- **A malformed group claim returns a `None` sentinel that aborts**, rather than resolving to `[]` and
  wiping every membership. Fail-closed on garbage.
- **Group auto-creation is glob-gated**, so an IdP with 4,000 groups doesn't pollute `auth_group`.
- **`save(update_fields=touched)` plus a set-equality fast path.** This runs on every login and is written
  to do nothing when nothing changed.

Plus `sync_mode` per rule (Keycloak's `IMPORT`/`FORCE`), because "should SSO overwrite what an admin changed
locally?" has no single right answer and every system that hardcodes one gets bug reports.

---

## 5. Identity and linking

```python
SSO = {"IDENTITY": {
    "KEY": ("issuer", "subject"),      # never email
    "LINKING_POLICY": "subject_only",  # | "verified_email_once"
    "REQUIRE_VERIFIED_EMAIL": True,
}}
```

`verified_email_once` exists because migrating an existing user table needs it. It links on first login
only when `email_verified is True`, then pins to subject, and **logs a distinct audit event every time it
fires** so an operator can watch the migration finish and then disable it.

Get this wrong and nothing else in the document matters. mozilla-django-oidc's `filter_users_by_claims`
defaults to `email__iexact`, and Django's `User.email` has **no unique constraint**, so the duplicate case
raises `SuspiciousOperation` and the login just fails. The worse outcome is when it doesn't fail: an IdP
admin who can change a user's email quietly takes over another account. That is allauth CVE-2025-65431,
observed in the wild against Okta and NetIQ.

Per-provider subject resolution, from §12:

| Provider | Subject | Why not `sub` |
|---|---|---|
| Entra ID | `oid` + `tid` | `sub` is pairwise per application |
| Okta | `sub` | — |
| Google | `sub` + `hd` check | `hd` is the only tenant boundary; omitting the check is a cross-org vulnerability |
| Keycloak | `sub` (user UUID) | — |
| AD FS | `objectGUID` | `upn` is mutable |
| Ping | deployment-defined | `sub` is fully remappable — the risk |

---

## 6. Admin integration

### 6.1 Why the admin ignores `LOGIN_URL`

Structural, not a toggle. **`grep -rn "LOGIN_URL" django/contrib/admin/` returns zero hits** in 5.2, 6.0,
6.1 and `main`. `redirect_to_login` consults `settings.LOGIN_URL` only as a fallback
(`login_url or settings.LOGIN_URL`), and `admin_view()` always passes it explicitly:

```python
return redirect_to_login(
    request.get_full_path(),
    reverse("admin:login", current_app=self.name),
)   # django/contrib/admin/sites.py:243-246
```

So the only way to change what happens at login is to change what `admin:login` resolves to, or what the
view behind it does.

### 6.2 Approach: (d) primary, (e) fallback

Five approaches were probed empirically on 5.2.16, 6.0.7 and 6.1rc1.

| | (a) shadow path | (b) shadow name | (c) patch `AdminSite.login` | **(d) subclass + `AdminConfig.default_site`** | (e) `admin.site.login = decorator(...)` |
|---|---|---|---|---|---|
| `reverse('admin:index'/'logout')` | ✅ | ❌ **`NoReverseMatch`** | ✅ | ✅ | ✅ |
| `admin_view()` redirect | ✅ | ❌ 500s | ✅ | ✅ | ✅ |
| Covers every `AdminSite` | ❌ | ❌ | ✅ | ❌ default only | ❌ `admin.site` only |
| Keeps `_registry` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `LoginRequiredMiddleware` | needs `login_required=False` | ❌ | ✅ | ✅ | ✅ free — `functools.wraps` copies `__dict__` |
| Documented | ⚠️ | ❌ | ❌ | ✅ | ❌ |

**(b) is catastrophic and must never ship.** Shadowing the namespace replaces the admin's entire
`app_dict`; measured output:

```
reverse(admin:login ) = /admin/login/
reverse(admin:index ) FAILED: Reverse for 'index' not found.
anon GET /admin/      EXC NoReverseMatch: Reverse for 'logout' not found.
```

Every admin page 500s, because `admin_view` reverses `admin:logout` on the permission-denied path.

**(d) is the recommendation** — the only documented, contracted seam, and the only one that preserves
`_registry` while replacing the class, because `AdminConfig.ready()` swaps the site before
`autodiscover_modules("admin")` runs. Instantiating your own `AdminSite()` in `urls.py` — the shape shown
in Django's own docs — **silently loses every model** (probe: `reverse('admin:auth_user_changelist')`
failed).

**(e) ships as the zero-config fallback**, since it needs no `INSTALLED_APPS` edit and django-allauth has
already normalised the pattern.

Note the (c) footgun: `AdminSite.login = fn` with a plain function makes it a bound method and yields
`AttributeError: 'AdminSite' object has no attribute 'user'` — `self` arrives in the `request` slot.

### 6.3 The login view must be a terminal state

Two redirect loops were reproduced. The second is the real trap for SSO packages:

```
nonstaff GET /admin/
302 → /admin/login/?next=/admin/     (admin_view: has_permission False)
302 → /admin/                        (our view: "you're logged in, go to next")
302 → /admin/login/?next=/admin/
*** STILL REDIRECTING AFTER 8 HOPS ***
```

`admin_view` tests **staff**; a naive SSO login view tests **authenticated**. The predicates disagree and
neither side is terminal.

**Fail with `PermissionDenied` (403), not a redirect** — allauth's `secure_admin_login` does exactly this,
and the measured result is two hops to a terminal 403.

```python
class SSOAdminSite(AdminSite):
    @login_not_required                       # LoginRequiredMiddleware opt-out
    def login(self, request, extra_context=None):
        if request.user.is_authenticated:
            if not self.has_permission(request):    # is_active and is_staff
                raise PermissionDenied              # terminal, no info leak
            return HttpResponseRedirect(reverse("admin:index", current_app=self.name))
        return redirect_to_login(self._safe_next(request), reverse("django_sso:begin"))
```

### 6.4 The 403 page

Django's bare fallback with `DEBUG=False` has no `<title>`, no `lang`, no heading structure and no way out.
Ours must have: an `<h1>`, a `lang` attribute, a visible correlation ID, and a **POST** sign-out control —
`LogoutView.http_method_names = ["post", "options"]`, so `<a href="/admin/logout/">` is a dead link.

Content, per §9.3, since the user's identity is already proven and there is no enumeration risk: who they
signed in as, which group is missing, a named next step, and a copyable correlation ID.

**Do not leak account existence through response *shape*.** Every negative outcome from the callback —
subject unknown, not provisioned, provisioned but not staff, deprovisioned — must produce one body and one
status code. Watch for `AuthenticationForm.confirm_login_allowed`, which raises a distinct "This account is
inactive." message reachable if you use `AllowAllUsersModelBackend` or write a backend returning inactive
users. And watch timing: JIT-provisioning lookups that run only for *known* subjects are a measurable
oracle.

### 6.5 Version-specific behaviour

- **Django 6.1 changed `AdminSite.login`** to honour `next` instead of always redirecting to the index. If
  we *subclass* we inherit it free; if we *replace* the method we must replicate it or an authenticated
  staff user hitting `/admin/login/?next=/admin/auth/user/` lands on the index.
- **Django 6.2 (`main`) adds `AdminSite.shortcut_view()`** with a permission check. Any package overriding
  `get_urls()` wholesale silently drops this hardening.
- **`LoginRequiredMiddleware` + admin is inconsistent in every version 5.1→main.** `AdminSite.get_urls()`
  sets `wrapper.login_url`; `ModelAdmin.get_urls()` **does not**. Measured with `LOGIN_URL="/sso/login/"`:

  ```
  anon GET /admin/            → /admin/login/?next=/admin/          (AdminSite wrap)
  anon GET /admin/auth/user/  → /sso/login/?next=/admin/auth/user/  ← settings.LOGIN_URL
  ```

  Every per-model admin URL escapes to `settings.LOGIN_URL`. On a default project that is a 404. Likely an
  upstream bug worth reporting; meanwhile it must be tested (§14).

---

## 7. Provisioning and lifecycle

### 7.1 SCIM conformance

The RFC's normative floor sits well below what shipping against Entra and Okta actually requires. Teams
routinely build to the RFC, pass a conformance checker, and then fail against both vendors.

| Item | RFC 7644 | Entra ID | Okta |
|---|---|---|---|
| PATCH | OPTIONAL (§3.5.2) | **required** | **required** for new OIN integrations |
| `op` values | lowercase in all normative examples | `Add`/`Replace`/`Remove` **capitalised**, unless the `aadOptscim062020` flag is set | lowercase |
| `active` on disable | boolean | the **string** `"False"` without the flag | boolean |
| Filtering | OPTIONAL (§3.4.2.2) | required; only `eq` and `and` used | `filter=userName eq "…"` **mandatory** |
| Pagination types | JSON numbers | numbers | **integers, not strings**, a very common failure |
| User DELETE | permitted; soft delete RFC-sanctioned | supported | **never sent**; `active:false` only |
| Group query | — | `?excludedAttributes=members` required | — |
| Base path | unspecified | `/scim` must be in the URL root | — |
| Duplicate | 409 + `scimType: uniqueness` | expected | 409 required |

Build order: implement the RFC-mandatory core, then treat the Entra column as the real specification since
it is the strictest superset, then check Okta's specifics. Never hard-delete on `active:false`. Both
vendors require the resource to stay retrievable, which happens to suit audit retention, since the
identity row has to outlive the account.

### 7.2 SCIM as a security surface

The SCIM bearer token is a **superuser-equivalent credential**. Per-tenant token, hashed at rest,
IP/mTLS-bound, rotatable, and structurally unable to grant `is_superuser` or edit break-glass accounts
(§10). django-scim2 leaves authn/authz entirely to the integrator — a real gap for a package that ships an
HTTP write API.

### 7.3 Deprovisioning: the mechanism, not the intent

**Measured on Django 6.0.7:**

| Mutation | ModelBackend | Custom backend whose `get_user()` omits `user_can_authenticate()` |
|---|---|---|
| `is_active = False` | logged out | **STILL LOGGED IN** |
| `is_staff = False` | still logged in | still logged in |
| `set_unusable_password()` | logged out | logged out |

Read that table carefully, because it contradicts what most people assume.

**`is_active=False` is not a session kill. It is a backend-dependent side effect.** It works only because
`ModelBackend.get_user()` ends with `return user if self.user_can_authenticate(user) else None`. A custom
SSO backend that omits that one line leaves every deprovisioned session live indefinitely. Hence invariant
25's system check. Separately, **`is_staff=False` touches sessions not at all**: the account stays
authenticated everywhere except the admin.

There is **no supported way to enumerate sessions by user.** `django.contrib.sessions.models.Session` has
exactly three fields — `session_key`, `session_data`, `expire_date`. No user FK.

What works, in order:

1. **Rotate the auth hash.** `get_session_auth_hash()` is `HMAC(SECRET_KEY, user.password)`, re-derived on
   every request by `auth.get_user()`. `set_unusable_password()` sets `password = make_password(None)`,
   which is `UNUSABLE_PASSWORD_PREFIX + get_random_string(40)` — **a fresh random value each call**, so the
   hash genuinely changes. This is O(1), backend-agnostic, and the *only* mechanism that works under
   `SESSION_ENGINE = signed_cookies` or `cache`.
2. Delete session rows, where the engine permits it — `db`, `cached_db`, `file` are enumerable by table
   scan; `cache` and `signed_cookies` are **not**.
3. Detect and use `django-user-sessions` if installed (a session model with a user FK). Do not reimplement
   it. **[assumed]** its Django 6.x compatibility is unverified — see §14.

```python
def deprovision(user, reason):
    user.is_active = False
    user.is_staff = False
    user.set_unusable_password()          # rotates the hash → kills every session
    user.save(update_fields=["is_active", "is_staff", "password"])
    _delete_sessions_if_enumerable(user)
    audit.emit("user.deactivated", target=user, reason=reason)
```

Plus a system check flagging `SESSION_ENGINE = signed_cookies` as incompatible with prompt revocation.

### 7.4 Session establishment

`auth.login()` calls `cycle_key()` **only when `SESSION_KEY` is absent**, and `flush()` only for a
different user or a stale hash. Re-login as the same user rotates nothing, and `cycle_key()` preserves
session *data* regardless. So: **explicitly `flush()` the pre-auth session** after consuming
state/nonce/`InResponseTo` and before `login()` (invariant 35).

An SSO login view that sets session state itself instead of calling `auth.login()` gets neither
`cycle_key()` nor `rotate_token()` and is session-fixation-vulnerable.

---

## 8. Audit and compliance

### 8.1 Event schema

Every field earns its place by being required by a named control, or by making an auditor's sample
defensible.

**AU-3's six elements are the canonical minimum across every regime** — PCI 10.2.2 and ISO 27002 8.15 are
rewordings of the same six.

| Field | Type | Required by |
|---|---|---|
| `event_id` | UUIDv7 | idempotent dedup; time-ordered for free |
| `event_type` | dotted string | AU-3a, PCI 10.2.2 |
| `occurred_at` | timestamptz UTC, ≥ms | AU-3b, PCI 10.2.2, ISO 8.15 |
| `recorded_at` | timestamptz | not mandated — detects clock skew, which is what makes `occurred_at` trustworthy |
| `outcome` | `success`\|`failure`\|`denied`\|`error` | AU-3e. `denied` **must** be distinct from `failure` — authz denial and authn failure are different detections under CC7.2 |
| `actor_id` | opaque, immutable, never reused | AU-3f, HIPAA §164.312(a)(2)(i), PCI 10.2.2. Internal PK, **not** email |
| `actor_type` | `user`\|`service`\|`scim_client`\|`system`\|`anonymous` | separates humans from integrations in privileged-access populations |
| `source_ip` | inet | AU-3c/d. Personal data under AU-3(3) → redactable |
| `target_type`/`target_id` | string | PCI 10.2.2 |
| `actor_external_id` | string | the IdP subject — lets an auditor **reconcile our log against the IdP's**, and the reconciliation is the evidence |
| `on_behalf_of_id` | string, nullable | impersonation. AC-6(9) and CC7.2 both fail silently without it |
| `auth_protocol` | enum incl. `break_glass` | makes "every break-glass action" a one-line query |
| `auth_methods` / `auth_context` | `amr` / `acr` | the only durable evidence that IA-2(1)/(2) MFA requirements were met at the moment of access |
| `session_id`, `request_id`, `tenant_id` | string | correlation, forensics, scope isolation |
| `changes` | JSON `{field: {from, to}}` | ISO 8.15, CC6.3. Structurally diffable, never prose. Secrets structurally impossible to place here |
| `reason` | text | **enforced non-null for break-glass and elevation.** An optional justification field is an empty one |
| `ticket_ref` | string, nullable | what a SOC 2 auditor asks for: proof the approval *preceded* the grant |
| `is_privileged` | bool | AC-2(7), A.8.2 population extraction |
| `chain_seq` | bigint, gapless | **the completeness field** — higher evidentiary value than the hash chain |
| `prev_hash`/`record_hash` | bytes | AU-9(3), PCI 10.3.2/10.3.4 |
| `schema_version` | int | retention spans years; without it, old records become uninterpretable and the evidence dies |

**Excluded by construction:** raw tokens, assertions, passwords, `Authorization` headers, full SAML XML,
full ID tokens. Store an assertion *digest* if non-repudiation is needed.

### 8.2 Event catalogue

Publishing this list **is** the AU-2(a)/(c)/(d) deliverable — unusually high value, because customers
otherwise write it by hand.

- **Auth:** `login.succeeded`/`.failed` (with reason sub-code), `login.denied`, `mfa.required`/`.satisfied`/
  `.failed`, `logout`, `session.expired`/`.expired_absolute`/`.revoked`, `lockout.triggered`/`.released`,
  `assertion.rejected`, `protocol.fallback`.
- **Identity:** `user.provisioned`/`.updated`/`.deactivated`/`.reactivated`/`.deleted`,
  `user.identity_linked`/`.unlinked` (account-takeover-relevant and usually missing),
  `user.attribute_conflict`.
- **Authorization:** `role.granted`/`.revoked`, `group.membership.added`/`.removed`,
  `mapping_rule.created`/`.updated`/`.deleted`, `mapping.evaluated`, **`entitlement.snapshot`** — this is
  what lets an auditor answer "who had admin on 14 March" without reconstructing state from a change stream.
- **Privileged:** `breakglass.requested`/`.activated`/`.expired`/`.revoked`, `breakglass.action`,
  `privilege.elevated`/`.dropped`.
- **SCIM:** `scim.request`, `scim.client.credential_issued`/`.rotated`/`.revoked`.
- **Config:** `idp.connection.*`, `idp.certificate.rotated`, `idp.jwks.refreshed`,
  `config.security_setting.changed`, `audit.export.generated`, `audit.integrity.verified`/`.failed`,
  `audit.retention.purged` (so a `chain_seq` gap has an explanation).
- **Review:** `review.campaign.started`/`.item_decided`/`.completed`/`.overdue`.

### 8.3 Tamper evidence: honest about the limits

| Approach | Verdict |
|---|---|
| Append-only design + DB grants withholding UPDATE/DELETE | ✅ baseline everywhere; ISO 27002 8.15 names it |
| **Shipping to an independent system under different administrative control** | ✅ **the strongest practical control**, and what auditors look for |
| Change detection on log stores | ✅ **mandated** by PCI DSS 10.3.4 |
| Hash chaining | reasonable and cheap — **becomes theatre if sold as immutability.** An attacker with write access recomputes the chain in seconds. Real value only when the head hash is periodically anchored somewhere the attacker doesn't control |
| Signed export manifests | ✅ high value, low cost, underused — directly answers the completeness challenge |
| Merkle trees, transparency logs, blockchain anchoring | ❌ gold-plating. No regime asks for it; buys nothing over "ship to a system you don't administer" |

### 8.4 Retention

| Regime | Requirement |
|---|---|
| PCI DSS 10.5.1 | **12 months, 3 months immediately available** |
| FedRAMP AU-11 | **1 year, 90 days online** |
| CNIL Délib. 2021-122 | **6 months–1 year** standard; up to **3 years** for documented internal-control cases |
| NIST AU-11 base, ISO 27001, SOC 2 | organisation-defined, no number |
| **HIPAA** | **none.** §164.316(b)(2)(i)'s six years covers required *documentation*, not application logs — this is widely misstated |

Default TTL **12 months**, configurable, with the above as named documented presets — never as a default
masquerading as a requirement.

### 8.5 The GDPR erasure path

Regulator research, in brief:

- Art. 17(3)(b)/(e) apply only "to the extent necessary" — not a blanket carve-out for a log table.
- **CNIL Délibération 2021-122 §12 is the only regulator text that squarely blesses an audit log outliving
  the record it describes** ("souvent inévitable et acceptable"), and it recommends timestamping and
  signing logs at creation. §7 wants logs segregated and write-only. §22 endorses pseudonymous identifiers
  in logs where source retention is short.
- **German DSK SDM Baustein 60 says logs containing personal data ARE subject to the deletion duty** —
  audit logs are not automatically outside Art. 17. Its list of adequate deletion methods **omits key
  destruction**.
- **Crypto-shredding is not endorsed by any EU or UK regulator.** A claim circulating in AI-written blog
  posts — that EDPB Guidelines 5/2019, the ICO and CNIL all recognise cryptographic erasure — is **verified
  false**: a full-text search of Guidelines 5/2019 found zero mentions of encryption, cryptography or keys.
  CNIL's blockchain paper says key deletion moves "closer to the effects of data erasure" and then that it
  does "not, strictly speaking, result in an erasure." **This claim must never appear in our docs.**
- EDPB Guidelines 01/2025 on pseudonymisation is still the **consultation draft**. Cite as draft.

**The architectural constraint:** the Art. 11 route (rights do not apply where the controller cannot
re-identify) and a recoverable mapping are **mutually exclusive**. If the package retains any ability to
re-derive the subject from an audit event — a live pepper, an HSM key, an ops-accessible mapping table —
Art. 11 is unavailable and the residual log is plainly personal data.

So `erase_subject(user)` **severs the identity record and reduces retained events to an opaque
non-reversible key**, under a documented field-by-field necessity assessment with a hard TTL. Not "we
crypto-shredded, therefore we erased."

### 8.6 What we cannot claim

Stated in the README, not a footnote.

1. The package is not SOC 2 / ISO 27001 / HIPAA / FedRAMP / PCI "compliant" or "certified." **No software
   is.** These regimes assess entities, ISMSs and systems, not libraries.
2. We evidence that access was *granted*, never that it was *authorized*. The business approval lives in
   the IdP, HRIS or ticketing system; `ticket_ref` is a pointer, not proof.
3. We cannot perform the access review. PCI 7.2.4's management acknowledgement in particular cannot be
   automated away.
4. **We do not satisfy HIPAA §164.312(a)(2)(ii).** It requires *procedures* for obtaining ePHI in an
   emergency. Break-glass is a mechanism a procedure can be built around. The clean mapping is **NIST
   AC-2(2)** (automated removal of temporary and emergency accounts), which we do satisfy.
5. We cannot "examine" logs. §164.312(b) and §164.308(a)(1)(ii)(D) require review, not just recording.
6. We cannot guarantee immutability where the deployer holds DB superuser or root.
7. We do not control clock accuracy (ISO A.8.17).
8. We cannot set your retention period.
9. We do not perform MFA. If the IdP lies about `amr`, we log the lie faithfully.
10. We cannot define least privilege or SoD for you.
11. Incident response, change management, vendor management, personnel and physical security, BCDR — wholly
    out of scope. CC7.3–CC7.5, CC8.1, CC9.x get nothing from us.
12. **We cannot make deprovisioning instant. We can make its latency measurable** — which is what auditors
    now sample on. Measured honesty beats an unverifiable "immediate."

---

## 9. Accessibility

### 9.1 Target

**WCAG 2.2 Level AA**, plus four AAA criteria treated as mandatory because they are load-bearing for an
auth product and cheap for us specifically: **2.2.5 Re-authenticating**, **2.2.6 Timeouts**, **3.3.9
Accessible Authentication (Enhanced)**, **2.4.12 Focus Not Obscured (Enhanced)**.

2.2 AA is the floor, not an aspiration: **Django core's contributing docs state it targets WCAG 2.2 AA**, so
a third-party admin UI at 2.1 would actively regress the host application. It is also the superset
satisfying Section 508 (WCAG 2.0), the DOJ ADA Title II rule (2.1 AA), EN 301 549 V3.2.1 (2.1 AA) and the
UK PSBAR regulations (currently 2.2 AA).

Do not claim WCAG 3.0 (Working Draft, "inappropriate to cite … as other than a work in progress"). Do not
claim ATAG 2.0 — it governs authoring tools; a role-mapping admin is not one, and claiming it invites an
audit question we cannot answer.

Keep **SC 4.1.1 Parsing** as a tested, reported line item despite its removal from 2.2, because 508 and EN
301 549 V3.2.1 still reference versions that contain it — and because duplicate `id`s, which Django inline
formsets generate silently, break every `aria-describedby` and `<label for>` pointing at them.

### 9.2 The finding that shapes the architecture

**SSO does not discharge SC 3.3.8 — it relocates half of it.**

Offering third-party OAuth login is a listed *sufficient technique* for the step we render. But WCAG
Conformance Requirement 3 says every page in a process conforms, and the IdP's login page is in the login
process. If the IdP blocks paste or shows a CAPTCHA, the process does not conform and neither do we. The
escape is a §5.4 Statement of Partial Conformance, which obliges us to **monitor** the third-party content
and **identify non-conforming parts to users**.

What that obliges us to do:

1. **Never ship a configuration where an IdP is the only way in.** There must always be a locally-controlled
   path — break-glass, WebAuthn, or email-link (technique G218). **This makes break-glass an accessibility
   control as well as a security one**, and is the second independent justification for building it (§10).
2. Scope the conformance claim explicitly in the ACR, naming the IdP as third-party content.
3. Ship a deployer-facing IdP procurement checklist: does it block paste, does it show a CAPTCHA, does it
   support passkeys, does it publish an ACR.
4. Every step *we* render — provider selection, callback interstitial, step-up, error pages — is ours.

### 9.3 Hard rules

- **No `autocomplete="off"`, no paste blocking, no `readonly` tricks, ever.** Failure F109; NIST 800-63B and
  OWASP both explicitly say permit paste. Enforced by a lint rule.
- **No `autofocus` on the login page.** It teleports screen-reader users past the heading, the provider list
  *and* the error summary. Django removed it from admin search for this reason; allauth has carried an open
  complaint since 2014. The GOV.UK error-summary-receives-focus pattern wins; the two are mutually exclusive.
- **`autocomplete="one-time-code"` on OTP fields** — required by 3.3.8 (it enables OS autofill), *not* by
  1.3.5, since the token is not in WCAG's 53-token Input Purposes list. Single input, or split boxes with
  working paste distribution.
- **Three tiers of error specificity.** The mistake every SSO product makes is applying tier-1 vagueness to
  tiers 2 and 3, and there is no security justification for it.

  | Tier | Case | Specificity |
  |---|---|---|
  | Pre-auth | wrong credentials, unknown user | **Generic** — but still text, announced. A bare 401 or red border fails 3.3.1, which has **no security exception** |
  | Infrastructure | IdP unreachable, clock skew, signature failure | **Specific** — discloses nothing about a user |
  | Post-auth | authenticated, authorization failed | **Maximally specific** — identity already proven, no enumeration risk |

  3.3.3 Error Suggestion is the only A/AA criterion in this family carrying the "unless it would jeopardize
  the security" clause. Use it deliberately and record each use in the ACR.
- **Session timeout:** NIST's inactivity reauth vs WCAG 2.2.1 (Level A) resolves via the *Extend* route.
  Copy HMRC's dialog: visible counter `aria-hidden`, a **separate** assertive live region carrying rounded
  values — four announcements instead of 120. Warn at 2 minutes, allow ≥10 extensions.
- **Full-page redirect, never a popup.** Screen readers do not announce that a new window opened; magnifier
  users lose the focal point. Front-load the `<title>` — `Error: Sign in — {Site}` — since on a redirect it
  is the only thing guaranteed to be announced.
- **Live regions must exist empty in the DOM before population.** Two persistent regions (`role="status"`,
  `role="alert"`) fed from one message queue. Record in the ACR that `role="alert"` on JAWS+Chrome is only
  *partially* supported — on the most common Windows pairing, "assertive" is not assertive.
- **Consume Django's CSS custom properties; never hardcode a colour.** Match the
  `html[data-theme="light"], :root` selector pattern exactly, or the admin theme toggle loses our overrides.
- **Never `role="grid"` on the audit table.** That promises arrow-key navigation we will not implement. Use
  a native `<table>` with `scope`, a `<caption>` naming the active filter, and an `overflow-x` wrapper with
  `role="region"` + `tabindex="0"` (a scrollable region that cannot be focused cannot be scrolled by
  keyboard).
- **Announce the result count after filtering:** "Filter applied. 42 of 1,204 events shown." Cheap to
  build, and without it a screen-reader user gets a full page reload and no indication anything narrowed.
- Sortable columns get a real `<button>` inside the `<th>` plus `aria-sort`, not Django's current empty
  anchors named only by `title` (open ticket #36460).

### 9.4 Testing reality

**axe-core has exactly one WCAG 2.2 rule** (`target-size`). There is **no rule at all** for 3.3.8, 2.4.11,
3.3.7 or 4.1.3. Every criterion that matters most for an auth package is manual-only.

So: automation is a regression net; **manual testing is the conformance evidence.** Wagtail — the most
a11y-mature package in the ecosystem — does not gate CI on axe either; its investment is a standing team
plus versioned OpenACR YAML in git. Django core has no a11y CI at all (#33620, stalled).

CI tiers: fast template scan (contrast/target-size disabled — no stylesheets resolve against `about:blank`);
full-fidelity scan under `StaticLiveServerTestCase` (**not** `LiveServerTestCase`, or CSS never loads and
every contrast result is meaningless); `html5validator`; forced-colors and 400% zoom via Django's own
`@screenshot_cases` harness. Use `pytest-playwright-axe`; **`pytest-axe` is archived by Mozilla.** If using
pa11y-ci, set `"runners": ["axe"]` — the default HTML_CodeSniffer engine does not support WCAG 2.2 at all.

Publish a W3C-style accessibility statement first, naming the **actual** AT/browser matrix tested. Graduate
to an ACR on VPAT 2.5Rev INT, authored in **OpenACR YAML** and versioned in git. Do not publish an ACR
without test evidence: in procurement, "Partially Supports" and "Does Not Support" both mean "does not
conform."

---

## 10. Break-glass

### 10.1 Why it is not optional

Two independent justifications:

1. **Security.** It is the fire escape when the IdP is down, and nothing in the Django ecosystem provides
   one (verified: five candidate PyPI names all 404).
2. **Accessibility.** §9.2 — it is the locally-controlled path that keeps our own login process
   conformant end-to-end regardless of the IdP's conformance.

### 10.2 Design, grounded in prior art

From Microsoft Entra's emergency-access guidance, AWS root-user practice, HashiCorp Vault root tokens, and
Entra PIM:

**`BreakGlassAccount`** — a flag on a config model, not a magic username.

- **Bypasses the SSO requirement**, via a documented narrow local-password path reachable only by flagged
  accounts. This is Entra's "exclude from Conditional Access" control and the entire point: it must not
  depend on the system it routes around.
- **At least two must exist** (system check), and the last one cannot be deleted or unflagged.
- **A second factor that is not the IdP** — `django-otp` TOTP or WebAuthn, seeded out-of-band. Entra: "make
  sure it doesn't use the same authentication methods as your other administrative accounts."
- **Exempt from automated deprovisioning.** The SCIM/directory reconciler must skip flagged accounts, or the
  nightly job deletes the fire escape. Also exempt from password-expiry and inactivity lockout.
- Rate-limited but **never locked out** — lockout is itself a denial of the fire escape. Alert instead.

**`ElevationGrant`** — modelled on the PIM request shape: `justification` (required, non-empty),
`ticket_number`/`ticket_system`, `starts_at`/`expires_at` (short default, hard `MAX_DURATION` ceiling),
`scope` (narrowest by default), `status`, `approved_by`, `deactivated_at`, `correlation_id`.

Enforcement uses django-elevate's dual-token primitive: a signed cookie carrying the grant id with
`max_age`, **plus** a matching session token, compared with `constant_time_compare`. Cookie alone cannot be
revoked; session alone cannot carry a tamper-evident expiry. Never trust `expires_at` from the cookie —
re-read the row.

**Expiry is enforced on read**, in `has_permission()`, not only by a scheduled job. A cron every five
minutes is a five-minute window.

Grants confer **permissions, never `is_superuser`** (A8).

**Alerting is built to be hard to switch off.** The default receiver fires **synchronously on the request
path**, so it cannot be swallowed by a dead queue during the exact outage the account exists for. A system
check **errors** if break-glass is enabled with no alert sink configured. A break-glass account nobody
gets told about is just a backdoor with paperwork.

**Tooling:** `manage.py breakglass_check` (≥2 accounts, 2FA enrolled, alert sink reachable, days since last
validation; exit non-zero — wire into monitoring so the 90-day cadence is measured, not remembered);
`breakglass_drill` (scripted login, asserts the alert fired, prints a post-mortem template);
`breakglass_grant` for out-of-band use when the web path is down.

### 10.3 Package vs. operational process

Cannot be enforced in Python, must be documented as such: credential storage and custody split (AWS: the
password and the MFA device held by *different groups*); the human approval decision; who is authorised;
the privileged access workstation; post-mortem discipline; **independence of the alert channel** — if
alerts route through an SSO-protected inbox, the IdP outage that triggers break-glass also silences the
alarm; and the 90-day validation drill itself.

---

## 11. Engineering foundations

### 11.1 Licence: Apache-2.0

Decisive, and the **patent grant is the reason**, not a tiebreaker. Federated identity has genuine
historical patent activity, which makes the defensive-termination clause less theoretical here than in a
date-parsing library. Enterprise legal review is materially faster. Cost is GPLv2 incompatibility — accept
it; our consumers are Django applications. "Match Django's BSD-3" is an aesthetic argument.

Ship a `NOTICE` file and SPDX headers on every source file.

**DCO, not CLA.** A CLA on a security package reads as "we reserve the right to relicense," which is
precisely the doubt we cannot afford, and it suppresses drive-by security fixes — the contributions we most
want.

### 11.2 Support matrix

| | Django 5.2 LTS | 6.0 | 6.1 | main |
|---|:--:|:--:|:--:|:--:|
| Python 3.11 | ✅ | — | — | — |
| Python 3.12 | ✅ | ✅ | ✅ | — |
| Python 3.13 | ✅ | ✅ | ✅ | — |
| Python 3.14 | ✅ **[assumed — verify 5.2.x backport]** | ✅ | ✅ | ⚠️ non-blocking |

Python floor at **3.11**, not 3.12, because RHEL 9 ships `python3.11` and dropping it costs exactly the
public-sector constituency we target. Floor rises when we drop 5.2.

Policy: a Django series is dropped in the first minor release **after** it leaves upstream extended support;
a Python version in the first minor after its upstream EOL. Adding support is patch-eligible; dropping is
never done in a patch. Every drop is announced one release ahead.

### 11.3 Supply chain

- **PyPI Trusted Publishing only. Zero API tokens, ever.** Nothing to steal, rotate or leak.
- **PEP 740 attestations on** (the default — do not disable). Adoption is ~5% of top projects; being in that
  5% is a differentiator for an auth package.
- **CycloneDX 1.6 SBOM shipped inside the wheel via PEP 770**, not just attached to the release. Solves the
  phantom-dependency problem for consumers; almost nobody does it.
- **Every GitHub Action pinned to a full 40-char SHA**, first-party included. The `tj-actions/changed-files`
  and `trivy-action` compromises both moved mutable tags.
- **Renovate** with digest pinning; Dependabot **alerts** stay on. **Never auto-merge** — update bots are
  themselves a documented malware-delivery vector.
- Two-tier deps: loose ranges for runtime (a library must not pin); `uv.lock` + hash-pinned
  `requirements/release.txt` for the publish path specifically.
- `permissions: {}` at workflow top level; **build and publish in separate jobs** so a malicious build
  script cannot inherit `id-token: write`; publish gated behind a GitHub Environment with required
  reviewers; `zizmor` as a required check.
- OpenSSF Scorecard ≥8.0 before 1.0, badge published, regressions treated as bugs. OpenSSF Best Practices
  **Baseline** + passing; **do not chase gold** — it requires maintainers of unrelated affiliation, which we
  cannot honestly claim.

### 11.4 Security policy

Copy Django's *structure*, shrink the *promises*. The failure mode is copying Django's embargo theatre
without Django's staffing.

- **Intake: GitHub Private Vulnerability Reporting**, not an email alias — free, gives a private fork, drafts
  the advisory in place, no PGP key management at v0.1.
- Ack ≤3 working days, fix target 90 days.
- CVEs via GitHub as CNA, but **do not couple the disclosure date to GHSA publication** — the Advisory
  Database is running multi-week delays under ~4,000 requests/month.
- **No private pre-notification list at v0.x or v1.0, and say so.** We lack the vetting capacity, and an
  unvetted embargo list is a leak, not a control.
- T-48h: severity and date only. T-0: releases for all supported series → signed tags → GHSA → docs advisory
  → announcements **and `oss-security@lists.openwall.com`**. Posting to oss-security is free and is the
  strongest "run by adults" signal available to a young project.
- T+1 week: a post-mortem naming the test that would have caught it. **Write the test first, then cite it
  in the post-mortem.** Handled this way an incident does more for our credibility than a clean record does.
- Because we perform authn/authz, **authentication bypass and incorrect role assignment are classified High**
  — stricter than upstream Django's default for broken authentication.

### 11.5 Testing

pytest + `pytest-django`; **nox not tox** (the matrix has real exclusions — Django 6.x requires Python ≥3.12
— and expressing that in tox factor conditionals is write-only).

Coverage: `branch = True`, 95% repository-wide as a hard gate, **100% enforced per-module** on `rules/`,
`claims/`, `protocols/`, `audit/`, `breakglass/`.

Mutation testing (`mutmut`) on the security core only, **weekly, not a merge gate** — it is a detector of
weak assertions, and its value concentrates in branchy validation logic.

**Hypothesis is the highest-leverage testing decision here.** A predicate tree over claims is an algebraic
structure with laws. Build a `st.recursive` strategy for trees and a `st.deferred` strategy for arbitrary
JSON claims, then assert:

1. **Determinism/purity** — `evaluate()` twice agrees and performs no I/O. Guards against someone slipping a
   DB lookup into a predicate.
2. **Differential testing against a naive reference evaluator.** If only one property survives budget cuts,
   keep this one. It also catches cross-database semantic drift if either arm ever compiles to SQL.
3. **Serialisation round-trip** — non-negotiable, because rules persist as JSON and a round-trip bug is a
   silent authorization change.
4. Boolean algebra laws (De Morgan, absorption, identity) — the correctness spec for any future simplifier.
5. **Deny-overrides monotonicity** — adding a deny rule never turns deny into allow.
6. Order independence over claim-dict key order and group array order.
7. **Totality** — never raises on any well-formed claims object; returns a `Decision` or a typed
   `EvaluationError`, never `KeyError`/`TypeError`.
8. **Bounded execution** — deep and wide trees within a step bound. This is where **ReDoS in regex
   predicates** will be found. Either forbid backtracking constructs, cap input length, or use a
   linear-time engine.
9. **Stateful testing** (`RuleBasedStateMachine`) for JIT provisioning and SCIM reconciliation: generate
   create/update/deactivate/reactivate sequences and assert final state equals applying only the final
   claims. SCIM PATCH ordering bugs are exactly what this finds.

CI profiles: `ci` (`derandomize=True`, 200 examples) so PRs are reproducible; `nightly` (randomised, 5000,
no deadline) opening an issue on failure.

Migrations: `makemigrations --check --dry-run` as a required gate; forward-apply from empty **and** from the
previous release's schema; `django-test-migrations` for any data migration touching audit rows.

### 11.6 Database

**The structural decision that makes portability a non-problem: do not query the raw claims blob in any path
that matters.** Store raw claims as an opaque `JSONField` for audit; **project** the queryable claims into a
normalised indexed table at write time; evaluate rules **in Python** over deserialised claims.

This buys identical semantics on every backend, no dependency on `contains`/`contained_by` (unsupported on
SQLite and Oracle), ordinary B-tree indexes, and keeps Postgres JSON operators as a pure optimisation behind
a flag. It also means SQLite's silent coercion of the strings `"true"`/`"false"`/`"null"` cannot change an
authorization decision.

Tiering, stated in the README:

- **Tier 1: PostgreSQL 14+.** All features. Required for partial unique constraints on audit and
  break-glass tables, `nulls_distinct` on identity linkage, covering indexes.
- **Tier 2: SQLite 3.37+.** Development, testing, single-node evaluation. Full suite runs.
- **Tier 3: MySQL 8.0+ / MariaDB 10.6+.** Best-effort, with enumerated `xfail`s and a **startup system check
  naming the specific integrity guarantees unavailable on this backend.** Constraint options are *silently
  ignored*, not errors — a partial unique constraint enforcing "one active break-glass account per tenant"
  simply does not exist there, and nothing tells you.
- **Oracle: not supported.** Stated plainly.

The defensible formulation: "the package runs on any Django-supported database; the tamper-evidence and
uniqueness guarantees documented in the threat model are enforced only on PostgreSQL, and the software tells
you at startup when they are not." That survives procurement review; "works everywhere" with
silently-dropped constraints ends up in someone's incident report.

### 11.7 Async

Sync-first, async-capable. Backends implement `aauthenticate()`/`aget_user()` natively (Django 5.2+); the
OIDC callback, JWKS refresh, token exchange, back-channel logout and SCIM endpoints are async views.

**The transactional write path — JIT provisioning, role assignment, audit writes — is synchronous and
wrapped in `sync_to_async` when called from async context.** Django does not support transactions in async
mode, and we will not write audit records outside a transaction. An audit package that loses records to win
latency has failed at its one job. Stated as a deliberate trade, which turns the constraint into a
credential.

### 11.8 Typing and documentation

Ship `py.typed` from v0.1, with a CI test that installs the built wheel and asserts its presence. **mypy is
the merge gate; pyright is a required advisory second job** — `django-stubs` is both stubs and a *mypy
plugin*, and **pyright does not load mypy plugins**, so a large fraction of users see only the static stubs.
If pyright cannot see our public API, neither can they.

Two-zone strictness: `strict = true` for the pure-Python core (rule engine, claim normalisation, token
validation, SCIM schema — plain dataclasses over dicts, no excuse); relaxed for models, admin, migrations
and management commands, each with a per-module override carrying a comment.

Docs: **Diátaxis**, Sphinx + MyST (Markdown authoring, native autodoc, and ecosystem gravity — Django, DRF,
Wagtail, Celery). Three gates: doctests executed, `-W --keep-going`, `sphinx-lint` + internal linkcheck. A
wrong code sample in an auth package's quickstart is a vulnerability with extra steps.

Security pages that decide whether a security team approves us: **threat model with an explicit
out-of-scope section** (this is what makes the rest believable), deployment checklist an auditor can tick,
**cryptographic inventory** (every algorithm, key type, length, library, location — reviewers ask and almost
nobody has it ready), data/PII inventory, break-glass runbook, permanent advisory archive, and an honest
**"why you might not want this"** page comparing us against allauth-plus-a-SAML-lib and against buying an
IdP-side solution. Counter-intuitively that last one is a top-three trust signal — nobody who is overselling
writes one.

### 11.9 Trust signals, ranked

**Tier 1 — decides the outcome:** a specific threat model with an out-of-scope section; a published security
policy **with a track record of meeting it** (one well-handled advisory beats two years of clean history);
a dated support matrix with a drop policy; **bus factor > 1, stated in `GOVERNANCE.md`** (a single-maintainer
auth package fails vendor risk assessment on principle); an independent audit published **including unfixed
findings**.

**Tier 2:** deployment checklist and inventories; Trusted Publishing + attestations + SBOM; Apache-2.0; a
named reference deployment ("in production at $ORG since $DATE" outperforms every badge); Scorecard ≥8;
**OpenID Foundation RP certification** — in this specific domain worth more than most generic signals.

---

## 12. Per-IdP quirks

| Provider | Group claim | Format | Cap / overage | Subject | MFA signal | Logout |
|---|---|---|---|---|---|---|
| **Entra ID** | `groups` (opt-in) | **GUIDs** by default | **150 SAML / 200 JWT** → `_claim_names` + Graph call; filtering stops applying >1,000 | `oid`+`tid` (**`sub` is pairwise**) | `amr`; SAML needs `include_granular_amr` | RP-initiated ✅, front-channel ✅, **back-channel ✖** |
| **Okta** | `groups` (**not default**) | names | **hard cap 100** → error, no overage claim | `sub` | `amr`: `pwd,mfa,otp,kba,sms,swk,hwk` | RP-initiated ✅, SLO ✅ |
| **Google** | **none in OIDC** | names (SAML only) | **75 in SAML**; rename silently breaks mapping | `sub` + `hd` | `amr` only if requested | **no `end_session_endpoint`** |
| **Keycloak** | `groups` scope (not default) | names or `/full/paths` | none documented | `sub` (UUID) | `acr` + `acr-to-loa-map` | all four ✅ |
| **AD FS** | `role`/`groupsid` | **SIDs** unless a rule is added | — | `objectGUID` | `authnmethodsreferences` | WS-Fed + SLO |

Gotchas that break naive implementations:

- Entra `ApplicationGroup` mode **drops nested groups entirely** — a silent authorization difference, not an
  error. `emit_as_roles` **suppresses your actual app roles**. Overage requires admin-consented
  `GroupMember.Read.All`, so the package cannot handle >150 groups without the operator granting Graph
  access.
- Okta group resolution above 100 is **app-config-driven, not directory-driven** — the documented workaround
  is a static allowlist. A fresh integration with no `groups` claim looks like "user has no groups" rather
  than erroring.
- Google's live discovery document's `claims_supported` contains no group claim at all. Any claims→role
  mapping over Google OIDC requires an out-of-band Directory API call.
- Keycloak's "Full group path" toggle changes `/eng/backend` into `backend`; rules written against one break
  against the other. Realm roles, client roles and groups are three separate namespaces for one concept.
- AD FS's `Token-Groups - Unqualified Names` rule yields names but **excludes distribution and Domain Local
  groups** — a silent membership gap.

**CI test IdPs:** synthetic fixtures do ~90% of the work (sign your own JWTs, stub JWKS and discovery) —
no real IdP will produce an Entra overage claim or a mid-flight key rotation on demand.
`navikt/mock-oauth2-server` (MIT, container, arbitrary claim injection) for OIDC protocol tests; Keycloak
with an imported realm for both protocols; hand-crafted signed XML for adversarial SAML; `scim2-tester`
plus hand-written Entra/Okta dialect tests. Real vendor tenants stay off the PR path — Entra sandboxes now
generally need a Visual Studio subscription and Okta deactivated Developer Edition orgs in July 2025.

---

## 13. Build plan

Scope discipline is the whole game. Each phase has a definition of done; nothing ships without it.

### Phase 0: Skeleton (no features)

Repo scaffold per §11; CI with the full gate matrix; Apache-2.0 + NOTICE + SPDX; `SECURITY.md`;
`SUPPORT_MATRIX.md`; `GOVERNANCE.md` stating the bus factor honestly; Sphinx skeleton with the threat-model
and out-of-scope pages **written before any protocol code**; Trusted Publishing wired and a `0.0.1a0`
published to TestPyPI and back.

**Done when:** a no-op package publishes end-to-end with attestations and an SBOM, and `check --deploy`
passes on a fresh project.

### Phase 1: OIDC + mapping + admin + audit

`IdentityProvider`/`SSOConnection`/`FederatedIdentity`; the `dynamic_setting` config layer; the OIDC adapter
over authlib with invariants 1–13, 15, 32–35; the rule engine with `explain()` and the Hypothesis property
suite; `SSOAdminSite`; the audit store with the §8.1 schema; `sso_doctor`; the synthetic-fixture test
harness and the adversarial OIDC corpus.

**Done when:** every invariant in §2.2 applicable to OIDC has a test; the adversarial corpus passes; a real
Entra and a real Okta tenant each complete a login with correct `is_staff` derivation, including the Entra
overage path; `explain()` output appears in the audit record.

### Phase 2: Break-glass + accessibility conformance

`BreakGlassAccount`, `ElevationGrant`, the dual-token primitive, mandatory alerting with the
error-if-unconfigured check, `breakglass_check`/`_drill`/`_grant`; every screen in §9.3; the accessibility
statement with the real tested AT matrix.

**Done when:** `breakglass_check` runs green in CI; a drill fires a real alert; the full login flow is
completed keyboard-only under NVDA and VoiceOver; the a11y CI tiers are green.

### Phase 3: SAML

pysaml2 adapter with invariants 6, 14–19; the 8-position XSW corpus; the XXE corpus with a socket guard; the
startup checks for pysaml2's insecure defaults; Keycloak-based integration tests.

**Done when:** the entire SAML adversarial corpus passes, and the PortSwigger attribute-pollution and
void-canonicalization techniques have been **run against our actual stack** rather than assumed
inapplicable (§14).

### Phase 4: SCIM + lifecycle

SCIM 2.0 SP; per-client bearer tokens; `deprovision()` with the auth-hash rotation; the
`user_can_authenticate` system check; `scim2-tester` conformance plus Entra and Okta dialect tests; access
review campaigns and `entitlement.snapshot`.

**Done when:** a real Entra tenant and a real Okta org both provision, update and deactivate successfully,
and a deactivated user is anonymous on the next request with the session row gone.

### Phase 5: Multi-tenancy and hardening

Organization scoping; per-org self-service connection onboarding; independent security audit; OpenID
Foundation RP certification if affordable; 1.0 with the API-stability commitment.

---

## 14. Open questions

Grouped by what would settle them. Nothing here is a blocker for Phase 0 or 1.

**Needs a decision from the maintainer**

1. **Distribution name.** `django-sso` is taken. Unclaimed as of the check: `django-breakglass`,
   `django-emergency-access`, `django-jit-access`, `django-privileged-access`. The name should signal
   *governance*, not *protocol*, since that is the positioning.
2. Whether to target B2B SaaS (needs the per-org self-service admin portal — a product, not a module) or
   internal platforms (does not). This changes Phase 5 substantially.
3. Whether to emit **SSF/CAEP events** (OpenID Shared Signals). No Django package does. Could not be
   determined whether that is an opportunity or an absence of demand.
4. Whether requiring a ticket number for break-glass is safe during a genuine outage — the ticket system may
   be down. Likely a configurable "required except in `EMERGENCY_MODE`, with louder alerting on the
   exception."

**Needs verification before the API freezes**

5. **`azp` as a MUST (invariant 12) is stricter than OIDC Core**, which says SHOULD. Needs interop testing
   against Entra, Okta, Ping, Keycloak and Google before shipping as a hard default, or it will reject
   conformant-but-unusual IdPs.
6. **The PortSwigger attribute-pollution / void-canonicalization class was reported against Ruby and PHP
   libraries only.** Whether lxml/xmlsec1/pysaml2 exhibit the same parser differential is **untested**.
   Nothing about the technique is language-specific, so assuming immunity would be wishful. Gates Phase 3.
7. **Replay-cache atomicity by cache backend.** LocMem cannot provide insert-or-fail; Redis `SET NX` and a
   DB unique constraint can. Needs enumeration and a startup check, not an assumption.
8. **`django-user-sessions` on Django 6.x** — 2.0.0 shipped 2022-12 and its README claims Django ≤4.2,
   Python ≤3.11. Verify before recommending it as a dependency.
9. **Python 3.14 on Django 5.2 LTS** — marked `[assumed]` in §11.2. Check the 5.2 release notes.
10. **Partial unique-constraint support per backend** — verify against `django/db/backends/*/features.py`
    for our minimum Django before relying on it for a security-relevant constraint.
11. **The `ModelAdmin.wrap()` missing `login_url`** (§6.5) — confirmed in 5.2/6.0/6.1/main but no Trac
    ticket was found. Search Trac; if absent, file it.
12. **Multiple `AdminSite` instances.** Approaches (d) and (e) demonstrably do not cover non-default sites.
    Interaction with `django-otp-admin`, Wagtail and `django-admin-sso` is untested.
13. **Custom `AUTH_USER_MODEL` without a password field** breaks the auth-hash session-kill lever entirely,
    and on Django 6.1+ breaks `auth.login()` outright. Needs its own probe.
14. Async behaviour of the SSO admin login under ASGI — all admin probes were sync.

**Deferred scope**

15. Ping, OneLogin, JumpCloud quirks are unresearched beyond group-claim configuration.
16. **Whether AWS IAM Identity Center can act as an OIDC IdP for a third-party RP at all** — it is primarily
    a SCIM *receiver*, and with attribute-based access control enabled it forbids multi-valued SAML
    attributes, which structurally rules out a normal groups attribute. Decisive for whether we support it.
17. Cost and availability of OpenID Foundation RP certification for our profiles — potentially a Tier-1
    trust signal, unpriced.

**Standards in motion**

18. **EN 301 549 V4.1.1 is not yet published** and not yet cited in the Official Journal — until it is,
    there is no presumption of conformity available under the EAA.
19. **EDPB Guidelines 01/2025 on pseudonymisation is still the consultation draft.** Re-check before
    publishing anything citing it.
20. **NIST reauthentication intervals differ between revisions.** SP 800-63B-3: AAL2 = 12 h / 30 min.
    SP 800-63B-4 (final July 2025): AAL2 = **24 h SHOULD / 1 h SHOULD**. Deployers under a Rev-3-referencing
    contract need the stricter numbers. **Both profiles must be selectable; neither hardcoded.**
21. The HIPAA Security Rule NPRM (Jan 2025) that would make every implementation specification *required*
    has **not** been finalised; OMB now shows final action expected **July 2027**. §8 reflects the rule as
    currently in force.
22. PCI DSS v4.0.1 verbatim text could not be retrieved (403). Requirement numbers and the 10.2.2 field list
    are corroborated across secondary sources but **not quoted from the standard**.

---

## 15. Sources

**Specifications**
RFC 9700 (OAuth 2.0 Security BCP, BCP 240, Jan 2025) · RFC 6749 · RFC 6819 · RFC 9207 · OpenID Connect Core
1.0 (§3.1.3.7, §5.3.2, §15.5.2, §16.11) · RFC 7642/7643/7644 (SCIM) · RFC 8176 (`amr`) · OASIS SAML 2.0
Bindings and Approved Errata · WCAG 2.2 and Understanding docs · WAI-ARIA APG · EN 301 549 V3.2.1 · PEP 561,
PEP 740, PEP 770

**Standards and regulation**
NIST SP 800-63-4 / 63B-4 / 63C-4 (final July 2025) · NIST SP 800-53 Rev 5 (AC-2, AC-6, AU-2, AU-3, AU-9,
AU-11, IA-2) · AICPA 2017 Trust Services Criteria · ISO/IEC 27001:2022 Annex A · 45 CFR §164.308/312/316 ·
PCI DSS v4.0.1 · GDPR Art. 11, 17 · CNIL Délibération n° 2021-122 · German DSK SDM Baustein 60 · EDPB
Guidelines 05/2019, 01/2021, 01/2025 (draft) · Section 508 · EAA Directive (EU) 2019/882

**Django source** (verified against 6.0.7, cross-checked 5.2.16 / 6.1rc1 / main @ `c2517faff3`)
`contrib/admin/sites.py` (`admin_view` :210-255, `get_urls` :257-321, `login` :413-450) ·
`contrib/admin/options.py` (`ModelAdmin.get_urls().wrap` :709-714) · `contrib/auth/__init__.py`
(`login` :153-197, `get_user` :312-353) · `contrib/auth/base_user.py` (`get_session_auth_hash` :132-149) ·
`contrib/auth/backends.py` (`user_can_authenticate` :91-96) · `contrib/auth/middleware.py`
(`LoginRequiredMiddleware` :44-91) · `utils/http.py` (`url_has_allowed_host_and_scheme` :245-305) ·
`docs/ref/contrib/admin/index.txt` · `docs/releases/6.1.txt` :135-136

**Prior art read at source**
django-allauth 65.18.0 (`socialaccount/adapter.py`, `account/adapter.py`, `mfa/models.py`,
`account/decorators.py`, `providers/saml/`) · mozilla-django-oidc 5.x (`auth.py`, `middleware.py`) ·
mozilla-django-oidc-db 2.0.1 (`models.py`, `registry.py`, `plugins.py`, `config.py`) · django-auth-ldap
(`config.py` — `LDAPGroupQuery`) · django-scim2 (`adapters.py`) · djangosaml2 (`backends.py`) ·
python-social-auth (pipeline) · django-elevate 2.0.3 (`utils.py`) · DRF (`settings.py` — `APISettings`) ·
Keycloak `AdvancedClaimToRoleMapper` · Grafana generic-OAuth docs · Authentik expression policies

**Vendor documentation**
Microsoft Learn: Entra optional/ID-token/SAML claims references, group claims, SCIM provisioning, signing-key
rollover, Conditional Access authentication context, emergency access accounts, PIM activation · Okta
developer docs: groups claim, OAuth API, step-up via ACR, SCIM 2.0, Developer Edition changes · Google
Identity: OIDC discovery document, Workspace group membership mapping · Keycloak server admin guide ·
AWS root user best practices · HashiCorp Vault tokens

**Advisories**
Authlib CVE-2026-27962/-28498/-28802/-2024-37568/-2025-59420/-62706/-61920/-2026-41479/-44681 · PyJWT
CVE-2017-11424/-2022-29217/-2026-48526/-48523/-48522/-48524/-2024-53861 · pysaml2 CVE-2021-21238/-21239/
-2016-10127 · python-saml CVE-2017-11427/-2016-1000252 · Duo Labs 2018 comment-truncation family
(CVE-2017-11427…11430, CVE-2018-0489) · SignXML CVE-2025-48994 · python-ldap CVE-2025-61911/-61912 ·
django-allauth CVE-2025-65430/-65431/-2026-27982 · lxml CVE-2026-41066 · xmlsec1 CVE-2009-0217 ·
PortSwigger "The Fragile Lock" (CVE-2025-66567/66568) · Somorovsky et al., *On Breaking SAML*, USENIX 2012
