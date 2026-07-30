# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
with the caveat that anything below 1.0.0 may break between minor versions.

Security fixes are listed under **Security** and also announced through
[GitHub Security Advisories](https://github.com/thesaadmirza/django-bastion/security/advisories).
See [SECURITY.md](SECURITY.md) for how to report one.

## [Unreleased]

Nothing since 0.0.1a2.

## [0.0.1a2] - 2026-07-30

One fix. Nothing on the authentication path changed, so upgrade at your
convenience unless you care what the package says its version is.

### Fixed

- **The package misreported its own version.** `__version__` was a literal in
  `bastion/__init__.py`, separate from the one in `pyproject.toml`, so 0.0.1a1
  shipped announcing itself as 0.0.1a0. It is now read from the installed
  distribution, which cannot drift, and two tests check that the package,
  `pyproject.toml` and the changelog all agree before a release goes out.

  Found by running the smoke test against the published wheel rather than
  trusting the release job's green tick.

## [0.0.1a1] - 2026-07-30

Three of these are faults on the authentication path and one of them stopped
Entra deployments before the first login. Upgrade over 0.0.1a0.

None were found by the test suite. Two came from following the tutorial twice
against providers on different ports, one from someone pointing the package at
a live Entra tenant, and one from reading a document against the source it
described. Worth saying, because the suite passing is what 0.0.1a0 was released
on.

### Fixed

- **Signing in returned a 500 when the username was already taken.** The
  username is derived from the subject and the identity is keyed on
  `(issuer, subject)`, so changing an issuer URL makes every existing person
  look new while their username is still held. Adding a second connection for
  the same directory does the same. The insert now happens in a savepoint and
  raises `ProvisioningConflict`, which renders the ordinary failure page. The
  accounts are not linked automatically: selecting a local user by a
  provider-supplied value is the shape of allauth CVE-2025-65431.
- **Any error from the authentication backend was a 500.** The callback's
  handler covered `complete_login` and stopped there, leaving provisioning and
  resolution outside it, so a backend refusal produced a stack trace on a
  request anyone can make. Refusals now get the same page, audit record and
  correlation reference as a rejected assertion.
- **Discovery refused providers that do not advertise PKCE methods.**
  `code_challenge_methods_supported` is optional under RFC 8414 and Microsoft's
  v2.0 document omits it while accepting S256, so `bastion_doctor` failed every
  Entra deployment on its first run and advised turning off `require_s256` --
  a flag that also silences a provider genuinely refusing S256. An absent field
  is now reported as unverifiable. A field present without S256 still fails.
  Nothing about the request changed: `code_challenge_method` has always been
  hardcoded to S256.

### Changed

- `require_s256` governs a provider that advertises a method set excluding
  S256. It is no longer the answer to a provider that advertises nothing.

### Documentation

- The audit catalogue said it listed every event the package emits. Fourteen of
  the thirty had no emitter, including `auth.logout`, which was documented as
  recorded when a session ends. Each is now marked reserved, and two tests keep
  the markers honest in both directions.
- The crypto inventory listed `c_hash` and an RFC 7638 thumbprint. Neither is
  computed: `c_hash` belongs to the hybrid flow, and `kid` is read from the
  provider rather than derived.
- The README claimed `bastion_doctor` checks the redirect URI registration and
  the group claim, which are the two things it most conspicuously cannot and
  reports as unverifiable. It also described an allauth adapter that does not
  exist and a SAML extra whose implementation does not exist.
- MariaDB is tested now, at 10.6 and 11.4, and CI runs it on every push.

## [0.0.1a0] - 2026-07-29

First release. Alpha here means the API can change in any later version, patch
releases included, and nothing is promised about upgrades until 1.0.

Thinly tested it is not. 694 tests run on every commit across Python 3.11 to
3.14 and Django 5.2, 6.0 and 6.1, against PostgreSQL 16, MySQL 8.4 and SQLite.
A separate run stands up a real Django project, installs the built wheel into
it, and signs in through an OIDC provider over TLS. Four modules carry a 100%
coverage gate rather than the repository's 95%: `protocols`, `audit`,
`breakglass` and `claims`, on the grounds that a mistake in any of them is
expensive and quiet.

### Added

- OIDC relying party built directly on `cryptography`, with no JOSE
  dependency. Covers discovery, JWKS caching with rate-limited refetch, PKCE
  S256, state and nonce binding, RFC 9207 issuer checking, and `at_hash`.
- Provider quirk adapters for Entra ID, Okta, Google and Keycloak, plus a
  generic fallback. These exist because the differences between providers are
  not cosmetic — pairwise versus stable subject identifiers, group claim
  overage, and absent `email_verified` all change what a correct
  implementation has to do.
- Admin SSO: `AdminSite` mixin that replaces the form login, an authentication
  backend, and the login and callback views.
- Append-only audit log with hash chaining and a gapless sequence. Events are
  pseudonymous from the first write, so erasing an actor removes the mapping
  row and leaves the chain intact.
- Retention, signed export manifests, and chain verification.
- Break-glass accounts with network restrictions, alert sinks, and a drill
  command.
- `bastion_doctor`, which checks a deployment against the provider before a
  login does.
- System checks, `py.typed`, and Django 5.2 through 6.1 support.

[Unreleased]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a2...HEAD
[0.0.1a2]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a1...v0.0.1a2
[0.0.1a1]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a0...v0.0.1a1
[0.0.1a0]: https://github.com/thesaadmirza/django-bastion/releases/tag/v0.0.1a0
