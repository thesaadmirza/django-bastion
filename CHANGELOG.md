# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
with the caveat that anything below 1.0.0 may break between minor versions.

Security fixes are listed under **Security** and also announced through
[GitHub Security Advisories](https://github.com/thesaadmirza/django-bastion/security/advisories).
See [SECURITY.md](SECURITY.md) for how to report one.

## [Unreleased]

Nothing since 0.0.1a0.

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

[Unreleased]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a0...HEAD
[0.0.1a0]: https://github.com/thesaadmirza/django-bastion/releases/tag/v0.0.1a0
