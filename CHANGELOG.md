# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
with the caveat that anything below 1.0.0 may break between minor versions.

Security fixes are listed under **Security** and also announced through
[GitHub Security Advisories](https://github.com/thesaadmirza/django-bastion/security/advisories).
See [SECURITY.md](SECURITY.md) for how to report one.

## [Unreleased]

Nothing since 0.0.1a6.

## [0.0.1a6] - 2026-08-11

A misconfigured connection is now caught by `manage.py check` instead of by the
first person who tries to log in. Adding that check turned up two faults on the
path it was checking, which is the part worth reading before upgrading: one of
them could take down `manage.py` entirely on a config that previously only
broke the login.

Nothing changes for a correctly configured deployment.

### Added

- **Connections are validated by `manage.py check`.** They are built on first
  use, so a missing `client_id` or a mistyped key used to pass every check and
  then fail at login instead. Usually in staging, where whoever hits it cannot
  tell a configuration mistake from an outage.

  `bastion.E027` reports every broken entry rather than stopping at the first.
  `bastion.E028` catches an admin pointed at a connection nobody configured.
  The check calls the same loader the login path calls instead of keeping its
  own list of required keys, so unknown keys and unknown providers are caught
  as well, and the two cannot disagree.

  An install with no connections still starts. That was deliberate: `pip
  install` followed by `manage.py check` should work before you have configured
  anything.

- The check-id table in the settings reference is now tested against the checks
  that exist, in both directions. It is what a reader copies into
  `SILENCED_SYSTEM_CHECKS`, and until now it was kept in step by hand.

### Changed

- The support matrix no longer names a MySQL or MariaDB floor of its own. That
  floor is Django's and it moves between releases, so the page gives the number
  per Django version instead of a single one that quietly goes stale. Below it
  Django refuses to connect at all, so it was never a question of whether the
  suite passes.

### Fixed

- **`build_connection` raised exceptions no caller was catching.** Every caller
  treats `ConfigurationError` as the whole contract, but a mistyped
  `auth_method` came out as `ValueError` and a non-iterable `scopes` as
  `TypeError`. On the login path that was a 500 instead of a clean refusal;
  once the new check ran the same code at startup it aborted the check
  framework, so `migrate`, `runserver` and `collectstatic` all died with a
  traceback into `enum.py`.

  Settings could also set `identifier` and the private cache fields, because
  the unknown-key guard matched against every dataclass field and those are all
  `init` fields. Setting `_lock` got you a connection whose lock was a string.

  Found by adding the check above, not by the suite.

- **The admin's connection pointer was validated in the wrong place.**
  `sso_connection` on an admin site beats `ADMIN["connection"]`, and only the
  setting was checked, so a typo in the attribute the docs recommend to
  customizers passed every check and 500'd on the admin login page.

- **CI stopped being able to reach MariaDB.** Nothing to do with an install;
  this one is for contributors. Django 6.1 raised the MariaDB floor from 10.6
  to 10.11, and the workflow still pinned 10.6, so every database run failed
  with `NotSupportedError` on commits that changed nothing. The failure looked
  like whichever branch happened to be open.

  A test now compares the pinned images against the floor the installed Django
  declares, so the next time Django moves it this fails with the new number in
  the message rather than turning up as someone else's red job.

## [0.0.1a5] - 2026-08-01

One setting that was declared, documented, and read by nothing now takes effect.
Small, but it changes where people land after signing in, so it is worth a
release of its own rather than riding along silently.

### Fixed

- **`BASTION["SUCCESS_URL"]` was never read.** `views.py` redirected to its own
  `DEFAULT_SUCCESS_URL` constant, so setting it changed where nobody landed. A
  `next` parameter still wins over it; the setting answers the case where
  nothing said where to go.

  There was already a passing test asserting `get_setting("SUCCESS_URL")`
  returns an override. It proved the settings machinery worked, not that
  anything called it, which is how this survived four releases. The new tests
  assert the redirect.

  The setting is **not** put through `safe_redirect_url`, deliberately: `next`
  is request input and is host-checked on the way out, while this is deployer
  configuration, and host-checking it would break landing people on a separate
  front end after sign-in. The [settings reference](docs/reference/settings.md)
  says so.

### Changed

- **If you set `SUCCESS_URL` and worked around it not applying, it now
  applies.** Nothing else moves: unset, the destination is `/` exactly as
  before.

### Removed

- `bastion.views.DEFAULT_SUCCESS_URL`. It was never documented and existed only
  as the hardcoded value that shadowed the setting. `conf.DEFAULTS` already
  holds `/`, and a second copy is how the two drift apart again.

## [0.0.1a4] - 2026-08-01

Two settings that read as security controls and enforced nothing now enforce
something. **One of them changes a default and one can refuse logins that
previously succeeded**, so read the two Changed entries before upgrading.

### Security

- **`IDENTITY["REQUIRE_VERIFIED_EMAIL"]` was never read.** It defaulted to
  `True` and was documented, while a user whose provider explicitly marked the
  address unverified was provisioned and, with a matching group, made staff.
  Accounts are keyed on `(issuer, subject)`, so this is not account takeover by
  itself; `user.email` is the field the rest of a Django project trusts, and a
  provider where anyone can self-assert an address turns that into impersonation
  one layer down.
- **`ADMIN["require_mfa"]` was never read.** It appears in the README
  quickstart, so a deployer following it believed the admin was MFA-protected
  while a password-only sign-in walked straight in. It is now enforced in
  `has_permission`, which runs on every admin request rather than only at
  sign-in, so enabling it also covers sessions that already exist.

### Changed

- **`ADMIN["require_mfa"]` now defaults to `False`.** That is a fix rather than
  a relaxation: it enforced nothing, so no deployment ever had this control from
  this key. Defaulting it on would lock out every deployment whose provider does
  not emit `amr`, which is opt-in on several of them. **If you had it set to
  `True`, it now does what you thought it did** — confirm the claim arrives with
  one sign-in before deploying, or your administrators are locked out.
- **A login can now be refused where it previously succeeded**, when the
  provider explicitly marks the address unverified. `Verified.UNKNOWN` still
  passes, which is why Entra deployments are unaffected: Entra emits no
  `email_verified` at all, and treating absent as unverified would refuse every
  Entra login.

### Added

- `auth.mfa.missing` is emitted when the admin refuses a session for having one
  factor. It was already in the catalogue with no emitter.
- The access-denied page says which requirement failed. Telling someone their
  group is missing when the real answer is the second factor sends them to a
  service desk that will add them to a group and change nothing.
- A test that fails when any key in `conf.DEFAULTS` is read by nothing and is
  not listed as inert with a reason, so this class does not recur. It parses the
  source rather than grepping it: the first version matched the setting name
  inside the docstring explaining it and passed with the enforcement deleted.
  Six keys are currently marked inert rather than fixed.

### Fixed

- The sign-out control on the access-denied page could not end the session. It
  pointed at `admin:logout`, which Django wraps in `admin_view`; that wrapper
  redirects the logout path to the admin index without calling the view when
  `has_permission` is false, and that page is only rendered when it is false.
  The button was a no-op for everyone ever shown it.

## [0.0.1a3] - 2026-07-31

Signing out now signs you out of the identity provider as well, which it did
not before. If you rely on the old behaviour, you were relying on people
staying signed in. The rendered pages also follow the admin's design where the
admin is available.

### Added

- **RP-initiated logout.** `POST /sso/logout/`, and the admin's own Log out
  button, end the local session and then send the browser to the provider's
  `end_session_endpoint`. The local session is destroyed first and
  unconditionally, so an unreachable provider still leaves the person signed
  out here. Where the provider publishes no `end_session_endpoint`, which is
  Google, a page says the provider session is still live rather than
  redirecting somewhere that implies otherwise.
- Two connection keys, both off by default: `store_id_token`, which keeps the
  compact ID token in the session so logout can send `id_token_hint` and the
  provider does not ask the person to confirm; and `post_logout_redirect_uri`,
  which **must be registered at the provider**, because an unregistered value
  makes Keycloak refuse the logout outright rather than fall back.
- `auth.logout` is now emitted, carrying `context.rp_initiated` so a later
  investigation can tell a full sign-out from a local one.
- The four rendered pages extend `admin/base_site.html` wherever
  `django.contrib.admin` is installed and routed, and a packaged
  `bastion/base.html` otherwise. See
  [customising the pages](docs/how-to/customising-pages.md).

### Fixed

- **Logout left the provider session intact.** The Django session was cleared
  and nothing else, so the next request to a protected URL was answered with a
  fresh authorization code and no prompt. `bastion_doctor` reported
  `Provider supports RP-initiated logout` while nothing in the package ever
  called the endpoint.
- **The sign-out control on the access-denied page could not end the session.**
  It pointed at `admin:logout`, which Django wraps in `admin_view`; that wrapper
  checks `has_permission` first and redirects the logout path to the admin index
  without calling the view. Since the page is only rendered when
  `has_permission` is false, the button was a no-op for everyone who was ever
  shown it, on the page that tells them to sign out and try another account.
  Found while security-reviewing the logout work.

### Removed

- The unused `state` parameter on `build_end_session_url`. It is only useful
  for correlating the post-logout redirect, which needs a handler this package
  does not have. It comes back with the handler.

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

[Unreleased]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a5...HEAD
[0.0.1a5]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a4...v0.0.1a5
[0.0.1a4]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a3...v0.0.1a4
[0.0.1a3]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a2...v0.0.1a3
[0.0.1a2]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a1...v0.0.1a2
[0.0.1a1]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a0...v0.0.1a1
[0.0.1a0]: https://github.com/thesaadmirza/django-bastion/releases/tag/v0.0.1a0
