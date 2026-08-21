# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
with the caveat that anything below 1.0.0 may break between minor versions.

Security fixes are listed under **Security** and also announced through
[GitHub Security Advisories](https://github.com/thesaadmirza/django-bastion/security/advisories).
See [SECURITY.md](SECURITY.md) for how to report one.

## [Unreleased]

### Removed

- **Four settings that were declared and read by nothing.** `BACKEND`,
  `MAPPING["STRICT"]`, `MAPPING["MANAGED_GROUPS"]` and
  `ADMIN["reauth_max_age"]` — and with the last of its keys gone, the `MAPPING`
  namespace itself.

  The settings reference states the rule they broke, on the same page:
  *"Declared nowhere, on purpose. Shipping a config surface that does nothing
  is worse than not having one."* A deployment could set any of the four and
  get silence. `BACKEND` was the sharpest case: the comment directly above it
  in `conf.py` gave that exact reasoning, and the backend has always been
  loaded from `AUTHENTICATION_BACKENDS` rather than from there.

  **Nothing changes behaviour.** None was read, so setting one never did
  anything; after this, `get_setting()` raises for the name instead of
  returning a value nothing consulted. All four are listed under "Not yet
  implemented", which is where a reserved name belongs until something reads
  it.

### Added

- **A deprecation policy**, at
  [docs/reference/deprecation-policy.md](docs/reference/deprecation-policy.md).
  What is covered, what a rename does, and how long a refused name keeps
  failing loudly before it goes: two minor versions, then it is removed from
  the refusal list. Renamed keys are refused rather than ignored, because a
  deployment running with a control it believes is on is worse than one that
  will not boot.

- **The configuration surface is held still by a test.** Every global setting,
  every per-connection key, every check id and every refused name is listed in
  `tests/test_settings_surface.py`. Adding one is a line there; the point is
  that it cannot happen as a side effect of adding a dataclass field, and that
  the surface moves in a diff a reviewer sees.

  It found seven keys that worked and were undocumented — the four above, plus
  `transport`, `transactions` and `validation`, which take objects rather than
  data and are how a custom transport or a shared transaction store gets in.
  Those three are documented now, as extension points.

  The existing coverage test had missed them: it asked whether the name
  appeared anywhere in the page, and `BACKEND` matched inside
  `AUTHENTICATION_BACKENDS`.

### Added

- **`bastion.testing`: a fake identity provider, in the package.** Testing an
  SSO integration means producing assertions no real provider will produce on
  demand — an address the provider marks unverified, a group list truncated to
  a Graph pointer, a replayed `state` — so those are the paths projects end up
  not testing.

  ```python
  def test_an_unverified_address_is_refused(client):
      rig = harness()
      with rig.installed():
          rig.login(client, email_verified=False)
      assert SESSION_KEY not in client.session
  ```

  **No certificate and no local HTTPS server.** The report that asked for this
  described building a self-signed cert and a merged CA bundle, because bastion
  refuses a plain-http issuer and has no localhost exemption. That refusal
  stays, and none of the scaffolding is needed: `Connection` takes its
  transport as a field, so the fake is injected rather than served.

  `harness()` gives a provider, a transport and a connection wired together;
  `installed()` points the views at it and puts them back; `login()` drives the
  whole flow. It reads the `state` and `nonce` out of the authorization URL,
  which is ordinary public data — the version of this inside bastion's own
  suite read them out of `connection.transactions._records`, and a helper that
  needs a private attribute is one every integrator gets wrong.

  Five vendor profiles mint what that vendor actually emits, and bastion's own
  suite now runs on the same module rather than a private copy. See
  [testing your integration](docs/how-to/testing-your-integration.md).

  Malformed and hostile tokens are deliberately **not** included. `alg: none`,
  algorithm confusion and key injection prove that *bastion* refuses them,
  which says nothing about your deployment, and shipping them would commit this
  package to an attack-token API with no reason to exist.

### Removed

- **The `saml`, `ldap` and `scim` extras.** They were declared in the package
  metadata and shipped no modules, so `pip install django-bastion[saml]` pulled
  in pysaml2 and xmlsec, `[ldap]` built python-ldap from source against OpenLDAP
  headers, and neither gave you anything to call. Reserving a name is not worth
  putting a signature-handling library with its own vulnerability history into
  the dependency tree of a package that cannot reach it.

  They come back one at a time, each with an implementation and a live tenant
  behind it. A test now refuses an extra that installs a library the package
  never imports; empty extras like `[oidc]` are still fine, because they install
  nothing and so promise nothing.

  **If you install with one of these**, drop it: `pip install django-bastion`
  installs exactly what it did before. Nothing that worked stops working.

### Added

- **`bastion_doctor --check-registration` asks the provider whether your
  callback URL is registered.** `redirect_uri_mismatch` is the most common way
  an OIDC integration fails and the hardest to see from inside the application:
  the settings are right, the URL is right, and the provider still refuses.
  Nothing local can tell you whether a console edit propagated or landed on a
  different client.

  One authorization request answers it. No client secret is used and no token
  is issued, because the flow is abandoned before the code is exchanged, and
  the `state`, `nonce` and PKCE verifier are generated for the request and
  thrown away — no transaction record exists, so there is nothing for a later
  callback to replay. Off by default: it is the only check here that appears in
  the provider's logs.

  It asks about the same URL the report prints, from one derivation rather than
  two, and refuses to run at all when no concrete host is knowable — asking
  about a URL the deployment would never send is worse than not asking.

  The classifier reports *inconclusive* rather than passing when it cannot read
  the answer. That distinction is the point: Entra replies to a bad client id
  with HTTP 200 and an HTML page carrying no OAuth error parameter, so treating
  "no error seen" as success reported a broken deployment as healthy.

- **A provider matrix**, at [docs/reference/providers.md](docs/reference/providers.md). Five profiles
  ship and they are not equally proven: `entra` has been run against Microsoft's
  live endpoints and a real tenant, `google` has had its public discovery
  document read and no sign-in driven through it, and `okta`, `keycloak` and
  `generic` are written from the specification. The page says which is which,
  because "from the specification" means the failure mode is undiscovered
  rather than absent.

  It also collects the per-provider gaps that otherwise turn up one at a time
  mid-rollout: no group claim and no `end_session_endpoint` on Google, no
  `groups` by default and no truncation signal on Okta, no `email_verified` and
  no RFC 9207 `iss` on Entra. A test keeps the matrix and the registry in step
  in both directions.

### Fixed

- **The summary line promised role mapping the package cannot always do.** It
  said "claims-to-role mapping" with no qualifier, while `staff_groups` and
  `superuser_groups` cannot match anything on Google: the ID token carries no
  group claim, so a Google connection authenticates people and never grants
  staff. Nothing was broken — group evidence that does not exist is correctly
  treated as incomplete rather than empty, which blocks escalation instead of
  stripping privileges — but a deployer found this out after wiring everything
  up. The summary, the README and the two settings rows now name the
  dependency.

- **The threat model described a different package.** It said signature
  verification and JOSE primitives were the work of authlib, pysaml2 and
  python-ldap. None of the three has ever been imported here, and one was never
  a dependency — the runtime list is Django and `cryptography`, and
  `protocols/oidc` carries its own compact JWS verifier. The page told a
  security reviewer the cryptography was somebody else's audited library, which
  is the opposite of what they need to know before adopting this.

  Four rows claimed controls that need SAML code to exist: XML signature
  wrapping, XXE, entity expansion, unsigned assertions. One claimed a startup
  refusal for trusted-proxy headers, where only a doctor warning exists. One
  claimed a distinct `redirect_uri` per issuer, where there is one callback
  path.

  Three more were true but overstated, and are now stated as they are: replay
  protection is `state` single-use whose durability belongs to the cache
  backend, the JWT group-overage threshold is about 200 rather than 150, and
  the "adversarial corpus" is three named test modules.

  Every correction is recorded on the page rather than quietly applied — a
  security document that has been wrong should say so, because the reader is
  deciding whether to trust the rest of it. A test now refuses a security page
  that credits a library the package does not depend on. The same false
  sentence was in the package docstring, and is fixed there too.

## [0.0.1a8] - 2026-08-18

Eleven reports from a deployment that put this in front of a real admin, worked
through in order. The theme running through most of them is the same: a check or
a message that was right about the general case and wrong about the project in
front of it, and a package has no business making a deployment write its settings
conditionally to get past a check.

**One breaking change**, and it is a rename: `require_group_match` is now
`require_privileged_user`. The old key is refused at startup with a message
naming the new one rather than accepted and ignored, because it is the only
control stopping an unprivileged account from holding a session and silently
dropping it is the one outcome worse than a failed boot.

### Added

- **`IDENTITY["LINKING_POLICY"] = "verified_email_once"` exists now.** It was
  declared, documented, referenced by `bastion.E026`'s own hint, and implemented
  nowhere, so the only behaviour was `subject_only` — meaning no project with
  existing administrators could adopt them. Every one of them got a second
  account on their first sign-in, named from the provider's subject, with their
  permissions and history stranded on the first.

  Adoption happens once and only when all five hold: the provider says the
  address is **verified** (`Verified.UNKNOWN` is not enough here, unlike
  `REQUIRE_VERIFIED_EMAIL`), the domain is in the new
  `IDENTITY["LINKABLE_EMAIL_DOMAINS"]`, exactly one local account holds the
  address, that account has no federated identity yet, and it is not a
  break-glass account. Afterwards the account is pinned to `(issuer, subject)`
  like any other. `bastion.E029` refuses the policy with an empty domain list,
  since the pin is the control that makes it safe. Adoptions and refusals to
  adopt are both audited.

- **`persist_refused_identities` on a connection.** Resolution runs before the
  privilege gate, so a person the connection refuses has always been given a
  `User` row and a `FederatedIdentity` row by the time the refusal renders. That
  is useful — it is the audit trail, and ticking `is_staff` on the row is how the
  first administrator is onboarded — but it was not written down anywhere, and it
  means anyone the provider will authenticate can append to your user table by
  attempting a login they cannot complete. The behaviour is now documented and
  the setting turns it off, refusing from the claims before anything is written.

- **`ADMIN["local_login"]` does something.** It was declared and inert. It now
  answers the question `bastion.E023` is really asking — what a local password is
  allowed to be in this project — with `"breakglass_only"` (the default),
  `"never"`, and `"elsewhere"` for a project where the Django admin is one part
  of a larger application whose portal and API authenticate with passwords and
  cannot stop. `"elsewhere"` turns the error into `bastion.W031`, so the decision
  stays visible on every check run. Enabling an emergency credential endpoint to
  satisfy a check, which was the only way through before, is turning on a
  security-relevant route for the wrong reason. `bastion.E024` refuses an
  unknown value rather than reading it as the strictest one.

- **`bastion.W032` and `bastion.E102`, for the break-glass network allowlist.**
  Two docstrings said an empty `ALLOWED_NETWORKS` was "the deliberate
  configuration the startup check warns about". There was no such check, so
  emergency access could be enabled and reachable from any address on the
  internet with nothing said anywhere. W032 is the warning they promised — a
  warning, not an error, because an allowlist your office is in is one the hotel
  you are in at 3am is not. E102 refuses an entry that is not a network at all:
  `ipaddress` raises on those inside the branch deciding whether to answer an
  unauthenticated caller, so a typo there was a 500 on the emergency login,
  discovered during the emergency.

- **`bastion_doctor --base-url`**, to print the exact callback URL against an
  address you know rather than one assembled from settings.

### Changed

- **`require_group_match` is `require_privileged_user`.** It never looked at
  groups; it reads `is_staff` and `is_superuser`. The old name described the
  usual *cause* of those flags rather than what is tested, and on a provider
  that publishes no group claim at all — Google — it made the switch look
  inapplicable to the deployment it matters most to. Without it every account in
  the tenant authenticates, holds a Django session, and is stopped only at the
  admin door.

- **`bastion_doctor` prints the callback URL, not the callback path.** The path
  was right and useless: a deployment behind a load balancer that terminates TLS
  without `SECURE_PROXY_SSL_HEADER` builds `http://` redirect URIs while the
  `https://` one is registered at the provider, every sign-in fails with
  `redirect_uri_mismatch`, and the output pointed at none of it because the path
  in it was correct. The scheme is knowable at check time, so it is shown, along
  with which setting it came from, and `http://` warns. The caveat that used to
  be prose underneath is now attached to the thing it qualifies.

- **`bastion.E023` imports backends and tests `issubclass(cls, ModelBackend)`**
  instead of matching the dotted path. A project with a `UsernameOrEmailBackend`
  passed the check by deleting `ModelBackend` from the list while the subclass
  went on authenticating with a username and password exactly as before. A check
  that can be silenced by a change closing nothing is worse than no check,
  because now there is a green tick beside it. A backend that cannot be imported
  is left to Django, which raises on it at the first `authenticate()`.

- **A connection entry that is *incomplete* now warns (`bastion.W027`) rather
  than refusing to boot.** A missing `client_id` is a state every deployment
  passes through — a checkout or a CI run whose credentials are not in the
  environment yet — and erroring on it forces settings to be written
  conditionally just to keep those environments alive. A *wrong* value is still
  an error: it is wrong in every environment and no amount of secrets fixes it.
  When nothing in the project can reach a connection at all — the admin
  integration off and `bastion.urls` not routed — even a wrong one only warns,
  because a typo in an entry nobody is using should not take the site down.
  `bastion.W028` is the same downgrade for an admin connection named while SSO is
  not live. `bastion_doctor` still fails on every one of these, which is the gate
  to put in a deployment pipeline.

### Fixed

- **The break-glass network denial amplified.** Its branch recorded and alerted
  with nothing rate limiting it, while the throttle immediately below it had
  deduplication from the start — and the network branch is the one anyone can
  reach: the view is `login_not_required` and deliberately outside django-axes,
  so every request from outside the allowlist cost one chained audit write,
  which takes `SELECT FOR UPDATE` on the chain head and serialises against every
  other audit write in the system, plus one synchronous alert. With a sink that
  reaches a paging API on a long timeout, a loop against the URL holds workers
  open. Refusals are now recorded once per address per reason per window, on
  both branches, including for a request with no address at all. Successes are
  never suppressed: a flood must not be able to hide the one event that matters.

- **`manage.py check` no longer imports the OIDC stack when no connections are
  configured.** The import ran above the loop whatever `CONNECTIONS` held,
  pulling in `cryptography` — roughly 120ms cold — and Django runs system checks
  ahead of nearly every management command, so every command in every
  environment paid it, including ones with SSO switched off and nothing here to
  check.

- **A malformed CIDR in `ALLOWED_NETWORKS` raised out of the gate** deciding
  whether to answer an unauthenticated caller. `bastion.E102` catches it at
  startup; if it is reached anyway the entry is logged and matches nothing,
  which fails in the direction that grants nothing.

- **A `REMOTE_ADDR` that is not an address lost the whole audit record, on
  PostgreSQL only.** `source_ip` is a `GenericIPAddressField`, which is `inet`
  there, and Django adapts the value through `ipaddress.ip_address` on the way
  to the driver. A value that is not an address therefore raises rather than
  being stored — and on the write path that exception is caught by the
  recorder's own "a sink must never fail a login" rule, so the record vanished
  silently and only on one backend. `client_address` now normalises anything
  that is not an address to `None`, which keeps the record with an empty
  address field, and keeps every lookup that compares against `source_ip`
  working — including the break-glass deduplication above, which is a lookup
  and so raised into the caller rather than being swallowed.

### Documentation

- The settings reference gains `LINKABLE_EMAIL_DOMAINS`, `local_login`,
  `persist_refused_identities`, the renamed `require_privileged_user`, a section
  on migrating an existing user table, and a plain statement that refused logins
  still create rows.
- `bastion.backends` no longer claims a `bastion.W025` check warns about
  backends that drop `user_can_authenticate`. There is no such check and there
  was never going to be one — whether an override honours the method is a
  property of what it does at request time, and a check guessing from source
  would be confidently wrong in both directions. The invariant is asserted by
  tests, and the docstring now says so. Same defect as the missing
  `ALLOWED_NETWORKS` warning, which is why it is named rather than quietly
  deleted.
- `test_docs.py` gains the other half of the inert-settings guard: an entry that
  stays behind after the feature lands makes the list say a control does nothing
  when it now does, and only a test in that direction catches it.
- **`CONTRIBUTING.md` describes the project as it is.** It asked every commit for
  a DCO sign-off that nothing has ever checked and no commit in the history
  carries, and it asked for changelog fragments in a `changes/` directory that
  has never existed — a contributing guide is the one document whose readers
  cannot tell the difference between a rule and a wish. It now states the
  provenance position plainly, points at the changelog section releases actually
  use, and lists the gates CI really applies: the coverage floors, the
  cross-database matrix, the documentation tests, and the exact greps, including
  the `strict=False` that was removed from the insecure-flag list and the
  `# nosec` and `check_hostname=False` that were added to it. `pyright` is named
  as advisory, which is what `continue-on-error` in the workflow makes it.
- The link checker in `test_docs.py` now covers `CONTRIBUTING.md` and
  `CODE_OF_CONDUCT.md`. They were the only markdown in the repository nothing
  checked, which is how an instruction to write files into a directory that does
  not exist survived as long as it did.
- **The DCO sign-off is enforced rather than asserted.** A `dco` job checks
  every commit a pull request adds for a `Signed-off-by` trailer matching that
  commit's own author, so `CONTRIBUTING.md` asks for `git commit -s` again —
  this time truthfully. It is fifteen lines of `git` rather than a third-party
  action, because a supply-chain dependency in the CI of a security package
  should have to earn its place, and it runs only on pull requests: the history
  from before the check is unsigned and is not being rewritten to look
  otherwise.

## [0.0.1a7] - 2026-08-11

**The installable package is identical to 0.0.1a6.** Same code, same
dependencies, only the version string differs. Nothing here is a reason to
upgrade, and if you are on a6 you can stay there.

What changed is the publishing pipeline, which failed twice while cutting a6
and needed fixing before the next real release depended on it. This release
exists to run the corrected pipeline end to end against PyPI, because a release
path that has only ever been tested by releasing is one you find out about at
the worst moment.

### Fixed

- **Uploads were refused over packaging metadata.** hatchling emits core
  metadata 2.5 now, and the Twine bundled in the pinned publish action predates
  it, so the upload died at `'2.5' is not a valid metadata version` before it
  started. The action moves to v1.14.2, which carries Twine 7.

  Capping hatchling would have been the wrong end: 1.30.0 emitted 2.5, 1.30.1
  and 1.31.0 went back to 2.4, and 1.32.0 emits it again, so a cap holds a door
  shut against something the ecosystem is midway through adopting.

- **The publish action was pinned to a tag object rather than a commit.** The
  action is a Docker action and its image is published per commit, so the pin
  resolved to nothing and the run died at `manifest unknown`.

- **TestPyPI ran only on manual dispatch**, so no real release ever reached it.
  It now runs ahead of PyPI on tag pushes, where both of the failures above
  would have surfaced against an index whose version numbers are free.

  `skip-existing` is set there and deliberately not on PyPI. Retrying a version
  is the ordinary way out of a failed release, and TestPyPI refuses a file it
  already holds, so without it the gate would fail on the second attempt — the
  one that matters. On PyPI an existing version must still stop the release.

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

[Unreleased]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a8...HEAD
[0.0.1a8]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a7...v0.0.1a8
[0.0.1a7]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a6...v0.0.1a7
[0.0.1a6]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a5...v0.0.1a6
[0.0.1a5]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a4...v0.0.1a5
[0.0.1a4]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a3...v0.0.1a4
[0.0.1a3]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a2...v0.0.1a3
[0.0.1a2]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a1...v0.0.1a2
[0.0.1a1]: https://github.com/thesaadmirza/django-bastion/compare/v0.0.1a0...v0.0.1a1
[0.0.1a0]: https://github.com/thesaadmirza/django-bastion/releases/tag/v0.0.1a0
