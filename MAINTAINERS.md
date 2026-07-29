# Maintainers

| Name | GitHub | Areas | Key fingerprint |
|---|---|---|---|
| Saad Mirza | [@thesaadmirza](https://github.com/thesaadmirza) | everything | not yet published |

Release tags are signed. Until a fingerprint appears above, treat tag signatures
as unverified — an unverifiable signature is worse than none, because it invites
the assumption that someone checked.

## Bus factor: 1

One maintainer. If you are weighing this for production, weigh that against
everything else here.

The realistic failure mode is delay. A security report waits longer for a fix,
a release waits longer for a new Django. Price that in.

Losing the code is not the failure mode. Apache-2.0 covers it, patent grant
included, so an abandoned version stays usable and anyone may fork it. Whoever
does gets 694 tests, CI across Python 3.11 to 3.14 and Django 5.2 to 6.1 on
PostgreSQL, MySQL and SQLite, and a 100% coverage gate on the modules where a
mistake actually costs something. Inheriting that is not the same as
inheriting an orphan.

Recruiting a second maintainer, from a different organisation, with commit and
release rights, is a tracked deliverable before 1.0.
[GOVERNANCE.md](GOVERNANCE.md) says what changes then, and how to ask.

## Areas needing a second pair of eyes

Changes under these paths should not be merged by their own author once there is
more than one maintainer, and `CODEOWNERS` will enforce it:

- `src/bastion/protocols/` — signature verification and claim validation
- `src/bastion/audit/` — the evidence trail
- `src/bastion/breakglass/` — the path that bypasses SSO by design
- `src/bastion/backends.py` — identity resolution
