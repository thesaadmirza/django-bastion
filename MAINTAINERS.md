# Maintainers

| Name | GitHub | Areas | Key fingerprint |
|---|---|---|---|
| Saad Mirza | [@thesaadmirza](https://github.com/thesaadmirza) | everything | not yet published |

Release tags are not signed yet, and the fingerprint column is empty because
there is nothing to put in it. Do not infer anything from a tag's provenance.

What you can check instead: every release is published from
[`.github/workflows/release.yml`](.github/workflows/release.yml) through PyPI
Trusted Publishing, and the distributions carry PEP 740 attestations naming
that workflow and this repository. That is a stronger statement than a
signature nobody can verify against a published key, which is what the row
above would otherwise be inviting.

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
