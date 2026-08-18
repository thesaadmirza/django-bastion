# Contributing

## Licence and provenance

**Sign off every commit.**

```bash
git commit -s
```

That adds a `Signed-off-by` trailer certifying you have the right to submit the
work under the project's licence. It is the
[Developer Certificate of Origin](https://developercertificate.org/) — a
statement about where the code came from, not a copyright assignment, and it
costs you one flag.

**CI checks it**, on every commit a pull request adds, against that commit's own
author: a sign-off in somebody else's name certifies nothing, so the trailer has
to match. If you forgot on work already written, `git rebase --signoff <base>`
and force-push. Merge commits are skipped, because GitHub writes those and they
are nobody's certification.

The check arrived long after the requirement did. This page asked for the
trailer while nothing verified it, and no commit from before the check exists
carries one — an unenforced rule is the failure mode this codebase keeps writing
tests about, so it is now enforced rather than asserted. History is not being
rewritten to pretend otherwise; the job only looks at what a pull request adds.

**No CLA.** A contributor licence agreement on a security package reads as "we
are reserving the right to relicense," which is the doubt this project can least
afford, and it puts a signup wall in front of drive-by security fixes — the
contributions we most want. The DCO gets the provenance assurance without the
signup wall or the relicensing question, which is why it is the one and not the
other.

## Setup

`uv` is what CI runs and `uv.lock` is committed, so it is the reproducible path:

```bash
uv sync
uv run pytest
```

pip works as well, on 25.1 or newer for `--group`:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e . --group dev
pytest
```

Two notes on the optional extras, neither of which the test suite needs:
`[ldap]` pulls in python-ldap, which builds from source and wants OpenLDAP
headers (`libldap2-dev` and `libsasl2-dev` on Debian), and `[saml]` pulls in
pysaml2, which wants xmlsec. `uv sync` without extras avoids both. `[oidc]` is
empty on purpose — OIDC support is in the base install.

## Before opening a pull request

```bash
uv run ruff check --fix src tests noxfile.py
uv run ruff format src tests noxfile.py
uv run mypy src
uv run pytest
uv run python -m django makemigrations --check --dry-run --settings tests.settings
```

`noxfile.py` is in the lint paths because CI lints it too, and a file the
formatter skips locally but checks in CI is a failure you find after pushing.

Or `nox`, which runs the whole matrix. `nox -s lint typecheck migrations` is the
quick subset. The cross-database sessions need a server already running —
`nox -s "tests_db(database='postgres')"` expects one on 127.0.0.1:5432 with the
credentials in `tests/settings.py`; CI starts containers for PostgreSQL, MySQL
and MariaDB.

## What a change needs

**A test that fails without it.** For anything touching authentication or
authorisation, ideally one that would survive a plausible refactor — assert the
property, not the implementation.

**A comment explaining why, where the why is not obvious.** The codebase leans
heavily on this. A lot of what looks arbitrary is a specific vendor behaviour or
a specific CVE, and a reader six months from now needs to know which.

**A changelog entry** under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md),
in whichever [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) heading
fits — `Added`, `Changed`, `Fixed`, `Security`, `Removed`, `Deprecated`. Write
what changed for someone upgrading, not what you did. Entries here are prose
rather than one-liners, because the interesting part of a fix in this package is
usually why the old behaviour looked correct.

There is no `changes/` directory and no towncrier. An earlier version of this
page asked for fragments in one; it never existed, and every release so far has
edited the changelog directly.

## Things CI will reject

- **A commit without a `Signed-off-by` trailer matching its author.** See
  [Licence and provenance](#licence-and-provenance) above; the fix is
  `git commit -s`, or `git rebase --signoff <base>` for commits already written.
- **`assert` anywhere in `src/`.** It vanishes under `python -O`, and a runtime
  invariant guarded by one is not guarded. The check is a grep for `^\s*assert `.
- **`verify=False`, `insecure=True`, `check_hostname=False`, or `# nosec` in
  `src/`.** `strict=False` is deliberately *not* on that list: the only use in
  the tree is `ipaddress.ip_network(net, strict=False)`, which permits host bits
  in a CIDR and disables no checking at all. A guard that cries wolf on correct
  code gets switched off.
- **Anything that fails `ruff check` or `ruff format --check`** over `src`,
  `tests` and `noxfile.py`.
- **A missing migration.**
- **Coverage below 95% overall, or below 100% for the security core** —
  `bastion.claims`, `bastion.protocols`, `bastion.audit` and
  `bastion.breakglass`. If a branch there cannot be reached by a test, that is
  worth saying out loud in review rather than routing around.
- **A failure on any supported database.** The suite runs against SQLite,
  PostgreSQL, MySQL and MariaDB, and nothing is xfailed. Backend-specific
  failures are real: `source_ip` is `inet` on PostgreSQL and adapts values that
  the other three store without complaint.
- **A failure on any supported interpreter or Django version.** Python 3.11
  through 3.14, Django 5.2 through 6.1. The 3.11 × 6.0 and 3.11 × 6.1 cells are
  excluded because Django 6.0 requires 3.12, not because they are allowed to
  fail.
- **The documentation tests in `tests/test_docs.py`.** They fail on a setting in
  `conf.DEFAULTS` that the settings reference does not document, a check id in
  `checks.py` missing from the table in that reference (or listed there and no
  longer emitted), an `INERT_SETTINGS` entry that is now read or a read setting
  that is not listed, a relative link to a file that does not exist, and a
  version string in prose that is not the one in `pyproject.toml`.
- **zizmor findings** in `.github/workflows/`. The step has no
  `continue-on-error`, so a finding fails the job; it also uploads SARIF to code
  scanning. It is auditing our own CI for template injection and unpinned
  actions, which is why every `uses:` in there is pinned to a commit.

`pyright` runs and does not block: it is `continue-on-error` in CI and its nox
session accepts a non-zero exit. It exists to prove the public API is usable by
the large pyright/Pylance population, who see only the static stubs and not the
mypy plugin. mypy is the merge gate.

## Testing conventions

Test names read as sentences, and the docstring says *why the property matters*
rather than restating the assertion. Compare:

```python
def test_flag(self): ...                    # no
def test_overage_blocks_privilege_escalation(self):
    """The pointer to Graph is not an empty group list. Treating it as one
    would strip every group-derived permission."""
```

The synthetic identity provider in `tests/idp/` mints tokens at the byte level,
including shapes a correct JOSE library refuses to serialise. Use it rather than
mocking the verification layer — the point is to exercise the real code with
hostile input.

If you add a security invariant, add a mutation of it to your own check that the
test is load-bearing. Several tests in this repository exist because a mutation
survived and revealed a gap.

If you touch the audit chain or the break-glass throttle, run against
PostgreSQL before pushing. The concurrency tests skip on SQLite, which
serialises writes at the file level and so cannot show a lock race either way —
an honest skip, and one that means a whole class of bug is invisible locally
until CI finds it.

## Reporting a vulnerability

Not here. See [SECURITY.md](SECURITY.md).

## Code of conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
