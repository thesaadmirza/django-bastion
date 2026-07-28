# Contributing

## Sign-off

Every commit needs a DCO sign-off:

```bash
git commit -s -m "your message"
```

That adds a `Signed-off-by` line certifying you have the right to submit the
work under the project's licence. See [developercertificate.org](https://developercertificate.org/).

There is no CLA. A contributor licence agreement on a security package reads as
"we are reserving the right to relicense," which is the doubt this project can
least afford, and it puts a signup wall in front of drive-by security fixes —
the contributions we most want.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[oidc]" --group dev
pytest
```

## Before opening a pull request

```bash
ruff check --fix src tests
ruff format src tests
mypy src
pytest
python -m django makemigrations --check --dry-run --settings tests.settings
```

Or `nox`, which runs the matrix.

## What a change needs

**A test that fails without it.** For anything touching authentication or
authorisation, ideally one that would survive a plausible refactor — assert the
property, not the implementation.

**A comment explaining why, where the why is not obvious.** The codebase leans
heavily on this. A lot of what looks arbitrary is a specific vendor behaviour or
a specific CVE, and a reader six months from now needs to know which.

**A changelog fragment** in `changes/`, named `<issue>.<type>.md` where type is
one of `feature`, `bugfix`, `security`, `removal`, `deprecation`.

## Things CI will reject

- `assert` anywhere in `src/`. It vanishes under `python -O`, and a runtime
  invariant guarded by one is not guarded.
- `verify=False`, `insecure=True`, `strict=False` outside the test tree.
- Anything that fails `ruff format --check`.
- A missing migration.

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

## Reporting a vulnerability

Not here. See [SECURITY.md](SECURITY.md).

## Code of conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
