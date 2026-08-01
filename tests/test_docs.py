"""Documentation integrity.

This exists because of a specific failure: the threat model referenced a
deployment checklist that had never been written, and nothing noticed. A
document that promises a page which does not exist is the one place a
repository can straightforwardly say something untrue, and it is cheap to
prevent.

Deliberately not a Sphinx build. A build catches broken references only once
the toolchain is installed and configured; this catches them in under a second
with no dependencies, which means it runs on every commit rather than nightly.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

#: Markdown inline links, excluding images.
LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def markdown_files() -> list[Path]:
    files = sorted(DOCS.rglob("*.md"))
    files += [ROOT / "README.md", ROOT / "SECURITY.md", ROOT / "CHANGELOG.md"]
    files += [ROOT / "GOVERNANCE.md", ROOT / "SUPPORT_MATRIX.md", ROOT / "MAINTAINERS.md"]
    return [f for f in files if f.exists()]


def relative_links(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    found = []
    for target in LINK.findall(text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        # GitHub-relative UI paths such as ../../security/advisories/new are
        # resolved by GitHub, not by the filesystem. Skipping them is the
        # honest trade: checking would need network access, and the alternative
        # is not writing the link that actually helps a reporter.
        if "/security/advisories/" in target:
            continue
        found.append(target)
    return found


@pytest.mark.parametrize("path", markdown_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_every_relative_link_resolves(path: Path) -> None:
    broken = []
    for target in relative_links(path):
        # Strip any anchor; we check the file exists, not the heading.
        filename = target.split("#", 1)[0]
        if not filename:
            continue
        resolved = (path.parent / filename).resolve()
        if not resolved.exists():
            broken.append(target)

    assert not broken, f"{path.relative_to(ROOT)} links to missing files: {broken}"


def test_the_docs_index_exists() -> None:
    assert (DOCS / "index.md").exists()


@pytest.mark.parametrize(
    "page",
    [
        "security/threat-model.md",
        "security/deployment-checklist.md",
        "security/crypto-inventory.md",
        "security/data-inventory.md",
        "security/break-glass-runbook.md",
        "reference/settings.md",
        "reference/audit-events.md",
        "explanation/why-you-might-not-want-this.md",
    ],
)
def test_the_pages_a_security_review_asks_for_exist(page: str) -> None:
    """These are the ones that decide whether a security team approves a
    dependency. Their absence should fail rather than be noticed in a meeting.
    """
    assert (DOCS / page).exists(), f"missing {page}"


def test_the_settings_reference_covers_every_default() -> None:
    """A setting that exists but is undocumented is one nobody will configure
    correctly."""
    from bastion.conf import DEFAULTS

    text = (DOCS / "reference/settings.md").read_text(encoding="utf-8")
    undocumented = [name for name in DEFAULTS if name not in text]
    assert not undocumented, f"undocumented settings: {undocumented}"


def test_every_audit_event_is_in_the_catalogue() -> None:
    """Publishing the catalogue is the NIST AU-2 deliverable. An event the
    package emits but does not list makes that deliverable wrong."""
    from bastion.audit.events import Event

    text = (DOCS / "reference/audit-events.md").read_text(encoding="utf-8")
    missing = [event.value for event in Event if event.value not in text]
    assert not missing, f"events missing from the catalogue: {missing}"


def test_the_package_reports_the_version_it_was_built_as() -> None:
    """`bastion.__version__` and pyproject must agree.

    They did not: `__version__` was a literal, so 0.0.1a1 shipped announcing
    itself as 0.0.1a0. A package that misreports its own version turns every
    bug report into a guess about which code the reporter was running.
    """
    import tomllib

    import bastion

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    assert bastion.__version__ == declared, (
        f"the package reports {bastion.__version__} and pyproject declares {declared}. "
        "If you have just bumped the version, an editable install still carries the "
        "metadata recorded when it was installed: rerun `pip install -e .` or "
        "`nox -s tests`, which builds fresh."
    )


def test_no_page_states_a_version_that_is_not_this_one() -> None:
    """Version strings in prose drift, because bumping pyproject does not touch
    them and nobody greps.

    Two of them are load-bearing rather than decorative: the crypto inventory
    and the roadmap both say "as of version X", which is how a reader tells
    whether a statement still applies. A wrong number there is worse than none.

    The changelog is exempt: it is a history, so old versions are the point.
    """
    import tomllib

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    pattern = re.compile(r"\b\d+\.\d+\.\d+(?:a|b|rc)?\d*\b")

    stale: dict[str, list[str]] = {}
    for path in [ROOT / "README.md", *sorted(DOCS.rglob("*.md"))]:
        found = {
            v
            for v in pattern.findall(path.read_text(encoding="utf-8"))
            # Only our own release line; Django and Python versions live here too.
            if v.startswith("0.0.1")
        }
        if found - {declared}:
            stale[str(path.relative_to(ROOT))] = sorted(found - {declared})

    assert not stale, f"pages naming a version other than {declared}: {stale}"


def test_the_changelog_has_a_section_for_this_version() -> None:
    """A release with no entry is one nobody can find out about."""
    import tomllib

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{declared['project']['version']}]" in changelog


def emitted_and_reserved() -> tuple[set[str], set[str]]:
    """Split the event vocabulary by whether any code path emits it."""
    import re

    from bastion.audit.events import Event

    referenced: set[str] = set()
    for path in (ROOT / "src/bastion").rglob("*.py"):
        if path.name == "events.py":
            continue
        referenced |= set(re.findall(r"Event\.([A-Z_]+)", path.read_text(encoding="utf-8")))

    emitted = {e.value for e in Event if e.name in referenced}
    return emitted, {e.value for e in Event} - emitted


def test_reserved_events_are_marked_as_such() -> None:
    """The catalogue is the AU-2 deliverable, which separates what the system
    can log from what it does log.

    Fourteen names were listed with a plain "Recorded when" and no emitter, so
    an auditor would have gone looking for logout records that do not exist.
    """
    catalogue = (DOCS / "reference/audit-events.md").read_text(encoding="utf-8")
    _, reserved = emitted_and_reserved()

    unmarked = [
        value
        for value in sorted(reserved)
        if not any(
            line.startswith(f"| `{value}` |") and "Reserved" in line
            for line in catalogue.splitlines()
        )
    ]
    assert not unmarked, f"reserved events not marked in the catalogue: {unmarked}"


def test_emitted_events_are_not_marked_reserved() -> None:
    """The other direction: wiring up an emitter has to clear its marker, or
    the page starts understating what is available."""
    catalogue = (DOCS / "reference/audit-events.md").read_text(encoding="utf-8")
    emitted, _ = emitted_and_reserved()

    stale = [
        value
        for value in sorted(emitted)
        if any(
            line.startswith(f"| `{value}` |") and "Reserved" in line
            for line in catalogue.splitlines()
        )
    ]
    assert not stale, f"these events are emitted but still marked reserved: {stale}"


CONFIG_PAGES = [
    "README.md",
    "docs/tutorials/first-login.md",
    "docs/how-to/idp/entra.md",
]


@pytest.mark.parametrize("page", CONFIG_PAGES)
def test_documented_connection_keys_are_real(page: str) -> None:
    """Every connection key shown in a copyable example must be one the loader
    accepts.

    This exists because the README quickstart spent its whole life advertising
    ``protocol`` and ``discovery``, neither of which is a field. Anyone who
    pasted it got a ConfigurationError on the first request, and the two pages
    that walk through the same setup disagreed with it.
    """
    import re

    from bastion.connections import Connection

    text = (ROOT / page).read_text(encoding="utf-8")
    real = set(Connection.__dataclass_fields__) - {"identifier"}

    # Keys inside a CONNECTIONS block, which is the only place these appear.
    blocks = re.findall(r'"CONNECTIONS"\s*:\s*\{(.*?)\n    \},', text, re.DOTALL)
    assert blocks, f"{page} shows no CONNECTIONS block"

    documented = set()
    for block in blocks:
        # quirks_kwargs carries provider-specific names rather than connection
        # fields, so its contents are checked separately below.
        flat = re.sub(r'"quirks_kwargs"\s*:\s*\{[^}]*\}', "", block)
        documented |= set(re.findall(r'"([a-z_]+)"\s*:', flat))

    # The connection name itself is a key of CONNECTIONS, not of a connection.
    documented -= {"corp"}

    unknown = documented - real
    assert not unknown, f"{page} documents connection keys that do not exist: {sorted(unknown)}"


@pytest.mark.parametrize("page", CONFIG_PAGES)
def test_documented_quirks_kwargs_are_accepted(page: str) -> None:
    """quirks_kwargs is passed straight to the provider adapter, so a name that
    adapter does not take is a TypeError on the first login rather than a
    configuration error at startup."""
    import inspect
    import re

    from bastion.protocols.oidc.quirks import REGISTRY

    text = (ROOT / page).read_text(encoding="utf-8")
    for provider, kwargs_block in re.findall(
        r'"provider"\s*:\s*"(\w+)".*?"quirks_kwargs"\s*:\s*\{([^}]*)\}', text, re.DOTALL
    ):
        adapter = REGISTRY[provider]
        accepted = set(inspect.signature(adapter).parameters)
        documented = set(re.findall(r'"([a-z_]+)"\s*:', kwargs_block))
        unknown = documented - accepted
        assert not unknown, f"{page}: {provider} does not accept {sorted(unknown)}"


@pytest.mark.parametrize("page", CONFIG_PAGES)
def test_documented_connections_have_what_the_loader_requires(page: str) -> None:
    """A copyable example missing a required key fails at startup, which is a
    worse first impression than no example."""
    import re

    from bastion.connections import _REQUIRED

    text = (ROOT / page).read_text(encoding="utf-8")
    blocks = re.findall(r'"CONNECTIONS"\s*:\s*\{(.*?)\n    \},', text, re.DOTALL)

    for block in blocks:
        keys = set(re.findall(r'"([a-z_]+)"\s*:', block))
        missing = set(_REQUIRED) - keys
        assert not missing, f"{page} shows a connection missing {sorted(missing)}"


#: Settings declared in ``conf.DEFAULTS`` that nothing reads yet, each with the
#: reason. The list exists so that "declared but inert" is a visible, shrinking
#: set rather than something a reader discovers by grepping, which is how
#: ADMIN["require_mfa"] and IDENTITY["REQUIRE_VERIFIED_EMAIL"] both sat there
#: reading as security controls while enforcing nothing.
#:
#: Same shape as the reserved-event markers in the audit catalogue, and for the
#: same reason: the honest version of an unfinished feature is a marked one.
INERT_SETTINGS = {
    "BACKEND": "the backend is imported by path from AUTHENTICATION_BACKENDS, not from here",
    "MAPPING": "the dict itself is never resolved; its keys arrive with the rule engine",
    "MAPPING.STRICT": "arrives with the rule engine, v0.2",
    "MAPPING.MANAGED_GROUPS": "arrives with the rule engine, v0.2",
    "IDENTITY.LINKING_POLICY": "verified_email_once is not built",
    "ADMIN.reauth_max_age": "step-up re-authentication is not built",
    "ADMIN.local_login": "break-glass is configured under BREAK_GLASS instead",
}


def _setting_names() -> list[str]:
    from bastion.conf import DEFAULTS

    names = []
    for key, value in DEFAULTS.items():
        if isinstance(value, dict) and value:
            names.extend(f"{key}.{inner}" for inner in value)
        names.append(key)
    return names


def _accessed_keys() -> set[str]:
    """Every string literal the source actually *uses* as a key.

    Parsed rather than grepped, and that distinction is the test. A text search
    matches the setting name inside the very docstring that explains it, so the
    first version of this passed with the enforcement deleted -- a guard that
    cannot fail, which is worse than no guard. The AST sees only
    ``get_setting("X")``, ``d["X"]`` and ``d.get("X")``.
    """
    import ast

    found: set[str] = set()
    for path in (ROOT / "src" / "bastion").rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
                if isinstance(node.slice.value, str):
                    found.add(node.slice.value)
            elif isinstance(node, ast.Call):
                name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                if name in {"get", "get_setting"} and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        found.add(first.value)
    return found


def test_every_declared_setting_is_read_somewhere_or_marked_inert() -> None:
    """A setting that nothing reads is a security control that does not exist.

    Two of these were found by hand: ADMIN["require_mfa"] defaulted to True,
    appeared in the README quickstart, and enforced nothing; and
    IDENTITY["REQUIRE_VERIFIED_EMAIL"] defaulted to True while an address the
    provider marked unverified was provisioned and made staff. Neither had a
    failing test, because an unenforced control cannot have one.
    """
    accessed = _accessed_keys()
    unread = [
        name
        for name in _setting_names()
        if name not in INERT_SETTINGS and name.split(".")[-1] not in accessed
    ]

    assert not unread, (
        f"declared in conf.DEFAULTS and read nowhere: {sorted(unread)}. "
        "Either wire it up or add it to INERT_SETTINGS with the reason."
    )


def test_the_inert_list_names_only_settings_that_exist() -> None:
    """So the list shrinks when one is implemented instead of going stale."""
    declared = set(_setting_names())
    stale = sorted(set(INERT_SETTINGS) - declared)
    assert not stale, f"INERT_SETTINGS names settings that no longer exist: {stale}"
