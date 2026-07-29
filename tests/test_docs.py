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
