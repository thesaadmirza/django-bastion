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
