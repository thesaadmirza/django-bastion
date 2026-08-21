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
    # CONTRIBUTING and the code of conduct were not on this list, so their
    # links were the only ones in the repository nothing checked -- including,
    # for a while, an instruction to put changelog fragments in a directory
    # that has never existed.
    files += [ROOT / "CONTRIBUTING.md", ROOT / "CODE_OF_CONDUCT.md"]
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


def test_the_check_id_table_matches_the_checks() -> None:
    """The table is what someone reads to write `SILENCED_SYSTEM_CHECKS`.

    It is maintained by hand, so it drifts the moment a check is added, and an
    id that is silenced-by-copy-paste from a stale table silences nothing.
    Both directions matter: an undocumented check is unsilenceable in practice,
    and a documented id that no longer exists is a promise the code dropped.
    """
    source = (ROOT / "src/bastion/checks.py").read_text(encoding="utf-8")
    text = (DOCS / "reference/settings.md").read_text(encoding="utf-8")

    emitted = set(re.findall(r'id="(bastion\.[EW]\d+)"', source))
    documented = set(re.findall(r"`(bastion\.[EW]\d+)`", text))

    assert emitted, "no check ids found in checks.py; the pattern has drifted"
    assert not emitted - documented, (
        f"checks missing from the table: {sorted(emitted - documented)}"
    )
    assert not documented - emitted, f"table lists absent checks: {sorted(documented - emitted)}"


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


#: Distribution names whose import name differs from the name on PyPI.
_IMPORT_NAMES = {
    "pysaml2": "saml2",
    "python-ldap": "ldap",
    "django-auth-ldap": "django_auth_ldap",
    "psycopg": "psycopg",
    "mysqlclient": "MySQLdb",
}


def test_every_extra_installs_something_the_package_can_call() -> None:
    """An extra that pulls in a library nothing imports is a promise with no
    code behind it.

    `[saml]` installed pysaml2 and xmlsec, `[ldap]` built python-ldap from
    source, and neither had a single import in the package: `pip install
    django-bastion[saml]` put a signature-handling library with its own
    vulnerability history into the dependency tree and gave you nothing to
    call. Empty extras are fine -- `[oidc]` keeps an install line working --
    because they install nothing and therefore promise nothing.
    """
    import re
    import tomllib

    extras = (
        tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"].get(
            "optional-dependencies"
        )
        or {}
    )

    source = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "src/bastion").rglob("*.py")
    )

    unbacked: dict[str, list[str]] = {}
    for extra, requirements in extras.items():
        missing = []
        for requirement in requirements:
            # "pysaml2>=6.5.0" -> "pysaml2"
            distribution = re.split(r"[<>=!~\[; ]", requirement, maxsplit=1)[0].strip()
            module = _IMPORT_NAMES.get(distribution, distribution.replace("-", "_"))
            if not re.search(rf"^\s*(?:from|import)\s+{re.escape(module)}\b", source, re.M):
                missing.append(distribution)
        if missing:
            unbacked[extra] = missing

    assert not unbacked, (
        f"extras installing libraries the package never imports: {unbacked}. "
        "Add the implementation, or drop the extra until there is one."
    )


#: Libraries a security page must not credit unless they are actually here.
#: The threat model said signature verification was "delegated to authlib,
#: pysaml2 and python-ldap". None was ever imported and one was never even a
#: dependency, so the page told a reviewer the crypto was someone else's
#: audited code while the package carried a hand-rolled JWS verifier.
_LIBRARIES_THAT_MUST_BE_REAL = ("authlib", "pysaml2", "python-ldap", "xmlsec", "lxml", "joserfc")


@pytest.mark.parametrize("page", ["security/threat-model.md", "security/crypto-inventory.md"])
def test_no_security_page_credits_a_library_we_do_not_have(page: str) -> None:
    """Naming a library you do not depend on transfers its reputation to code
    that never runs it.

    Mentioning one is fine -- saying what is *not* used is useful, and the
    threat model does exactly that. What is refused is crediting it: naming it
    as the thing that performs a control.
    """
    import re
    import tomllib

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dependencies = " ".join(declared["dependencies"])
    for group in (declared.get("optional-dependencies") or {}).values():
        dependencies += " " + " ".join(group)

    text = (DOCS / page).read_text(encoding="utf-8")
    credited = []
    for library in _LIBRARIES_THAT_MUST_BE_REAL:
        if library in dependencies:
            continue
        # "delegated to authlib", "verified by pysaml2", "uses lxml"
        credits = r"(?:delegated to|handled by|verified by|performed by|uses|via)"
        pattern = rf"{credits}\s+[^.]*\b{re.escape(library)}\b"
        if re.search(pattern, text, re.I):
            credited.append(library)

    assert not credited, (
        f"{page} credits libraries this package does not depend on: {credited}. "
        "Say what the code actually does, or add the dependency."
    )


def _django_floor(*, mariadb: bool) -> tuple[int, ...]:
    """The minimum server version the installed Django enforces.

    Read off the descriptor rather than a live connection, because this has to
    work in the plain test job where no MySQL is running.
    """
    from types import SimpleNamespace

    from django.db.backends.mysql.features import DatabaseFeatures

    descriptor = DatabaseFeatures.__dict__["minimum_database_version"]
    resolve = getattr(descriptor, "func", None) or descriptor.fget
    fake = SimpleNamespace(connection=SimpleNamespace(mysql_is_mariadb=mariadb))
    return tuple(resolve(fake))


@pytest.mark.parametrize(
    ("service", "mariadb"),
    [("mariadb", True), ("mysql", False)],
)
def test_ci_runs_a_server_the_installed_django_will_talk_to(service: str, mariadb: bool) -> None:
    """The pinned image has to satisfy Django's floor, and Django moves it.

    Django 6.1 raised MariaDB from 10.6 to 10.11 and MySQL from 8.0.11 to 8.4.
    The workflow still pinned mariadb:10.6, so every database run started
    failing with `NotSupportedError` on a commit that changed nothing. Nobody
    finds that by reading the diff; the failure looks like the branch.

    Pinning the two together turns a Django release into a failing test with
    the new number in the message, rather than a red job on unrelated work.
    """
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    match = re.search(rf"^\s*image: {service}:(\S+)$", workflow, re.M)
    assert match, f"no {service} image pinned in ci.yml"

    pinned = tuple(int(part) for part in match.group(1).split("."))
    floor = _django_floor(mariadb=mariadb)

    # Compare on the components the pin actually states: the images are tagged
    # `10.11`, and Django's floor for MySQL carries a patch level.
    assert pinned >= floor[: len(pinned)], (
        f"ci.yml pins {service}:{match.group(1)}, but the installed Django "
        f"requires {'.'.join(str(p) for p in floor)}. Raise the image, and the "
        f"floor named in SUPPORT_MATRIX.md with it."
    )


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
    "ADMIN.reauth_max_age": "step-up re-authentication is not built",
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


def test_the_inert_list_does_not_name_settings_that_are_read() -> None:
    """The other direction, and the one that goes wrong quietly.

    A setting implemented while its entry stays behind leaves the list saying a
    control does nothing when it now does. That is the same defect as the entry
    being missing, read backwards: both are the honest-unfinished-feature marker
    telling the reader something untrue. ``IDENTITY["LINKING_POLICY"]`` and
    ``ADMIN["local_login"]`` were both implemented in one change, and only this
    catches the leftovers.
    """
    accessed = _accessed_keys()
    live = sorted(name for name in INERT_SETTINGS if name.split(".")[-1] in accessed)
    assert not live, (
        f"INERT_SETTINGS still lists settings the source reads: {live}. "
        "Remove the entry: the feature landed."
    )
