"""The configuration surface, held still.

0.1.0 means the configuration stops moving, and prose alone does not stop it.
Every key a deployment can set, and every check id it can silence, is listed
below. Adding one is fine and takes a line here; the point is that it cannot
happen by accident, and that a reviewer sees the surface change in the diff
rather than inferring it from a dataclass field.

Removing or renaming one is not fine on its own. That is what
docs/reference/deprecation-policy.md is for, and the failure messages below
point at it.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Global settings, as nested paths under ``BASTION``.
GLOBAL_SETTINGS = {
    "SUCCESS_URL",
    "CONNECTIONS",
    "IDENTITY.KEY",
    "IDENTITY.LINKING_POLICY",
    "IDENTITY.LINKABLE_EMAIL_DOMAINS",
    "IDENTITY.REQUIRE_VERIFIED_EMAIL",
    "ADMIN.enabled",
    "ADMIN.connection",
    "ADMIN.require_mfa",
    "ADMIN.local_login",
    "BREAK_GLASS.ENABLED",
    "BREAK_GLASS.ALLOWED_NETWORKS",
    "BREAK_GLASS.ALERT_SINKS",
    "BREAK_GLASS.MAX_FAILURES_PER_IP",
    "BREAK_GLASS.FAILURE_WINDOW_SECONDS",
    "BREAK_GLASS.SUCCESS_URL",
    "AUDIT.SINKS",
    "AUDIT.RETENTION_DAYS",
}

#: Keys a ``BASTION["CONNECTIONS"]`` entry may carry.
CONNECTION_KEYS = {
    "issuer",
    "client_id",
    "client_secret",
    "provider",
    "quirks_kwargs",
    "scopes",
    "auth_method",
    "staff_groups",
    "superuser_groups",
    "require_mfa",
    "require_privileged_user",
    "require_s256",
    "persist_refused_identities",
    "store_id_token",
    "post_logout_redirect_uri",
    # Extension points. Objects rather than data, so they are only reachable
    # from a settings module that builds one -- which is legal, settings.py
    # being Python, and is how a custom transport or a shared transaction
    # store gets in.
    "transport",
    "transactions",
    "validation",
}

#: Ids a deployment may put in ``SILENCED_SYSTEM_CHECKS``.
CHECK_IDS = {
    "bastion.E022",
    "bastion.E023",
    "bastion.E024",
    "bastion.E026",
    "bastion.E027",
    "bastion.E028",
    "bastion.E029",
    "bastion.E100",
    "bastion.E101",
    "bastion.E102",
    "bastion.W027",
    "bastion.W028",
    "bastion.W030",
    "bastion.W031",
    "bastion.W032",
}

#: Keys that were removed or renamed and are still refused by name. The policy
#: says how long each stays here, and the count is what stops the list growing
#: forever unnoticed.
REFUSED_KEYS = {"discovery", "protocol", "require_group_match"}

POLICY = "docs/reference/deprecation-policy.md"


def _flatten(mapping: dict, prefix: str = "") -> set[str]:
    found: set[str] = set()
    for key, value in mapping.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict) and value:
            found |= _flatten(value, prefix=f"{path}.")
        else:
            found.add(path)
    return found


def _explain(kind: str, added: set[str], removed: set[str]) -> str:
    lines = [f"the {kind} surface moved."]
    if added:
        lines.append(f"  new: {sorted(added)} -- add them here and to the reference.")
    if removed:
        lines.append(
            f"  gone: {sorted(removed)} -- removing one is a breaking change; see {POLICY}."
        )
    return "\n".join(lines)


def test_the_global_settings_are_the_ones_documented() -> None:
    from bastion.conf import DEFAULTS

    found = _flatten(DEFAULTS)
    assert found == GLOBAL_SETTINGS, _explain(
        "global settings", found - GLOBAL_SETTINGS, GLOBAL_SETTINGS - found
    )


def test_the_connection_keys_are_the_ones_documented() -> None:
    from bastion.connections import _SETTABLE_KEYS

    found = set(_SETTABLE_KEYS)
    assert found == CONNECTION_KEYS, _explain(
        "connection", found - CONNECTION_KEYS, CONNECTION_KEYS - found
    )


def test_the_check_ids_are_the_ones_documented() -> None:
    source = (ROOT / "src/bastion/checks.py").read_text(encoding="utf-8")
    found = set(re.findall(r'id="(bastion\.[EW]\d+)"', source))
    assert found == CHECK_IDS, _explain("check id", found - CHECK_IDS, CHECK_IDS - found)


def test_the_refused_keys_are_the_ones_documented() -> None:
    """A rename that is never finished is a second name kept alive forever."""
    from bastion.connections import _RENAMED_KEYS

    found = set(_RENAMED_KEYS)
    assert found == REFUSED_KEYS, _explain(
        "refused key", found - REFUSED_KEYS, REFUSED_KEYS - found
    )


def test_every_connection_key_is_in_the_reference() -> None:
    """A key that works and is undocumented is one nobody sets on purpose."""
    text = (ROOT / "docs/reference/settings.md").read_text(encoding="utf-8")
    undocumented = sorted(key for key in CONNECTION_KEYS if f"`{key}`" not in text)
    assert not undocumented, f"connection keys missing from the reference: {undocumented}"


def test_every_global_setting_is_in_the_reference() -> None:
    text = (ROOT / "docs/reference/settings.md").read_text(encoding="utf-8")
    # The leaf name is what the reference tables show.
    undocumented = sorted(
        path for path in GLOBAL_SETTINGS if f"`{path.rsplit('.', 1)[-1]}`" not in text
    )
    assert not undocumented, f"settings missing from the reference: {undocumented}"


def test_the_deprecation_policy_exists() -> None:
    """Referenced by every failure message above."""
    assert (ROOT / POLICY).exists(), f"{POLICY} is what those messages point at"
