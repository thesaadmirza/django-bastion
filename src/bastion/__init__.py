"""django-bastion: enterprise SSO and identity governance for Django.

This package is the governance layer above a protocol implementation, not a
protocol implementation itself. Signature verification, canonicalization and
JOSE primitives are delegated to authlib, pysaml2 and python-ldap. Our job is
to assert their configuration, re-check their output structurally, and own
everything that happens after an assertion validates.

See docs/security/threat-model.md for what this package does and does not
defend against.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

#: Read from the installed distribution rather than written here.
#:
#: It was a literal, and the 0.0.1a1 release shipped reporting 0.0.1a0 because
#: bumping pyproject.toml does not touch a string in this file. Two places to
#: state one fact is one too many, and the one that drifts is the one nobody
#: looks at.
try:
    __version__ = version("django-bastion")
except PackageNotFoundError:  # pragma: no cover - only when running uninstalled
    # A source checkout with no install. Deliberately not a plausible-looking
    # number: something that reads as a real version here would be worse than
    # something obviously unset.
    __version__ = "0.0.0+unknown"
