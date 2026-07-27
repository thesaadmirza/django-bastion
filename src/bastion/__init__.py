"""django-bastion: enterprise SSO and identity governance for Django.

This package is the governance layer above a protocol implementation, not a
protocol implementation itself. Signature verification, canonicalization and
JOSE primitives are delegated to authlib, pysaml2 and python-ldap. Our job is
to assert their configuration, re-check their output structurally, and own
everything that happens after an assertion validates.

See FOUNDATIONS.md for the decision record, and docs/security/threat-model.md
for what this package does and does not defend against.
"""

from __future__ import annotations

__version__ = "0.0.1a0"
