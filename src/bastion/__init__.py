"""django-bastion: enterprise SSO and identity governance for Django.

Two things, and the second one is the part a reviewer should look at hardest.

A governance layer: who gets an account, what privileges a claim may grant,
what is written to the audit chain, and what happens when the provider says
something unexpected.

And an OIDC relying party, implemented here rather than taken from a library.
``protocols/oidc`` owns compact JWS verification: token parsing, the algorithm
allowlist, key selection from discovery-derived JWKS, and the order those
happen in. Only the primitives underneath -- signature verification, hashing --
come from ``cryptography``. There is no JOSE library in the dependency tree;
see ``protocols/oidc/jose.py`` for what that module does and why.

No SAML, LDAP or SCIM. Those are on the roadmap and none of the code exists,
so nothing here defends the assertion-parsing or directory-binding attack
surface that comes with them.

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
