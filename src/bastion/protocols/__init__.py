"""Protocol adapters.

Each adapter's only job is producing an ``IdentityClaims``. Everything above
that seam is protocol-agnostic, which is what lets one mapping engine serve
OIDC, SAML, LDAP and proxy-header auth without being written four times.
"""
