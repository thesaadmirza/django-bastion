"""OpenID Connect relying party.

The delegation boundary here sits at the *primitive* level rather than the JOSE
level, which is a deliberate departure from the first draft of FOUNDATIONS.md
1.2. The reasoning:

Every policy decision a JOSE library makes on our behalf is one we override
anyway. We pin the algorithm allowlist, we refuse key material from the header,
we resolve keys ourselves, and we reject unknown ``crit``. What would remain
delegated is the encoding mechanics and the signature check itself.

Meanwhile the CVE record for those libraries is concentrated in exactly that
policy layer: fail-open verification on an unrecognised algorithm, trusting an
embedded ``jwk``, accepting ``alg: none``, algorithm confusion. Wrapping a
library while overriding all of its policy inherits its fail-open bugs without
inheriting any of its judgement.

So signature verification calls ``cryptography`` directly, which is the same
primitive library authlib and PyJWT both sit on. The encoding work this leaves
us owning is roughly fifty lines and is well understood: base64url padding,
raw-to-DER conversion for ECDSA, and PSS parameters.

The same reasoning ended up applying to the token endpoint. The exchange is a
form POST and a JSON parse; what actually needed care was never putting a
response body into an exception or a log, which is exactly the part a
general-purpose client would not do for us. So there is no JOSE or OAuth
library in the dependency list at all, and the HTTP transport is pluggable with
a standard-library default.
"""

from bastion.protocols.oidc.jose import (
    ALLOWED_ALGORITHMS,
    VerifiedToken,
    parse_header,
    verify_compact,
)
from bastion.protocols.oidc.jwks import JWKSStore
from bastion.protocols.oidc.quirks import REGISTRY, ProviderQuirks, to_identity_claims
from bastion.protocols.oidc.validation import (
    ValidationPolicy,
    validate_id_token,
    validate_userinfo,
)

__all__ = [
    "ALLOWED_ALGORITHMS",
    "REGISTRY",
    "JWKSStore",
    "ProviderQuirks",
    "ValidationPolicy",
    "VerifiedToken",
    "parse_header",
    "to_identity_claims",
    "validate_id_token",
    "validate_userinfo",
    "verify_compact",
]
