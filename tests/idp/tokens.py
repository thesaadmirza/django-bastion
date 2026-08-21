"""Malformed and hostile tokens, built by hand.

The honest half of this -- assembling and signing a well-formed token -- moved
to ``bastion.testing.tokens`` when the harness became a supported thing to
import. What stays here is the corpus that exists to prove *bastion* refuses
it: `alg: none`, algorithm confusion, key injection, an unknown `crit`.

Those are not useful to a project integrating this package. They test the
library, not the deployment, and publishing them would commit bastion to an
attack-token API with no reason to exist. They stay in this suite.

A correct JOSE library refuses to emit nearly all of it, which is why none is
used here.
"""

from __future__ import annotations

import hmac
from typing import Any

from bastion.testing.keys import SigningKey
from bastion.testing.tokens import (
    b64u,
    b64u_json,
    compact,
    decode_segment,
    left_half_hash,
    sign,
    signing_input,
)

__all__ = [
    "alg_none",
    "b64u",
    "b64u_json",
    "compact",
    "decode_segment",
    "embedded_jwk",
    "hmac_with_public_key",
    "left_half_hash",
    "remote_key_url",
    "sign",
    "signing_input",
    "stripped_signature",
    "tampered_payload",
    "unknown_crit",
]


def alg_none(payload: dict[str, Any]) -> str:
    """`alg: none` with an empty signature."""
    return f"{b64u_json({'alg': 'none', 'typ': 'JWT'})}.{b64u_json(payload)}."


def hmac_with_public_key(payload: dict[str, Any], key: SigningKey) -> str:
    """Algorithm confusion: HS256 keyed with the provider's public key.

    A verifier that picks the algorithm from the header rather than from policy
    treats the public key as a shared secret, and anybody holding the JWKS can
    then mint tokens.
    """
    import hashlib

    header = {"alg": "HS256", "typ": "JWT", "kid": key.kid}
    signature = hmac.new(key.public_pem(), signing_input(header, payload), hashlib.sha256).digest()
    return compact(header, payload, signature)


def embedded_jwk(payload: dict[str, Any], attacker_key: SigningKey) -> str:
    """Key injection through the `jwk` header parameter."""
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": attacker_key.kid,
        "jwk": attacker_key.public_jwk(),
    }
    return sign(header, payload, attacker_key)


def remote_key_url(payload: dict[str, Any], attacker_key: SigningKey, url: str) -> str:
    """Key injection through `jku`, which also makes the verifier fetch."""
    header = {"alg": "RS256", "typ": "JWT", "kid": attacker_key.kid, "jku": url}
    return sign(header, payload, attacker_key)


def unknown_crit(payload: dict[str, Any], key: SigningKey) -> str:
    """A `crit` header naming an extension nothing implements.

    RFC 7515 requires rejection. A verifier that ignores `crit` accepts a token
    whose meaning it has not understood.
    """
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": key.kid,
        "crit": ["urn:example:not-a-real-extension"],
        "urn:example:not-a-real-extension": True,
    }
    return sign(header, payload, key)


def tampered_payload(token: str, replacement: dict[str, Any]) -> str:
    """Swap the payload, keep the original signature. Must never verify."""
    header_b64, _, signature_b64 = token.split(".")
    return f"{header_b64}.{b64u_json(replacement)}.{signature_b64}"


def stripped_signature(token: str) -> str:
    """Valid header and payload, signature removed but the dot kept."""
    header_b64, payload_b64, _ = token.split(".")
    return f"{header_b64}.{payload_b64}."
