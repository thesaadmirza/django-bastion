"""Compact JWS serialisation, built by hand.

A correct JOSE library refuses to emit most of what is below. That is the whole
point of doing it here instead.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from tests.idp.keys import SigningKey


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_json(obj: Any) -> str:
    return b64u(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


def signing_input(header: dict[str, Any], payload: dict[str, Any]) -> bytes:
    return f"{b64u_json(header)}.{b64u_json(payload)}".encode()


def compact(header: dict[str, Any], payload: dict[str, Any], signature: bytes) -> str:
    return f"{b64u_json(header)}.{b64u_json(payload)}.{b64u(signature)}"


def sign(header: dict[str, Any], payload: dict[str, Any], key: SigningKey) -> str:
    """Ordinary, correct signature. The control case."""
    return compact(header, payload, key.sign(signing_input(header, payload)))


# --------------------------------------------------------------------------- #
# Attack shapes
# --------------------------------------------------------------------------- #


def alg_none(payload: dict[str, Any]) -> str:
    """`alg: none` with an empty signature.

    OIDC Core permits this for the code flow with explicit registration. We
    refuse it anyway (FOUNDATIONS.md A2), because the carve-out has produced a
    steady supply of bypasses, most recently authlib CVE-2026-28802.
    """
    return compact({"alg": "none", "typ": "JWT"}, payload, b"")


def hmac_with_public_key(payload: dict[str, Any], key: SigningKey) -> str:
    """The algorithm-confusion classic: sign with HS256 using the RP's copy of
    the IdP *public* key as the shared secret.

    A verifier that trusts the header's `alg` and looks up "the key" without
    pinning the algorithm family will treat this as valid. PyJWT has shipped
    this bug four separate times (CVE-2017-11424, CVE-2022-29217,
    CVE-2026-48526, CVE-2026-48523).
    """
    header = {"alg": "HS256", "typ": "JWT", "kid": key.kid}
    data = signing_input(header, payload)
    signature = hmac.new(key.public_pem(), data, hashlib.sha256).digest()
    return compact(header, payload, signature)


def embedded_jwk(payload: dict[str, Any], attacker_key: SigningKey) -> str:
    """Self-consistent token carrying the attacker's own key in the header.

    Signature verifies perfectly against the embedded key. The only defence is
    refusing to source key material from the message at all. This is authlib
    CVE-2026-27962, rated critical.
    """
    header = {
        "alg": attacker_key.alg,
        "typ": "JWT",
        "kid": attacker_key.kid,
        "jwk": attacker_key.public_jwk(),
    }
    return sign(header, payload, attacker_key)


def remote_key_url(payload: dict[str, Any], attacker_key: SigningKey, url: str) -> str:
    """Same idea as embedded_jwk, via `jku`. Also an SSRF primitive."""
    header = {"alg": attacker_key.alg, "typ": "JWT", "kid": attacker_key.kid, "jku": url}
    return sign(header, payload, attacker_key)


def unknown_crit(payload: dict[str, Any], key: SigningKey) -> str:
    """A `crit` header naming an extension the verifier does not implement.

    RFC 7515 says reject. Libraries that ignore it silently accept a token
    whose semantics they do not understand (authlib CVE-2025-59420).
    """
    header = {
        "alg": key.alg,
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


# --------------------------------------------------------------------------- #
# Hash claims
# --------------------------------------------------------------------------- #


def left_half_hash(value: str, alg: str = "RS256") -> str:
    """Compute at_hash / c_hash: leftmost half of the digest, base64url.

    We compute these ourselves rather than trusting a library, because the
    failure mode we care about is a helper that cannot compute the hash for an
    unrecognised algorithm and returns success anyway (authlib CVE-2026-28498).
    """
    bits = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}
    digest = bits[alg[-3:]](value.encode()).digest()
    return b64u(digest[: len(digest) // 2])


def decode_segment(token: str, index: int) -> dict[str, Any]:
    """Read a segment without verifying anything. Tests only."""
    segment = token.split(".")[index]
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))
