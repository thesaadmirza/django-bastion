"""Compact JWS verification.

Order of operations matters here and is not arbitrary. Policy checks that need
no key run first, so a hostile token is rejected before it can influence key
selection or reach a crypto primitive. Nothing in this module returns a
sentinel: every rejection raises.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from bastion.exceptions import (
    AlgorithmNotAllowed,
    KeyNotFound,
    MalformedToken,
    SignatureVerificationFailed,
    TokenTooLarge,
    UnsupportedCriticalHeader,
    UntrustedKeyMaterial,
)

#: Asymmetric only. Expressing this as an allowlist rather than a denylist is
#: what makes ``alg: none`` and the entire HMAC family unreachable without
#: either needing a special case.
#:
#: HMAC is excluded on purpose even though OIDC permits ``HS256`` with the
#: client secret as the key. Symmetric verification is the substrate of the
#: algorithm-confusion class, where an attacker signs with HMAC using the
#: provider's *public* key as the shared secret. Refusing the family removes
#: the class instead of guarding it.
ALLOWED_ALGORITHMS: frozenset[str] = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)

#: Header parameters that carry key material. A token must never nominate the
#: key used to verify it.
FORBIDDEN_HEADER_PARAMS: frozenset[str] = frozenset({"jwk", "jku", "x5u", "x5c"})

#: Checked before parsing. A generous ID token is a few kilobytes; anything
#: near this is either a bug or an attempt at resource exhaustion.
MAX_TOKEN_BYTES = 16 * 1024

#: Typed as factories rather than as ``type[HashAlgorithm]``. The values are
#: concrete subclasses, but the annotation would let mypy think an abstract
#: base is being instantiated.
_HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "256": hashes.SHA256,
    "384": hashes.SHA384,
    "512": hashes.SHA512,
}


class KeyResolver(Protocol):
    """Resolves a verification key. Raises ``KeyNotFound`` rather than
    returning ``None``, so that "no key" can never be read as "no signature
    required"."""

    def __call__(self, *, kid: str | None, alg: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    header: Mapping[str, Any]
    claims: Mapping[str, Any]


def _b64u_decode(segment: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as exc:
        raise MalformedToken("segment is not valid base64url") from exc


def _json_segment(segment: str, what: str) -> dict[str, Any]:
    try:
        decoded = json.loads(_b64u_decode(segment))
    except json.JSONDecodeError as exc:
        raise MalformedToken(f"{what} is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise MalformedToken(f"{what} is not a JSON object")
    return decoded


def _split(token: str) -> tuple[str, str, str]:
    if len(token.encode()) > MAX_TOKEN_BYTES:
        raise TokenTooLarge(f"token exceeds {MAX_TOKEN_BYTES} bytes")
    parts = token.split(".")
    if len(parts) == 5:
        # JWE. We do not accept encrypted ID tokens, partly because the
        # compressed variant is a decompression bomb (CVE-2025-62706).
        raise MalformedToken("encrypted tokens are not accepted")
    if len(parts) != 3:
        raise MalformedToken("expected three segments")
    return parts[0], parts[1], parts[2]


def parse_header(token: str) -> Mapping[str, Any]:
    """Read the header without verifying anything.

    Public because callers legitimately need the ``kid`` before a key exists,
    and because pretending otherwise leads to people reaching for their own
    base64 decoder. Treat everything it returns as attacker-controlled.
    """
    header_b64, _, _ = _split(token)
    return _json_segment(header_b64, "header")


def _check_header_policy(header: Mapping[str, Any], allowed: frozenset[str]) -> str:
    supplied = FORBIDDEN_HEADER_PARAMS & header.keys()
    if supplied:
        raise UntrustedKeyMaterial(f"header supplies key material via {sorted(supplied)}")

    alg = header.get("alg")
    if not isinstance(alg, str):
        raise MalformedToken("header has no algorithm")
    if alg not in allowed:
        # Covers "none" and every HS* variant without naming either.
        raise AlgorithmNotAllowed(f"algorithm {alg!r} is not permitted")

    crit = header.get("crit")
    if crit is not None:
        if not isinstance(crit, list) or not all(isinstance(c, str) for c in crit):
            raise MalformedToken("crit must be a list of strings")
        if not crit:
            # RFC 7515 4.1.11: producers must not emit an empty list, and a
            # recipient that sees one is looking at an invalid JWS.
            raise MalformedToken("crit must not be empty")
        # We implement no crit extensions. RFC 7515 requires rejecting any
        # header listed here that we do not understand, which is all of them.
        raise UnsupportedCriticalHeader(f"unsupported critical headers: {sorted(crit)}")

    return alg


def _verify_signature(key: Any, signature: bytes, signed: bytes, alg: str) -> None:
    """Delegate to ``cryptography``. Any failure becomes one exception type."""
    try:
        if alg == "EdDSA":
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise SignatureVerificationFailed("key does not match algorithm")
            key.verify(signature, signed)
            return

        hash_cls = _HASHES[alg[-3:]]

        if alg.startswith("ES"):
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise SignatureVerificationFailed("key does not match algorithm")
            size = len(signature) // 2
            if size == 0 or len(signature) % 2:
                raise SignatureVerificationFailed("malformed ECDSA signature")
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
            key.verify(encode_dss_signature(r, s), signed, ec.ECDSA(hash_cls()))
            return

        if not isinstance(key, rsa.RSAPublicKey):
            raise SignatureVerificationFailed("key does not match algorithm")

        if alg.startswith("PS"):
            key.verify(
                signature,
                signed,
                padding.PSS(
                    mgf=padding.MGF1(hash_cls()),
                    salt_length=padding.PSS.DIGEST_LENGTH,
                ),
                hash_cls(),
            )
            return

        key.verify(signature, signed, padding.PKCS1v15(), hash_cls())

    except InvalidSignature as exc:
        raise SignatureVerificationFailed("signature did not verify") from exc


def verify_compact(
    token: str,
    *,
    key_resolver: KeyResolver,
    allowed_algorithms: frozenset[str] = ALLOWED_ALGORITHMS,
) -> VerifiedToken:
    """Verify a compact JWS and return its header and claims.

    Claim validation is deliberately not done here. Proving a token was signed
    by a key we trust and deciding whether its contents are acceptable are
    different questions, and tangling them is how ``iss`` checks end up
    accidentally skipped for one code path.
    """
    header_b64, payload_b64, signature_b64 = _split(token)

    header = _json_segment(header_b64, "header")
    alg = _check_header_policy(header, allowed_algorithms)

    kid = header.get("kid")
    if kid is not None and not isinstance(kid, str):
        raise MalformedToken("kid must be a string")

    # Raises KeyNotFound. There is no path here that continues without a key.
    key = key_resolver(kid=kid, alg=alg)
    if key is None:  # pragma: no cover - defensive; a resolver must raise
        raise KeyNotFound("key resolver returned no key")

    signature = _b64u_decode(signature_b64)
    if not signature:
        raise SignatureVerificationFailed("signature is empty")

    _verify_signature(key, signature, f"{header_b64}.{payload_b64}".encode(), alg)

    return VerifiedToken(header=header, claims=_json_segment(payload_b64, "payload"))
