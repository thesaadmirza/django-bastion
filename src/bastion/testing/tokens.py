"""Compact JWS serialisation, built by hand.

Deliberately not built on a JOSE library. A correct one refuses to emit most of
what a test corpus needs, and you cannot check that ``alg: none`` is rejected
using a library that will not serialise it.

What lives here is the honest half: assembling and signing a well-formed token.
The malformed and hostile shapes stay in this project's own test suite. They
exist to prove that *bastion* refuses them, which is bastion's job to test, not
yours -- and publishing them would commit this package to an attack-token API
it has no reason to support.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from bastion.testing.keys import SigningKey


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_json(obj: Any) -> str:
    return b64u(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


def signing_input(header: dict[str, Any], payload: dict[str, Any]) -> bytes:
    return f"{b64u_json(header)}.{b64u_json(payload)}".encode()


def compact(header: dict[str, Any], payload: dict[str, Any], signature: bytes) -> str:
    return f"{b64u_json(header)}.{b64u_json(payload)}.{b64u(signature)}"


def sign(header: dict[str, Any], payload: dict[str, Any], key: SigningKey) -> str:
    """An ordinary, correct signature."""
    return compact(header, payload, key.sign(signing_input(header, payload)))


def left_half_hash(value: str, alg: str = "RS256") -> str:
    """``at_hash``: left half of the hash of the access token, base64url.

    Here rather than in the attack corpus because a provider that omits it is
    normal and a provider that gets it wrong is a bug worth reproducing.
    """
    import hashlib

    digest = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}[alg[-3:]]
    hashed = digest(value.encode()).digest()
    return b64u(hashed[: len(hashed) // 2])


def decode_segment(token: str, index: int) -> dict[str, Any]:
    """Read a header or payload back out of a compact token."""
    segment = token.split(".")[index]
    padded = segment + "=" * (-len(segment) % 4)
    decoded: dict[str, Any] = json.loads(base64.urlsafe_b64decode(padded))
    return decoded
