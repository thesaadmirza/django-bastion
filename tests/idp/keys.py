"""Signing keys and JWK serialisation for the synthetic IdP."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

HASHES = {
    "RS256": hashes.SHA256,
    "RS384": hashes.SHA384,
    "RS512": hashes.SHA512,
    "PS256": hashes.SHA256,
    "ES256": hashes.SHA256,
}


def b64u_uint(value: int) -> str:
    """Base64url-encode an integer the way JWK wants it (RFC 7518 §6.3.1)."""
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


@dataclass(frozen=True)
class SigningKey:
    """One key pair, plus the JWK representation an RP would fetch.

    ``kid`` is the RFC 7638 thumbprint rather than a random string, because a
    real provider's kid is stable across restarts and we want key-rotation
    tests to be able to assert on it.
    """

    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    alg: str = "RS256"
    _kid: str | None = field(default=None, repr=False)

    @property
    def public(self) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
        return self.private.public_key()

    @property
    def kid(self) -> str:
        if self._kid is not None:
            return self._kid
        return self.thumbprint()

    def thumbprint(self) -> str:
        """RFC 7638 JWK thumbprint. Members sorted, no whitespace, required only."""
        jwk = self.public_jwk(include_meta=False)
        if jwk["kty"] == "RSA":
            required = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
        else:
            required = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
        canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
        digest = hashlib.sha256(canonical.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def public_jwk(self, *, include_meta: bool = True) -> dict[str, str]:
        if isinstance(self.public, rsa.RSAPublicKey):
            numbers = self.public.public_numbers()
            jwk = {"kty": "RSA", "n": b64u_uint(numbers.n), "e": b64u_uint(numbers.e)}
        else:
            numbers = self.public.public_numbers()
            size = (self.public.curve.key_size + 7) // 8
            jwk = {
                "kty": "EC",
                "crv": "P-256",
                "x": base64.urlsafe_b64encode(numbers.x.to_bytes(size, "big"))
                .rstrip(b"=")
                .decode(),
                "y": base64.urlsafe_b64encode(numbers.y.to_bytes(size, "big"))
                .rstrip(b"=")
                .decode(),
            }
        if include_meta:
            jwk.update({"kid": self.kid, "alg": self.alg, "use": "sig"})
        return jwk

    def public_pem(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, signing_input: bytes) -> bytes:
        """Sign with this key's declared algorithm."""
        hash_cls = HASHES[self.alg]
        if isinstance(self.private, ec.EllipticCurvePrivateKey):
            der = self.private.sign(signing_input, ec.ECDSA(hash_cls()))
            return _der_to_raw(der, (self.private.curve.key_size + 7) // 8)
        if self.alg.startswith("PS"):
            return self.private.sign(
                signing_input,
                padding.PSS(
                    mgf=padding.MGF1(hash_cls()),
                    salt_length=padding.PSS.DIGEST_LENGTH,
                ),
                hash_cls(),
            )
        return self.private.sign(signing_input, padding.PKCS1v15(), hash_cls())


def _der_to_raw(der: bytes, size: int) -> bytes:
    """Convert a DER ECDSA signature to the raw r||s form JOSE requires."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(der)
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def generate_key(alg: str = "RS256", *, kid: str | None = None) -> SigningKey:
    """Generate a fresh key pair.

    2048-bit RSA takes roughly 50ms, which is cheap enough to do per session
    but not per test. Fixtures scope this accordingly.
    """
    if alg.startswith("ES"):
        private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = ec.generate_private_key(
            ec.SECP256R1()
        )
    else:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return SigningKey(private=private, alg=alg, _kid=kid)
