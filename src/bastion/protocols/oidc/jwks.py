"""JWKS cache and key resolution.

Two threats shape this module.

An attacker who can post tokens carrying arbitrary ``kid`` values must not be
able to drive one outbound request per token. PyJWT's key client had exactly
that amplification (CVE-2026-48524), so refetching is rate limited and a cache
miss under throttle is a rejection rather than a fetch.

And the JWKS URI itself is a request the server makes on behalf of a
configuration value. PyJWT accepted arbitrary schemes there, turning it into an
SSRF primitive and a local-file read (CVE-2026-48522). We accept ``https``
only, checked at construction so a bad value fails at startup.
"""

from __future__ import annotations

import base64
import binascii
import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from bastion.exceptions import DiscoveryError, InsecureEndpoint, KeyNotFound

logger = logging.getLogger(__name__)

Fetcher = Callable[[str], Mapping[str, Any]]

#: Factories, for the same reason as the hash table in jose.py.
_CURVES: dict[str, Callable[[], ec.EllipticCurve]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}

#: Algorithms a JWK of each key type can possibly be used with. Prevents a
#: resolver from handing back an RSA key for an ES256 header, which would fail
#: later but only after the key had been selected.
_KTY_ALGS = {
    "RSA": ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"),
    "EC": ("ES256", "ES384", "ES512"),
    "OKP": ("EdDSA",),
}


def _b64u_int(value: str) -> int:
    return int.from_bytes(_b64u_bytes(value), "big")


def _b64u_bytes(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise DiscoveryError("JWK contains invalid base64url") from exc


def jwk_to_public_key(jwk: Mapping[str, Any]) -> Any:
    """Convert one JWK to a ``cryptography`` public key."""
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            numbers = rsa.RSAPublicNumbers(_b64u_int(jwk["e"]), _b64u_int(jwk["n"]))
            return numbers.public_key()
        if kty == "EC":
            curve = _CURVES.get(jwk.get("crv", ""))
            if curve is None:
                raise DiscoveryError(f"unsupported curve {jwk.get('crv')!r}")
            return ec.EllipticCurvePublicNumbers(
                _b64u_int(jwk["x"]), _b64u_int(jwk["y"]), curve()
            ).public_key()
        if kty == "OKP":
            if jwk.get("crv") != "Ed25519":
                raise DiscoveryError(f"unsupported OKP curve {jwk.get('crv')!r}")
            return ed25519.Ed25519PublicKey.from_public_bytes(_b64u_bytes(jwk["x"]))
    except KeyError as exc:
        raise DiscoveryError(f"JWK is missing {exc.args[0]!r}") from exc
    except ValueError as exc:
        raise DiscoveryError("JWK contains invalid key material") from exc

    raise DiscoveryError(f"unsupported key type {kty!r}")


@dataclass
class JWKSStore:
    """Caches a provider's signing keys and resolves them by ``kid``.

    Thread safe. Django serves requests concurrently and a burst of logins
    after a key rotation would otherwise stampede the provider.
    """

    uri: str
    fetcher: Fetcher

    #: Shortest gap between two network fetches. A cache miss inside this
    #: window is rejected rather than triggering a request.
    min_refetch_interval: float = 60.0

    #: Ceiling on fetches within ``rate_window`` regardless of spacing, so a
    #: slow drip of unknown kids cannot amplify either.
    max_fetches_per_window: int = 5
    rate_window: float = 3600.0

    clock: Callable[[], float] = time.monotonic

    _keys: dict[str, Any] = field(default_factory=dict, repr=False)
    _kty_by_kid: dict[str, str] = field(default_factory=dict, repr=False)
    _last_fetch: float | None = field(default=None, repr=False)
    _fetch_times: list[float] = field(default_factory=list, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        scheme = urlparse(self.uri).scheme
        if scheme != "https":
            raise InsecureEndpoint(
                f"JWKS URI must use https, got {scheme or 'no scheme'!r}. "
                "Anything else makes this a server-side request forgery "
                "primitive controlled by configuration."
            )

    # ------------------------------------------------------------------ api --

    def resolve(self, *, kid: str | None, alg: str) -> Any:
        """Return the verification key, or raise. Never returns ``None``."""
        with self._lock:
            key = self._lookup(kid, alg)
            if key is not None:
                return key

            if not self._may_fetch():
                raise KeyNotFound(f"no key for kid={kid!r} and refetching is rate limited")

            self._refresh()

            key = self._lookup(kid, alg)
            if key is None:
                raise KeyNotFound(f"no key matches kid={kid!r} for algorithm {alg}")
            return key

    def prime(self) -> None:
        """Fetch eagerly. Used by the startup doctor so a broken JWKS URI is a
        deployment failure rather than a login failure."""
        with self._lock:
            self._refresh()

    @property
    def kids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._keys)

    # -------------------------------------------------------------- internal --

    def _lookup(self, kid: str | None, alg: str) -> Any | None:
        if kid is not None:
            key = self._keys.get(kid)
            if key is None:
                return None
            if alg not in _KTY_ALGS.get(self._kty_by_kid.get(kid, ""), ()):
                # Right kid, wrong family. Treat as a miss rather than handing
                # back a key the algorithm cannot use.
                return None
            return key

        # No kid. Only unambiguous when the provider publishes exactly one key
        # usable with this algorithm; guessing among several is how the wrong
        # key gets selected during a rotation.
        usable = [
            key
            for stored_kid, key in self._keys.items()
            if alg in _KTY_ALGS.get(self._kty_by_kid.get(stored_kid, ""), ())
        ]
        return usable[0] if len(usable) == 1 else None

    def _may_fetch(self) -> bool:
        now = self.clock()
        if self._last_fetch is not None and now - self._last_fetch < self.min_refetch_interval:
            return False
        self._fetch_times = [t for t in self._fetch_times if now - t < self.rate_window]
        return len(self._fetch_times) < self.max_fetches_per_window

    def _refresh(self) -> None:
        now = self.clock()
        self._last_fetch = now
        self._fetch_times.append(now)

        document = self.fetcher(self.uri)
        keys: Any = document.get("keys", [])
        if not isinstance(keys, list) or not keys:
            raise DiscoveryError("JWKS document contains no keys")

        parsed: dict[str, Any] = {}
        kty_by_kid: dict[str, str] = {}
        for jwk in keys:
            if not isinstance(jwk, Mapping):
                continue
            kid = jwk.get("kid")
            if not isinstance(kid, str):
                continue
            if jwk.get("use") not in (None, "sig"):
                continue
            try:
                parsed[kid] = jwk_to_public_key(jwk)
            except DiscoveryError:
                # One unusable key must not poison the whole set. A provider
                # mid-rotation can legitimately publish something we cannot
                # parse, and refusing every login over it is worse. Logged
                # rather than swallowed: a kid is a public identifier, and a
                # provider that starts publishing junk is worth knowing about.
                logger.warning("Skipping unusable JWK kid=%r from %s", kid, self.uri, exc_info=True)
                continue
            kty_by_kid[kid] = str(jwk.get("kty"))

        if not parsed:
            raise DiscoveryError("JWKS document contained no usable signing keys")

        # Replace wholesale rather than merging. A key withdrawn by the
        # provider must stop being accepted here too.
        self._keys = parsed
        self._kty_by_kid = kty_by_kid
