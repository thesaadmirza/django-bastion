"""Provider metadata discovery.

The check that earns this module its existence is the issuer comparison. OIDC
Discovery requires that the ``issuer`` inside the document be **identical** to
the URL the document was fetched from. Skipping it means a provider that can
influence what you fetch can also tell you who it is, and every downstream
``iss`` check then validates against a value the attacker chose.

Everything else here is refusing to start on a configuration that cannot be
safe: a non-https endpoint, a missing token endpoint, a provider that does not
offer S256.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from bastion.exceptions import DiscoveryError
from bastion.protocols.oidc.transport import Transport, UrllibTransport, require_https

WELL_KNOWN = "/.well-known/openid-configuration"

REQUIRED_FIELDS = ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")

#: Endpoints that must be https if present at all.
ENDPOINT_FIELDS = (
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "userinfo_endpoint",
    "end_session_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
)


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """A validated discovery document."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    end_session_endpoint: str | None = None
    id_token_signing_alg_values_supported: tuple[str, ...] = ()
    code_challenge_methods_supported: tuple[str, ...] = ()
    response_modes_supported: tuple[str, ...] = ()
    supports_iss_parameter: bool = False
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def supports_rp_initiated_logout(self) -> bool:
        """Google publishes no ``end_session_endpoint``.

        Worth surfacing rather than discovering at logout time: against a
        provider without one, clearing the local session is all that is
        possible, and the next click on a protected URL silently signs the
        person back in.
        """
        return self.end_session_endpoint is not None


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return tuple(value)
    return ()


def validate_metadata(
    document: Mapping[str, Any],
    *,
    expected_issuer: str,
    require_s256: bool = True,
) -> ProviderMetadata:
    """Validate a discovery document and return the parsed metadata."""
    for name in REQUIRED_FIELDS:
        value = document.get(name)
        if not isinstance(value, str) or not value:
            raise DiscoveryError(f"discovery document is missing {name!r}")

    issuer = str(document["issuer"])
    if issuer != expected_issuer:
        # OIDC Discovery 4.3, and not a formality. Without it, whoever controls
        # what we fetch also controls the value every later `iss` check is
        # compared against.
        raise DiscoveryError(
            f"discovery document declares issuer {issuer!r}, "
            f"which does not match {expected_issuer!r}"
        )

    for name in ENDPOINT_FIELDS:
        endpoint = document.get(name)
        if isinstance(endpoint, str) and endpoint:
            require_https(endpoint, what=name)

    response_types = _strings(document.get("response_types_supported"))
    if response_types and "code" not in response_types:
        raise DiscoveryError("provider does not support the authorization code flow")

    challenge_methods = _strings(document.get("code_challenge_methods_supported"))
    if require_s256 and "S256" not in challenge_methods:
        raise DiscoveryError(
            "provider does not advertise S256 in code_challenge_methods_supported. "
            "PKCE is what prevents authorization code injection, and `plain` is "
            "not an acceptable substitute. If the provider supports S256 without "
            "advertising it, set require_s256=False on the connection and record "
            "why."
        )

    signing_algs = _strings(document.get("id_token_signing_alg_values_supported"))

    return ProviderMetadata(
        issuer=issuer,
        authorization_endpoint=str(document["authorization_endpoint"]),
        token_endpoint=str(document["token_endpoint"]),
        jwks_uri=str(document["jwks_uri"]),
        userinfo_endpoint=document.get("userinfo_endpoint"),
        end_session_endpoint=document.get("end_session_endpoint"),
        id_token_signing_alg_values_supported=signing_algs,
        code_challenge_methods_supported=challenge_methods,
        response_modes_supported=_strings(document.get("response_modes_supported")),
        supports_iss_parameter=bool(document.get("authorization_response_iss_parameter_supported")),
        raw=dict(document),
    )


def discovery_url(issuer: str) -> str:
    """Build the well-known URL. Trailing slashes are a common trip hazard."""
    return f"{issuer.rstrip('/')}{WELL_KNOWN}"


@dataclass
class DiscoveryCache:
    """Fetches and caches provider metadata.

    Same rate-limiting shape as the key store, for the same reason: a failure
    that triggers a refetch must not be reachable in a loop by anyone who can
    make a request.
    """

    issuer: str
    transport: Transport = field(default_factory=UrllibTransport)
    ttl: float = 3600.0
    min_refetch_interval: float = 60.0
    require_s256: bool = True
    clock: Callable[[], float] = time.monotonic

    _metadata: ProviderMetadata | None = field(default=None, repr=False)
    _fetched_at: float | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        require_https(self.issuer, what="issuer")

    def get(self, *, force: bool = False) -> ProviderMetadata:
        with self._lock:
            now = self.clock()
            cached = self._metadata
            fetched_at = self._fetched_at

            if cached is not None and fetched_at is not None:
                age = now - fetched_at
                if not force and age < self.ttl:
                    return cached
                if force and age < self.min_refetch_interval:
                    # Refetch throttled. Serve what we have rather than letting
                    # a repeatable failure become a stampede.
                    return cached

            document = self.transport.get_json(discovery_url(self.issuer))
            metadata = validate_metadata(
                document, expected_issuer=self.issuer, require_s256=self.require_s256
            )
            self._metadata = metadata
            self._fetched_at = now
            return metadata
