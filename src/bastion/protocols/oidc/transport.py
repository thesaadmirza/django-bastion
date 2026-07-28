"""HTTP transport for provider endpoints.

Pluggable, with a standard-library default. A library should not force a
particular HTTP client on the applications that embed it, and the two or three
requests a login makes do not justify a dependency.

The default is deliberately small. What it insists on is the set of things that
are easy to get wrong and expensive to get wrong here:

- **A timeout, always.** ``urllib`` has none by default, so a provider that
  accepts the connection and then stalls holds a worker forever. That is the
  whole denial-of-service, and it needs no attacker.
- **https at every hop.** Including after redirects, since a 302 to ``http``
  would otherwise put a client secret on the wire in clear.
- **A response size cap**, applied while reading rather than after.
- **Nothing sensitive in an exception.** A failure carries a status code and a
  URL, never a body. Token endpoint responses contain credentials, and an
  exception message is the most likely thing to reach a log aggregator.

Swap it out by passing any object with the same two methods. ``requests`` or
``httpx`` wrappers are three lines each and get you connection pooling.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from bastion.exceptions import DiscoveryError, InsecureEndpoint

#: Generous for a discovery document or a JWKS; absurd for either to exceed.
MAX_RESPONSE_BYTES = 1024 * 1024

DEFAULT_TIMEOUT = 10.0


class Transport(Protocol):
    """The two request shapes an OIDC relying party needs."""

    def get_json(self, url: str) -> Mapping[str, Any]: ...

    def post_form(
        self,
        url: str,
        *,
        data: Mapping[str, str],
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, Mapping[str, Any]]: ...


class TransportError(DiscoveryError):
    """A request failed. Carries a status and a URL, never a body."""


def require_https(url: str, *, what: str = "endpoint") -> None:
    if urllib.parse.urlparse(url).scheme != "https":
        raise InsecureEndpoint(f"{what} must use https: {url!r}")


@dataclass
class UrllibTransport:
    """Standard-library transport. No connection pooling, no dependencies."""

    timeout: float = DEFAULT_TIMEOUT
    max_bytes: int = MAX_RESPONSE_BYTES
    user_agent: str = "django-bastion"

    def read_capped(self, reader: Any) -> bytes:
        """Read at most ``max_bytes``, refusing anything larger.

        Reads one byte past the limit rather than checking afterwards, so a
        response that would not fit in memory never gets there. Extracted from
        the request path purely so it can be tested without a socket.
        """
        body = reader.read(self.max_bytes + 1)
        if len(body) > self.max_bytes:
            raise TransportError(f"response exceeded {self.max_bytes} bytes")
        return body

    def _open(self, request: urllib.request.Request) -> tuple[int, bytes]:
        require_https(request.full_url, what="request URL")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                # Redirects are followed by urllib; check where we actually
                # ended up rather than only where we asked to go.
                require_https(response.geturl(), what="redirect target")
                return response.status, self.read_capped(response)
        except urllib.error.HTTPError as exc:
            # An error response still has a body worth parsing (RFC 6749 5.2),
            # so it is returned rather than raised.
            return exc.code, self.read_capped(exc)
        except urllib.error.URLError as exc:
            raise TransportError(f"request to {request.full_url} failed") from exc
        except TimeoutError as exc:
            raise TransportError(f"request to {request.full_url} timed out") from exc

    def _decode(self, body: bytes, url: str) -> Mapping[str, Any]:
        try:
            decoded = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TransportError(f"response from {url} was not valid JSON") from exc
        if not isinstance(decoded, dict):
            raise TransportError(f"response from {url} was not a JSON object")
        return decoded

    def get_json(self, url: str) -> Mapping[str, Any]:
        request = urllib.request.Request(  # noqa: S310
            url, method="GET", headers={"Accept": "application/json", "User-Agent": self.user_agent}
        )
        status, body = self._open(request)
        if status != 200:
            raise TransportError(f"GET {url} returned {status}")
        return self._decode(body, url)

    def post_form(
        self,
        url: str,
        *,
        data: Mapping[str, str],
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, Mapping[str, Any]]:
        encoded = urllib.parse.urlencode(data).encode()
        merged = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": self.user_agent,
            **(headers or {}),
        }
        request = urllib.request.Request(url, data=encoded, method="POST", headers=merged)  # noqa: S310
        status, body = self._open(request)
        return status, self._decode(body, url)
