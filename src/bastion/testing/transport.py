"""A transport that serves a FakeIdP without touching the network."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from bastion.protocols.oidc.discovery import discovery_url
from bastion.protocols.oidc.transport import TransportError
from bastion.testing.provider import FakeIdP


@dataclass
class FakeTransport:
    """Routes discovery and JWKS to the in-memory provider, and lets a test
    script the token endpoint."""

    idp: FakeIdP

    #: Queued ``(status, body)`` pairs for successive token endpoint calls.
    token_responses: list[tuple[int, Mapping[str, Any]]] = field(default_factory=list)

    #: Every ``(url, data, headers)`` the client posted, for assertions.
    posts: list[tuple[str, Mapping[str, str], Mapping[str, str]]] = field(default_factory=list)

    gets: list[str] = field(default_factory=list)
    fail_with: Exception | None = None

    #: Override the discovery document wholesale.
    discovery_override: Mapping[str, Any] | None = None

    def get_json(self, url: str) -> Mapping[str, Any]:
        self.gets.append(url)
        if self.fail_with is not None:
            raise self.fail_with
        if url == discovery_url(self.idp.issuer):
            if self.discovery_override is not None:
                return self.discovery_override
            return self.idp.discovery_document()
        if url == self.idp.discovery_document()["jwks_uri"]:
            return self.idp.jwks()
        raise TransportError(f"nothing is served at {url}")

    def post_form(
        self,
        url: str,
        *,
        data: Mapping[str, str],
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, Mapping[str, Any]]:
        self.posts.append((url, dict(data), dict(headers or {})))
        if self.fail_with is not None:
            raise self.fail_with
        if self.token_responses:
            return self.token_responses.pop(0)
        return 200, {
            "id_token": self.idp.id_token(),
            "access_token": self.idp.access_token(),
            "token_type": "Bearer",
            "expires_in": 3600,
        }
