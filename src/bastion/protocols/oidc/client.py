"""The token endpoint exchange.

Small enough to own outright, and the parts that matter are the parts a
general-purpose client would not do for us: never putting a response body in an
exception, never logging one, and treating an unparseable error response as a
failure rather than a surprise.

A token endpoint response contains an ID token, an access token, and often a
refresh token. Every one of those is a credential. The single most likely way
they end up somewhere they should not be is an exception message reaching a log
aggregator, so nothing here interpolates a body into anything.
"""

from __future__ import annotations

import base64
import logging
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from bastion.exceptions import TokenError
from bastion.protocols.oidc.transaction import Transaction
from bastion.protocols.oidc.transport import Transport, UrllibTransport, require_https

logger = logging.getLogger(__name__)


class ClientAuthMethod(StrEnum):
    """How the client authenticates to the token endpoint.

    ``client_secret_basic`` is the OAuth 2.0 default and what a provider
    assumes when registration says nothing. ``client_secret_post`` is widely
    supported and slightly easier to debug. Both put the secret on the wire
    under TLS; neither is meaningfully stronger.
    """

    BASIC = "client_secret_basic"
    POST = "client_secret_post"
    NONE = "none"


class TokenEndpointError(TokenError):
    """The provider refused the exchange.

    Carries the RFC 6749 error code, which is a fixed vocabulary and safe to
    record. Never the description, which is provider-controlled free text.
    """

    def __init__(self, code: str, *, status: int) -> None:
        super().__init__(f"token endpoint returned {code!r} (HTTP {status})")
        self.code = code
        self.status = status


@dataclass(frozen=True, slots=True)
class TokenResponse:
    """Contains credentials. Do not log, do not put in an exception, do not
    place in a template context."""

    id_token: str
    access_token: str | None = None
    token_type: str | None = None
    expires_in: int | None = None
    refresh_token: str | None = None
    scope: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __repr__(self) -> str:
        # The default dataclass repr would print every token. This class ends
        # up in tracebacks and debug pages; it must be inert there.
        return "<TokenResponse id_token=[redacted] access_token=[redacted]>"


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    """RFC 6749 2.3.1: form-urlencode both halves before base64.

    Skipping the encoding step works right up until a secret contains a
    character that needs it, at which point authentication fails against some
    providers and not others.
    """
    user = urllib.parse.quote(client_id, safe="")
    password = urllib.parse.quote(client_secret, safe="")
    raw = f"{user}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def exchange_code(
    code: str,
    *,
    transaction: Transaction,
    token_endpoint: str,
    client_id: str,
    redirect_uri: str,
    client_secret: str | None = None,
    auth_method: ClientAuthMethod = ClientAuthMethod.BASIC,
    transport: Transport | None = None,
) -> TokenResponse:
    """Exchange an authorization code for tokens.

    The ``code_verifier`` comes from the transaction record rather than from a
    caller-supplied argument, so there is no call site where it can be omitted
    or substituted.
    """
    require_https(token_endpoint, what="token_endpoint")
    transport = transport or UrllibTransport()

    data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": transaction.code_verifier,
    }
    headers: dict[str, str] = {}

    if auth_method is ClientAuthMethod.BASIC:
        if not client_secret:
            raise TokenError("client_secret_basic requires a client secret")
        headers["Authorization"] = _basic_auth_header(client_id, client_secret)
    elif auth_method is ClientAuthMethod.POST:
        if not client_secret:
            raise TokenError("client_secret_post requires a client secret")
        data["client_secret"] = client_secret

    status, body = transport.post_form(token_endpoint, data=data, headers=headers)

    if status != 200:
        raise TokenEndpointError(_error_code(body), status=status)

    id_token = body.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        # A 200 with no ID token is not an OIDC response. Treating it as a
        # partial success is how an OAuth-only flow gets mistaken for
        # authentication.
        raise TokenError("token response contained no id_token")

    expires_in = body.get("expires_in")
    return TokenResponse(
        id_token=id_token,
        access_token=_optional_str(body.get("access_token")),
        token_type=_optional_str(body.get("token_type")),
        expires_in=expires_in if isinstance(expires_in, int) else None,
        refresh_token=_optional_str(body.get("refresh_token")),
        scope=_optional_str(body.get("scope")),
        raw=dict(body),
    )


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _error_code(body: Mapping[str, Any]) -> str:
    """Extract the RFC 6749 5.2 error code, ignoring the free-text fields.

    ``error_description`` and ``error_uri`` are provider-controlled and end up
    rendered or logged. The code is a closed vocabulary, so only the code
    survives.
    """
    known = {
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
    }
    code = body.get("error")
    if isinstance(code, str) and code in known:
        return code
    if isinstance(code, str) and code:
        logger.warning("Token endpoint returned an unrecognised error code")
        return "unrecognised_error"
    return "no_error_code"
