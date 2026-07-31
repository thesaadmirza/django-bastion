"""The login flow, as functions.

Kept out of the views so that the sequence can be tested without HTTP, and so
that a project wiring its own views does not have to reimplement the order.
The order is the security property: consume the transaction before spending the
code, check the issuer before trusting the response, validate the nonce against
the record rather than against anything in the request.
"""

from __future__ import annotations

import datetime as dt
import logging
import secrets
from dataclasses import dataclass

from django.http import HttpRequest
from django.urls import reverse

from bastion.claims import IdentityClaims
from bastion.connections import Connection
from bastion.exceptions import BastionError, TokenError, TransactionNotFound
from bastion.protocols.oidc.client import exchange_code
from bastion.protocols.oidc.jose import verify_compact
from bastion.protocols.oidc.quirks import to_identity_claims
from bastion.protocols.oidc.transaction import (
    Transaction,
    build_authorization_url,
    build_end_session_url,
    start_transaction,
    verify_callback_issuer,
)
from bastion.protocols.oidc.validation import validate_id_token
from bastion.redirects import safe_redirect_url

logger = logging.getLogger(__name__)


class ProviderReturnedError(BastionError):
    """The provider sent us back an ``error`` parameter instead of a code."""


@dataclass(frozen=True, slots=True)
class LoginResult:
    identity: IdentityClaims
    transaction: Transaction

    #: The compact ID token, kept only so a connection with ``store_id_token``
    #: can put it in the session for ``id_token_hint`` at logout. Treated the
    #: same as ``TokenResponse``: never logged, never rendered, never in an
    #: exception.
    id_token: str = ""

    def __repr__(self) -> str:
        return f"<LoginResult subject={self.identity.subject!r} id_token=[redacted]>"


def callback_uri(request: HttpRequest) -> str:
    """The absolute redirect URI, which must match what was registered.

    Built from the request rather than configured, so that a deployment behind
    a proxy gets this right only if ``SECURE_PROXY_SSL_HEADER`` is right. That
    coupling is deliberate: a mismatch here is a login failure, which is
    noticed, rather than a silent downgrade to http, which is not.
    """
    return request.build_absolute_uri(reverse("bastion:callback"))


def begin_login(
    request: HttpRequest,
    connection: Connection,
    *,
    next_url: str | None = None,
    prompt: str | None = None,
    max_age: int | None = None,
) -> str:
    """Start a transaction and return the URL to send the browser to."""
    metadata = connection.metadata()

    destination = safe_redirect_url(next_url, request=request, fallback="")
    if next_url and not destination:
        logger.info("Discarded an unsafe next parameter on connection %s", connection.identifier)

    if not request.session.session_key:
        # Needed so the transaction can record a binding. Cheap, and the
        # session is discarded on success anyway.
        request.session.save()

    transaction = start_transaction(
        connection=connection.identifier,
        store=connection.transactions,
        redirect_to=destination or None,
        session_key=request.session.session_key,
    )

    return build_authorization_url(
        transaction,
        authorization_endpoint=metadata.authorization_endpoint,
        client_id=connection.client_id,
        redirect_uri=callback_uri(request),
        scopes=connection.scopes,
        prompt=prompt,
        max_age=max_age,
    )


def complete_login(request: HttpRequest, connection: Connection) -> LoginResult:
    """Turn a callback into a verified identity.

    Raises on every failure. Callers render one page for all of them; the
    distinction exists for the log, not for the person.
    """
    error = request.GET.get("error")
    if error:
        # Provider-controlled. The code is closed vocabulary, the description
        # is not, so only the code is recorded.
        raise ProviderReturnedError(f"provider returned error={error!r}")

    state = request.GET.get("state")
    code = request.GET.get("code")
    if not state or not code:
        raise TransactionNotFound("callback is missing state or code")

    transaction = connection.transactions.consume(state)

    # Mix-up defence. Checked before the code is spent, so a code intended for
    # another provider is never sent to this one's token endpoint.
    verify_callback_issuer(request.GET.get("iss"), expected=connection.issuer)

    if transaction.connection != connection.identifier:
        raise TransactionNotFound("transaction belongs to a different connection")

    metadata = connection.metadata()
    tokens = exchange_code(
        code,
        transaction=transaction,
        token_endpoint=metadata.token_endpoint,
        client_id=connection.client_id,
        client_secret=connection.client_secret,
        redirect_uri=callback_uri(request),
        auth_method=connection.auth_method,
        transport=connection.transport,
    )

    verified = verify_compact(tokens.id_token, key_resolver=connection.key_store().resolve)
    claims = validate_id_token(
        verified,
        issuer=connection.issuer,
        client_id=connection.client_id,
        now=dt.datetime.now(tz=dt.UTC),
        nonce=transaction.nonce,
        access_token=tokens.access_token,
        policy=connection.validation,
    )

    identity = to_identity_claims(claims, quirks=connection.quirks, issuer=connection.issuer)

    if connection.require_mfa and not identity.mfa_satisfied:
        raise TokenError("connection requires MFA and the assertion did not carry it")

    return LoginResult(
        identity=identity,
        transaction=transaction,
        # Carried only when the connection asked for it. A token nobody
        # configured a use for should not survive this function.
        id_token=tokens.id_token if connection.store_id_token else "",
    )


def begin_logout(
    request: HttpRequest,
    connection: Connection,
    *,
    id_token: str | None = None,
) -> str | None:
    """Return the provider URL that ends the provider's own session.

    ``None`` means the provider publishes no ``end_session_endpoint``, in which
    case clearing the local session is the whole of what is possible and the
    caller should say so rather than pretend. Google is the provider this
    happens with.

    Reached only after the local session has been dealt with, so a provider
    that is down cannot leave someone signed in locally.
    """
    try:
        metadata = connection.metadata()
    except BastionError:
        # A discovery failure must not block the local sign-out that already
        # happened. Logging out of the provider is the part that fails.
        logger.warning(
            "Could not reach %s for its end_session_endpoint; local sign-out only.",
            connection.identifier,
        )
        return None

    if not metadata.supports_rp_initiated_logout:
        return None

    return build_end_session_url(
        str(metadata.end_session_endpoint),
        client_id=connection.client_id,
        id_token_hint=id_token or None,
        post_logout_redirect_uri=connection.post_logout_redirect_uri,
    )


def correlation_id() -> str:
    """A short reference shown on the failure page and written to the log.

    Short enough to read aloud to a service desk. Random rather than derived
    from anything, so it discloses nothing by itself.
    """
    return secrets.token_hex(2).upper() + "-" + secrets.token_hex(2).upper()
