"""The back-channel logout endpoint.

The provider POSTs a signed logout token here when a session ends on its side,
server to server, with no browser involved. That shape decides most of what
follows: there is no session cookie to read, no CSRF token to check, and no
person to show an error to.

What replaces those is the token. It is signed by the same keys the ID tokens
are checked with, it names the issuer, it is bound to this client, and it may
be used once. Nothing here trusts anything else about the request -- not its
source address, not a header, not a shared secret in a query string.

Responses are deliberately thin. The specification asks for 200 on success and
400 on a bad token, and there is nothing useful to add: the sender is a machine
that will not read prose, and an attacker probing the endpoint should not learn
which of the checks refused them. The detail goes to the audit log.
"""

from __future__ import annotations

import logging

from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from bastion import sessions
from bastion.audit import emit
from bastion.audit.events import Event, Outcome, Severity
from bastion.connections import Connection, all_connections
from bastion.exceptions import BastionError
from bastion.models import SeenLogoutToken
from bastion.protocols.oidc.jose import verify_compact
from bastion.protocols.oidc.logout import LogoutRequest, validate_logout_token

logger = logging.getLogger(__name__)


class LogoutTokenRefused(BastionError):
    """A logout token was not acted on. Carries a reason for the audit record."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@csrf_exempt
@never_cache
@require_POST
def backchannel_logout(request: HttpRequest, connection: str | None = None) -> HttpResponse:
    """Receive a logout token and end what it names.

    CSRF exempt because the request comes from the provider's own servers and
    carries no cookie of ours. The compensating control is the whole of the
    token validation below, which is stronger than a CSRF token would be: a
    forged request has to be signed by the provider's key.
    """
    token = request.POST.get("logout_token", "")

    try:
        _apply(_resolve(connection, token), token)
    except LogoutTokenRefused as exc:
        logger.warning("Refused a logout token: %s", exc.reason)
        emit(
            Event.ASSERTION_REJECTED,
            outcome=Outcome.FAILURE,
            request=request,
            severity=Severity.WARNING,
            reason=exc.reason,
            context={"endpoint": "backchannel_logout"},
        )
        # The body shape is RFC 6749's, which the specification points at for
        # this endpoint. The description is the same for every cause.
        # No Cache-Control here: @never_cache sets one after this returns, and
        # it is stricter than the specification's no-store on its own. Setting
        # ours as well would be a line that looks load-bearing and is
        # overwritten before it reaches anybody.
        return JsonResponse(
            {"error": "invalid_request", "error_description": "logout token was not accepted"},
            status=400,
        )

    return HttpResponse(status=200)


def _resolve(name: str | None, token: str) -> Connection:
    """Find the connection this token belongs to.

    A named route resolves directly. An unnamed one reads the issuer out of the
    token and matches on that -- unverified at this point, which is safe
    because the only thing it selects is which public key gets to prove the
    token genuine. A forged issuer picks a connection whose keys will refuse
    the signature.
    """
    connections = all_connections()
    if not connections:
        raise LogoutTokenRefused("no connections are configured")

    if name is not None:
        found = connections.get(name)
        if found is None:
            raise LogoutTokenRefused("unknown connection")
        return found

    claimed = _unverified_issuer(token)
    for candidate in connections.values():
        if candidate.issuer == claimed:
            return candidate
    raise LogoutTokenRefused("no connection matches the token issuer")


def _unverified_issuer(token: str) -> str:
    """Read ``iss`` from an unverified payload, for routing only.

    Everything this returns is attacker-controlled. It never becomes the issuer
    a token is validated against; that comes from the connection's own
    configuration, and the two are compared in ``validate_logout_token``.
    """
    import base64
    import json

    parts = token.split(".")
    if len(parts) != 3:
        raise LogoutTokenRefused("token is not a compact JWS")
    try:
        segment = parts[1]
        payload = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except Exception as exc:
        raise LogoutTokenRefused("token payload is not readable") from exc
    if not isinstance(payload, dict):
        raise LogoutTokenRefused("token payload is not an object")
    issuer = payload.get("iss")
    if not isinstance(issuer, str) or not issuer:
        raise LogoutTokenRefused("token names no issuer")
    return issuer


def _apply(connection: Connection, token: str) -> LogoutRequest:
    """Validate, claim single use, then end what the token names."""
    if not token:
        raise LogoutTokenRefused("no logout_token in the request")

    try:
        verified = verify_compact(token, key_resolver=connection.key_store().resolve)
    except BastionError as exc:
        raise LogoutTokenRefused(f"signature: {type(exc).__name__}") from exc

    try:
        parsed = validate_logout_token(
            verified,
            issuer=connection.issuer,
            client_id=connection.client_id,
            now=timezone.now(),
        )
    except BastionError as exc:
        raise LogoutTokenRefused(f"claims: {type(exc).__name__}") from exc

    _claim_single_use(parsed)

    if parsed.sid is not None:
        ended = sessions.revoke_by_sid(issuer=parsed.issuer, sid=parsed.sid)
    elif parsed.subject is not None:
        # A subject and no sid: end everything this identity holds.
        ended = sessions.revoke_by_subject(issuer=parsed.issuer, subject=parsed.subject)
    else:  # pragma: no cover - validate_logout_token refuses this combination
        # Not an assert. Under `python -O` an assert is not a check at all, and
        # this is the auth path; the invariant is restated as a refusal so it
        # survives the flag a performance-tuned deployment is most likely to set.
        raise LogoutTokenRefused("token names neither a session nor a subject")

    emit(
        Event.SESSION_REVOKED,
        outcome=Outcome.SUCCESS,
        severity=Severity.INFO,
        connection=connection.identifier,
        issuer=parsed.issuer,
        subject=parsed.subject or "",
        reason="backchannel_logout",
        context={
            "sessions_ended": ended,
            "scope": "subject" if parsed.ends_every_session else "sid",
        },
    )
    return parsed


def _claim_single_use(parsed: LogoutRequest) -> None:
    """Record the ``jti``, and refuse the token if it was already recorded.

    The insert is the claim. Checking for the row and then writing it would let
    two copies arriving together both pass the check before either wrote, which
    is exactly the shape a replay takes. Whoever inserts second gets the
    IntegrityError, and that is the answer.

    Wrapped in an atomic block because a failed insert marks the surrounding
    transaction broken on PostgreSQL, and the caller has audit writes to do
    afterwards.
    """
    SeenLogoutToken.purge_expired()
    try:
        with transaction.atomic():
            SeenLogoutToken.objects.create(
                issuer=parsed.issuer,
                jti=parsed.jti,
                expires_at=parsed.expires_at,
            )
    except IntegrityError as exc:
        raise LogoutTokenRefused("token has already been used") from exc
