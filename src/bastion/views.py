"""Login views.

The session handling in ``_establish_session`` is the part worth reading
closely. ``django.contrib.auth.login`` only calls ``cycle_key`` when no session
key is present, and ``cycle_key`` preserves session *data* regardless, so
relying on it alone leaves the pre-authentication state -- and possibly the
session identifier -- intact across the privilege transition. We flush first.
"""

from __future__ import annotations

import logging

from django.contrib.auth import login as auth_login
from django.contrib.auth.decorators import login_not_required
from django.contrib.auth.models import AbstractBaseUser
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from bastion.audit import emit
from bastion.audit.events import Event, Outcome, Severity
from bastion.conf import get_setting
from bastion.connections import Connection, get_connection
from bastion.exceptions import BastionError, ConfigurationError, TokenError
from bastion.flows import begin_login, complete_login, correlation_id

logger = logging.getLogger(__name__)

DEFAULT_SUCCESS_URL = "/"


def _resolve_connection(request: HttpRequest, name: str | None) -> Connection:
    if name:
        return get_connection(name)

    configured = get_setting("CONNECTIONS")
    if len(configured) == 1:
        return get_connection(next(iter(configured)))
    if not configured:
        raise ConfigurationError(
            'no connections are configured. Add one under BASTION["CONNECTIONS"].'
        )
    raise ConfigurationError(
        f"{len(configured)} connections are configured, so the URL must name one. "
        f"Use the connection-scoped routes, for example /login/{sorted(configured)[0]}/."
    )


def _failure(request: HttpRequest, reference: str, *, status: int = 400) -> HttpResponse:
    """One body and one status for every pre-authentication failure.

    Which check failed is in the log against the reference, not on the page.
    Varying the response by cause -- including by its shape or its timing --
    tells whoever is probing which of their guesses was closer.
    """
    response = render(
        request,
        "bastion/login_failed.html",
        {"reference": reference},
        status=status,
    )
    response["Referrer-Policy"] = "no-referrer"
    return response


@never_cache
@login_not_required
@require_http_methods(["GET", "POST"])
def begin(request: HttpRequest, connection: str | None = None) -> HttpResponse:
    """Start an authorization request and redirect to the provider."""
    resolved = _resolve_connection(request, connection)
    reference = correlation_id()
    try:
        url = begin_login(request, resolved, next_url=request.GET.get("next"))
    except BastionError:
        logger.exception("Could not start login on %s [ref %s]", resolved.identifier, reference)
        return _failure(request, reference, status=502)

    response = HttpResponseRedirect(url)
    response["Referrer-Policy"] = "no-referrer"
    return response


@never_cache
@login_not_required
@csrf_exempt
@require_http_methods(["GET", "POST"])
def callback(request: HttpRequest, connection: str | None = None) -> HttpResponse:
    """Complete the flow and establish a session.

    CSRF exempt because the request originates at the provider and carries no
    cookie we control. The compensating controls are the ones that matter
    anyway: the transaction is single-use and server-side, the nonce is
    checked against it, and the PKCE verifier never left this process.
    """
    resolved = _resolve_connection(request, connection)
    reference = correlation_id()

    try:
        result = complete_login(request, resolved)
    except BastionError as exc:
        # The specific reason goes to the log and the audit record, never to
        # the page. Audit writes are not conditional on success: a failed login
        # is the event most worth having.
        logger.warning(
            "Login failed on %s [ref %s]: %s",
            resolved.identifier,
            reference,
            type(exc).__name__,
        )
        emit(
            Event.ASSERTION_REJECTED if isinstance(exc, TokenError) else Event.LOGIN_FAILED,
            outcome=Outcome.FAILURE,
            request=request,
            severity=Severity.WARNING,
            connection=resolved.identifier,
            issuer=resolved.issuer,
            correlation_id=reference,
            context={"error": type(exc).__name__},
        )
        return _failure(request, reference)

    from django.contrib.auth import authenticate

    try:
        user = authenticate(request, sso_identity=result.identity, sso_connection=resolved)
    except BastionError as exc:
        # Provisioning and resolution happen inside authenticate(), and used to
        # be outside every handler here: a username collision surfaced as an
        # unhandled IntegrityError and a 500 on the callback. Anything the
        # backend refuses gets the same treatment as a refused assertion, which
        # is a rendered page and an audit record rather than a traceback.
        logger.warning(
            "Could not resolve %s to a user on %s [ref %s]: %s",
            result.identity.subject,
            resolved.identifier,
            reference,
            type(exc).__name__,
        )
        emit(
            Event.LOGIN_FAILED,
            outcome=Outcome.FAILURE,
            request=request,
            severity=Severity.WARNING,
            connection=resolved.identifier,
            issuer=result.identity.issuer,
            subject=result.identity.subject,
            correlation_id=reference,
            context={"error": type(exc).__name__},
        )
        return _failure(request, reference)

    if user is None:
        logger.warning(
            "Verified identity %s could not be resolved to a user [ref %s]",
            result.identity.subject,
            reference,
        )
        emit(
            Event.LOGIN_DENIED,
            outcome=Outcome.DENIED,
            request=request,
            severity=Severity.WARNING,
            connection=resolved.identifier,
            issuer=result.identity.issuer,
            subject=result.identity.subject,
            correlation_id=reference,
            context={"reason": "identity could not be resolved to a user"},
        )
        return _failure(request, reference, status=403)

    if resolved.require_group_match and not _has_any_privilege(user, resolved):
        # Post-authentication. Identity is proven, so there is no enumeration
        # risk and the page can say something useful.
        emit(
            Event.LOGIN_DENIED,
            outcome=Outcome.DENIED,
            actor=user,
            request=request,
            severity=Severity.NOTICE,
            connection=resolved.identifier,
            issuer=result.identity.issuer,
            subject=result.identity.subject,
            correlation_id=reference,
            context={"reason": "no configured group matched"},
        )
        return _denied(request, user, resolved, reference)

    _establish_session(request, user)

    emit(
        Event.LOGIN_SUCCEEDED,
        outcome=Outcome.SUCCESS,
        actor=user,
        request=request,
        connection=resolved.identifier,
        issuer=result.identity.issuer,
        subject=result.identity.subject,
        auth_protocol="oidc",
        auth_methods=list(result.identity.raw.get("amr", []) or []),
        correlation_id=reference,
        is_privileged=bool(getattr(user, "is_staff", False)),
        context={"mfa_satisfied": result.identity.mfa_satisfied},
    )

    destination = result.transaction.redirect_to or DEFAULT_SUCCESS_URL
    response = HttpResponseRedirect(destination)
    response["Referrer-Policy"] = "no-referrer"
    return response


def _has_any_privilege(user: AbstractBaseUser, connection: Connection) -> bool:
    return bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))


def _denied(
    request: HttpRequest, user: AbstractBaseUser, connection: Connection, reference: str
) -> HttpResponse:
    logger.info("Authenticated but unauthorised on %s [ref %s]", connection.identifier, reference)
    response = render(
        request,
        "bastion/access_denied.html",
        {
            "reference": reference,
            "identity": getattr(user, "email", None) or str(user),
            "connection": connection.identifier,
            "required_groups": connection.staff_groups + connection.superuser_groups,
        },
        status=403,
    )
    response["Referrer-Policy"] = "no-referrer"
    return response


def _establish_session(request: HttpRequest, user: AbstractBaseUser) -> None:
    """Discard everything from before the privilege transition, then log in.

    ``auth.login`` calls ``cycle_key`` only when ``SESSION_KEY`` is absent, so
    a re-login as the same user rotates nothing, and ``cycle_key`` keeps the
    session data either way. Flushing first is what actually guarantees the
    pre-authentication identifier and its contents do not survive.
    """
    request.session.flush()
    # Same stubs narrowing as the backend: auth.login is typed against the
    # configured user model, while the runtime contract is any AbstractBaseUser.
    auth_login(request, user, backend="bastion.backends.SSOBackend")  # type: ignore[arg-type]
