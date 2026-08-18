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
from django.contrib.auth import logout as auth_logout
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
from bastion.flows import (
    LoginResult,
    begin_login,
    begin_logout,
    complete_login,
    correlation_id,
)
from bastion.pages import base_template

logger = logging.getLogger(__name__)

# DEFAULT_SUCCESS_URL used to live here and was read *instead* of
# BASTION["SUCCESS_URL"], which is what made that setting a documented no-op.
# It is gone rather than kept alongside: conf.DEFAULTS already holds "/" as the
# default, and a second copy is how the two drift apart again.

#: Which connection signed this session in. Written on every SSO login, because
#: logout has to reach the same provider and the URL cannot be trusted to say
#: which one that was.
SESSION_CONNECTION_KEY = "_bastion_connection"

#: Whether the assertion that established this session showed a second factor.
#: Recorded on every login so the admin gate can enforce ``ADMIN["require_mfa"]``
#: on every request rather than only at the moment of sign-in, which is what
#: makes turning the setting on affect sessions that already exist.
SESSION_MFA_KEY = "_bastion_mfa_satisfied"

#: The compact ID token, present only for connections with ``store_id_token``.
#: Underscore-prefixed to match Django's own convention for session keys that
#: are not application data.
# The suppression below is for bandit, which flags any name ending in
# _TOKEN_KEY as a hardcoded credential. This is the session dictionary key, not
# the token.
SESSION_ID_TOKEN_KEY = "_bastion_id_token"  # noqa: S105


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
        {"reference": reference, "base_template": base_template()},
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

    if resolved.require_privileged_user and not _has_any_privilege(user):
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
            context={"reason": "authenticated but neither staff nor superuser"},
        )
        return _denied(request, user, resolved, reference)

    _establish_session(request, user, resolved, result)

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

    # The transaction's destination came from ``next`` and was already put
    # through safe_redirect_url in begin_login, so it is host-checked. The
    # setting is not, and deliberately: it is deployer configuration rather than
    # request input, and validating it against the request host would break the
    # legitimate case of landing people on a separate front end after login.
    destination = result.transaction.redirect_to or get_setting("SUCCESS_URL")
    response = HttpResponseRedirect(destination)
    response["Referrer-Policy"] = "no-referrer"
    return response


@never_cache
@login_not_required
@require_http_methods(["POST"])
def logout(request: HttpRequest) -> HttpResponse:
    """End the local session, then end the provider's.

    **POST only, and that is not negotiable.** Django made its own logout
    POST-only in 4.1 for a reason that applies here twice over: a ``GET`` that
    signs people out is triggerable from any image tag on any page, and on this
    route it would also bounce the browser at the provider's logout endpoint.

    The order is the property worth reading. The local session is destroyed
    first and unconditionally, so a provider that is unreachable, or one with
    no ``end_session_endpoint`` at all, still leaves the person signed out
    here. Reversing it would make the local sign-out depend on the availability
    of the very thing you may be signing out because of.
    """
    reference = correlation_id()
    user = request.user if request.user.is_authenticated else None

    # Read before the flush. auth.logout() empties the session, and these are
    # the two things the provider request needs.
    name = request.session.get(SESSION_CONNECTION_KEY)
    id_token = request.session.get(SESSION_ID_TOKEN_KEY)

    auth_logout(request)

    destination: str | None = None
    if name:
        try:
            destination = begin_logout(request, get_connection(name), id_token=id_token)
        except ConfigurationError:
            # The connection was renamed or removed while this session was
            # alive. The local sign-out has already happened, which is the part
            # that matters.
            logger.warning(
                "Session named connection %r, which is no longer configured [ref %s]",
                name,
                reference,
            )

    # Emitted after the destination is known, not before. Recording
    # ``rp_initiated`` from whether the *session* named a connection would make
    # the field say "we knew where to look" while reading as "the provider
    # session ended", and the log would show a clean sign-out for a provider
    # that was never contacted.
    emit(
        Event.LOGOUT,
        outcome=Outcome.SUCCESS,
        actor=user,
        request=request,
        connection=name or "",
        correlation_id=reference,
        context={"rp_initiated": destination is not None},
    )

    if destination:
        response: HttpResponse = HttpResponseRedirect(destination)
    else:
        # Terminal page rather than a redirect, and it says what did not
        # happen. A provider with no end_session_endpoint means the provider
        # session is still live, and someone who thinks they signed out on a
        # shared machine should be told otherwise.
        response = render(
            request,
            "bastion/logged_out.html",
            {
                "reference": reference,
                "provider_session_ended": False,
                "base_template": base_template(),
            },
            status=200,
        )
    response["Referrer-Policy"] = "no-referrer"
    return response


def _has_any_privilege(user: AbstractBaseUser) -> bool:
    """What ``require_privileged_user`` actually tests.

    ``is_staff`` or ``is_superuser``, never the group claim. Usually the flags
    got there from a group, which is why the setting was once called
    ``require_group_match``; but a provider that publishes no groups at all --
    Google -- can still have privileged accounts, granted in the admin or by a
    management command, and the switch works there. That case is the one the
    old name hid, and it is the case where it matters most: without it every
    account in the tenant authenticates, holds a Django session, and is only
    stopped at the admin door.
    """
    return bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))


def _denied(
    request: HttpRequest, user: AbstractBaseUser, connection: Connection, reference: str
) -> HttpResponse:
    logger.info("Authenticated but unauthorised on %s [ref %s]", connection.identifier, reference)
    response = render(
        request,
        "bastion/access_denied.html",
        {
            "base_template": base_template(),
            "reference": reference,
            "identity": getattr(user, "email", None) or str(user),
            "connection": connection.identifier,
            "required_groups": connection.staff_groups + connection.superuser_groups,
        },
        status=403,
    )
    response["Referrer-Policy"] = "no-referrer"
    return response


def _establish_session(
    request: HttpRequest,
    user: AbstractBaseUser,
    connection: Connection,
    result: LoginResult,
) -> None:
    """Discard everything from before the privilege transition, then log in.

    ``auth.login`` calls ``cycle_key`` only when ``SESSION_KEY`` is absent, so
    a re-login as the same user rotates nothing, and ``cycle_key`` keeps the
    session data either way. Flushing first is what actually guarantees the
    pre-authentication identifier and its contents do not survive.

    The logout material is written *after* ``auth_login``, not before, because
    the flush would otherwise take it straight back out.
    """
    request.session.flush()
    # Same stubs narrowing as the backend: auth.login is typed against the
    # configured user model, while the runtime contract is any AbstractBaseUser.
    auth_login(request, user, backend="bastion.backends.SSOBackend")  # type: ignore[arg-type]

    request.session[SESSION_CONNECTION_KEY] = connection.identifier
    request.session[SESSION_MFA_KEY] = result.identity.mfa_satisfied
    if result.id_token:
        request.session[SESSION_ID_TOKEN_KEY] = result.id_token
