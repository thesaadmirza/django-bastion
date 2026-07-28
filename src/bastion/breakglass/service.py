"""Break-glass authentication and alerting."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from django.utils.module_loading import import_string

from bastion.audit import emit
from bastion.audit.events import Event, Outcome, Severity
from bastion.breakglass.models import BreakGlassAccount
from bastion.conf import get_setting

logger = logging.getLogger(__name__)


class BreakGlassDenied(Exception):
    """Emergency access was refused.

    Carries a machine-readable reason for the audit record. The reason is never
    shown to the person: at this point we do not know who they are, and telling
    an attacker which of the three gates they failed is free information.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def is_break_glass(user: Any) -> bool:
    """Whether this account is exempt from provider-driven lifecycle changes.

    Directory sync must skip these. An emergency account that the nightly
    reconciliation deactivates because it does not exist upstream is an
    emergency account that will not work during the emergency.
    """
    return BreakGlassAccount.objects.active().filter(user=user).exists()


def _config() -> dict[str, Any]:
    config: dict[str, Any] = get_setting("BREAK_GLASS")
    return config


def _network_allows(client_ip: str | None) -> bool:
    networks = _config().get("ALLOWED_NETWORKS", [])
    if not networks:
        # Empty means unrestricted, and that is a deliberate configuration the
        # startup check warns about rather than a default we silently apply.
        return True
    if not client_ip:
        return False
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(net, strict=False) for net in networks)


def authenticate_break_glass(*, username: str, password: str, request: Any = None) -> Any:
    """Authenticate against the local password, for flagged accounts only.

    Deliberately not a Django auth backend. A backend would be reachable from
    every ``authenticate()`` call in the project, which is exactly the silent
    password fallback the package exists to remove. This is callable only from
    the break-glass view.

    Every outcome is audited at critical severity and every outcome fires the
    alert sinks, including failures. A wrong password on an emergency account
    is more interesting than a successful login on a normal one.
    """
    config = _config()
    if not config.get("ENABLED"):
        raise BreakGlassDenied("disabled")

    client_ip = getattr(request, "META", {}).get("REMOTE_ADDR") if request else None
    if not _network_allows(client_ip):
        _record(None, Outcome.DENIED, "network", request)
        raise BreakGlassDenied("network")

    user_model = get_user_model()
    try:
        user = user_model._default_manager.get(**{user_model.USERNAME_FIELD: username})
    except user_model.DoesNotExist:
        # Hash anyway. Skipping the work here is a timing oracle that says
        # whether the account exists, and this endpoint is one an attacker
        # would very much like to enumerate.
        check_password(password, _dummy_hash())
        _record(None, Outcome.FAILURE, "unknown-account", request)
        raise BreakGlassDenied("credentials") from None

    account = BreakGlassAccount.objects.active().filter(user=user).first()
    if account is None:
        check_password(password, _dummy_hash())
        _record(user, Outcome.DENIED, "not-a-break-glass-account", request)
        raise BreakGlassDenied("credentials")

    if not user.is_active:
        check_password(password, _dummy_hash())
        _record(user, Outcome.DENIED, "inactive", request)
        raise BreakGlassDenied("credentials")

    if not user.check_password(password):
        _record(user, Outcome.FAILURE, "bad-password", request)
        raise BreakGlassDenied("credentials")

    account.last_used_at = timezone.now()
    account.save(update_fields=["last_used_at"])
    _record(user, Outcome.SUCCESS, "used", request)
    return user


def _dummy_hash() -> str:
    from django.contrib.auth.hashers import make_password

    return make_password("timing-equalisation")


def _record(user: Any, outcome: Outcome, reason: str, request: Any) -> None:
    emit(
        Event.PROTOCOL_FALLBACK,
        outcome=outcome,
        actor=user,
        request=request,
        severity=Severity.CRITICAL,
        auth_protocol="break_glass",
        is_privileged=True,
        reason=reason,
        context={"outcome": str(outcome)},
    )
    notify(
        subject="Break-glass access attempt",
        detail=f"outcome={outcome} reason={reason} user={getattr(user, 'pk', None)}",
    )


def notify(*, subject: str, detail: str) -> None:
    """Fire the configured alert sinks, synchronously.

    Synchronous on purpose. The queue, the worker and the broker are all things
    that may be down during the incident that triggered this, and an alert that
    arrives after the outage is over is not an alert. The cost is latency on a
    path that is used a handful of times a year.

    A sink that raises is logged and skipped, because a broken pager must not
    prevent the emergency login it was meant to announce.
    """
    for path in _config().get("ALERT_SINKS", []):
        try:
            import_string(path)(subject=subject, detail=detail)
        except Exception:
            logger.exception("Break-glass alert sink %r failed", path)


def log_only_sink(*, subject: str, detail: str) -> None:
    """A sink of last resort.

    Better than nothing and worse than everything else. If this is the only
    thing configured, the alert reaches whatever consumes your logs, which
    during an identity outage may be nobody.
    """
    logging.getLogger("bastion.breakglass").critical("%s: %s", subject, detail)
