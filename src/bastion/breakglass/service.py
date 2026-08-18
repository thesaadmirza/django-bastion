"""Break-glass authentication and alerting."""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from django.utils.module_loading import import_string

from bastion.audit import emit
from bastion.audit.events import Event, Outcome, Severity
from bastion.audit.recorder import client_address
from bastion.breakglass.models import BreakGlassAccount
from bastion.conf import get_setting

logger = logging.getLogger(__name__)

#: Reason recorded when an attempt is refused by the throttle. Named because it
#: is also the reason excluded when counting, and those two uses must not drift.
_THROTTLED = "throttled"

#: Reason recorded when an attempt is refused by the network allowlist. Named
#: for the same reason as the one above: it is written by the recorder and read
#: back by the deduplication that keeps the refusal to one record per window.
_NETWORK = "network"

#: Value written to the audit record's auth_protocol, and matched on when
#: counting. Same reason for naming it.
_PROTOCOL = "break_glass"


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


def _window_start() -> dt.datetime:
    return timezone.now() - dt.timedelta(seconds=_config()["FAILURE_WINDOW_SECONDS"])


def _is_throttled(client_ip: str) -> bool:
    """Whether this address has already spent its allowance of failures.

    Counted from the audit log rather than from a cache. The cache is the
    conventional place for this and it is the wrong one here: Django's default
    ``locmem`` backend is per-process, so a deployment on four workers gets four
    independent counters and four times the limit, and every counter resets on
    restart. The audit log is already written on every attempt, is shared by
    every worker, and survives a restart.

    Refusals are excluded from the count. Counting them would let continued
    hammering hold the window open forever, which turns a throttle into an
    indefinite lockout of whoever shares that address.
    """
    from bastion.audit.models import AuditEvent

    limit: int = _config()["MAX_FAILURES_PER_IP"]
    if limit <= 0:
        return False

    seen = AuditEvent.objects.failures_from(
        client_ip,
        since=_window_start(),
        protocol=_PROTOCOL,
        limit=limit,
        ignoring=_THROTTLED,
    )
    return seen >= limit


def _already_refused(client_ip: str | None, reason: str) -> bool:
    """Whether this address has been refused for this reason inside the window.

    Used to record a refusal once rather than once per attempt. Recording each
    one is what makes a gate worse than no gate: every refusal would append a
    chained audit row, which takes ``SELECT FOR UPDATE`` on the chain head and
    serialises against every other audit write in the system, and would fire
    the alert sinks synchronously. A flood then costs more the longer it runs,
    and the growing rows are scanned by the next attempt.

    This guarded the throttle from the start and did not guard the network
    denial above it, which was the branch that actually mattered: the throttle
    only refuses an address that has already spent five credential failures,
    while the network gate refuses every request from every address outside the
    allowlist -- and the endpoint is ``login_not_required`` and deliberately
    outside django-axes, so anybody who finds the URL can produce those in a
    loop. One chained write and one synchronous alert per request is an
    amplifier, and a sink that reaches a paging API on a sixty-second timeout
    turns it into a way to hold workers open.

    Keyed per reason so that a network refusal and a throttle refusal do not
    suppress each other: they are different findings and an investigation wants
    both. ``None`` is a real bucket rather than a skip -- a request with no
    ``REMOTE_ADDR`` is refused by the network gate whenever an allowlist exists,
    and those requests are indistinguishable from each other anyway, so they
    share one record per window.
    """
    from bastion.audit.models import AuditEvent

    return AuditEvent.objects.filter(
        event_type=Event.PROTOCOL_FALLBACK,
        occurred_at__gte=_window_start(),
        auth_protocol=_PROTOCOL,
        # Django turns an ``=None`` lookup into IS NULL, which is what the
        # recorder writes for a request with no address.
        source_ip=client_ip,
        reason=reason,
    ).exists()


def _network_allows(client_ip: str | None) -> bool:
    """Whether the allowlist admits this address.

    Parses the address itself rather than trusting the caller to have done it.
    ``authenticate_break_glass`` resolves the address through
    ``client_address``, which now returns ``None`` for anything that is not one,
    so in that path the ``ValueError`` below is unreachable -- but this is the
    function that decides whether an unauthenticated caller is answered, and it
    is one refactor away from being handed a raw header value. Failing closed on
    a string it cannot parse costs a try block.
    """
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

    for net in networks:
        try:
            network = ipaddress.ip_network(str(net), strict=False)
        except ValueError:
            # ``bastion.E102`` refuses this at startup, so reaching it means the
            # check was silenced or the setting was changed underneath a running
            # process. Skipping the entry keeps an unauthenticated request from
            # raising out of the gate that is deciding whether to answer it; the
            # effect is that a malformed CIDR grants nothing, which is the
            # direction to fail in.
            logger.error(
                "Ignoring unusable entry %r in BREAK_GLASS ALLOWED_NETWORKS; "
                "it matches nothing. Fix it: bastion.E102 reports this at startup.",
                net,
            )
            continue
        if address in network:
            return True
    return False


def authenticate_break_glass(*, username: str, password: str, request: Any = None) -> Any:
    """Authenticate against the local password, for flagged accounts only.

    Deliberately not a Django auth backend. A backend would be reachable from
    every ``authenticate()`` call in the project, which is exactly the silent
    password fallback the package exists to remove. This is callable only from
    the break-glass view.

    Every outcome is audited at critical severity and every outcome fires the
    alert sinks, including failures. A wrong password on an emergency account
    is more interesting than a successful login on a normal one. The one
    exception is a repeat refusal from an address already refused this window,
    which is recorded once rather than once per attempt.
    """
    config = _config()
    if not config.get("ENABLED"):
        raise BreakGlassDenied("disabled")

    # The recorder's resolver, not a second copy. The throttle compares its
    # answer against source_ip values the recorder wrote, so two definitions of
    # "the client address" would have to agree by coincidence -- and they did
    # not: this used to yield "" where the recorder stores NULL, so a blank
    # REMOTE_ADDR silently matched nothing.
    client_ip = client_address(request) if request else None
    if not _network_allows(client_ip):
        # Deduplicated exactly as the throttle below is. Every refusal here
        # would otherwise cost a chained audit write and a synchronous alert,
        # on the one endpoint an unauthenticated caller can reach at will.
        if not _already_refused(client_ip, _NETWORK):
            _record(None, Outcome.DENIED, _NETWORK, request)
        raise BreakGlassDenied(_NETWORK)

    # Before the password work, so that a flood costs the attacker a query and
    # not a KDF round each time.
    #
    # Throttling is per source address and never per account. Locking the
    # account after N failures is what a normal login should do and exactly
    # what this one must not: anyone able to reach the form could then disable
    # the emergency route by failing against it, which is the outage this
    # feature exists to survive. An address can be abandoned; the fire escape
    # cannot.
    # No address means nothing to key on, so nothing to throttle. Refusing an
    # addressless request is the network allowlist's job, above.
    if client_ip and _is_throttled(client_ip):
        if not _already_refused(client_ip, _THROTTLED):
            _record(None, Outcome.DENIED, _THROTTLED, request)
        raise BreakGlassDenied(_THROTTLED)

    user_model = get_user_model()
    try:
        # Imported here rather than at module scope: bastion.backends imports
        # the models, and this module is loaded while the app registry is still
        # populating them.
        from bastion.backends import user_username_field

        user = user_model._default_manager.get(**{user_username_field(): username})
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
