"""The emit API.

One function, called from everywhere. Two rules it enforces on every caller.

**A sink failure never breaks the request.** Losing a record is bad; failing a
login because a collector is unreachable is worse. Exceptions from sinks are
caught and logged, and the request continues.

**Audit writes are not conditional on the thing succeeding.** A failed login is
the event most worth recording, so the call sites emit on both paths.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from bastion.audit.events import Event, Outcome, Severity

logger = logging.getLogger(__name__)

_sinks: list[Any] | None = None


def get_sinks() -> list[Any]:
    """Resolve configured sinks once, then reuse them."""
    global _sinks
    if _sinks is None:
        from django.utils.module_loading import import_string

        from bastion.conf import get_setting

        paths = get_setting("AUDIT").get("SINKS", [])
        resolved = []
        for path in paths:
            try:
                resolved.append(import_string(path)())
            except Exception:
                logger.exception("Could not load audit sink %r", path)
        _sinks = resolved
    return _sinks


def reset_sinks() -> None:
    """Drop the cache. Called when settings change."""
    global _sinks
    _sinks = None


def emit(
    event: Event | str,
    *,
    outcome: Outcome | str = Outcome.SUCCESS,
    actor: Any = None,
    request: Any = None,
    severity: Severity | str = Severity.INFO,
    **fields: Any,
) -> None:
    """Record one event.

    ``actor`` is a user instance. It is converted to an opaque token here and
    never stored directly, so that erasure can later sever the link without
    touching the event or breaking the chain.
    """
    payload: dict[str, Any] = {
        "event_type": event,
        "outcome": outcome,
        "severity": severity,
        "occurred_at": fields.pop("occurred_at", None) or dt.datetime.now(tz=dt.UTC),
    }

    if actor is not None:
        payload["actor_pseudonym"] = _pseudonym_for(actor)

    if request is not None:
        payload.setdefault("source_ip", client_address(request))
        session_key = getattr(getattr(request, "session", None), "session_key", None)
        if session_key:
            # Hashed: the raw key is a live credential, and an audit table is
            # exactly the sort of place it should not be sitting in clear.
            import hashlib

            payload["session_id"] = hashlib.sha256(session_key.encode()).hexdigest()[:32]

    payload.update(fields)

    for sink in get_sinks():
        try:
            sink.record(dict(payload))
        except Exception:
            # Deliberately broad. A sink must never be able to fail a login.
            logger.exception("Audit sink %r failed", type(sink).__name__)


def _pseudonym_for(actor: Any) -> str:
    from bastion.audit.models import AuditActor

    try:
        return AuditActor.for_user(actor).pseudonym
    except Exception:
        logger.exception("Could not resolve an audit pseudonym")
        return ""


def client_address(request: Any) -> str | None:
    """The client address as the application sees it.

    Public because the break-glass throttle counts audit rows by ``source_ip``
    and so has to derive the value the same way this does. Two copies of this
    policy would have to agree by coincidence.

    Deliberately reads ``REMOTE_ADDR`` only. Parsing ``X-Forwarded-For`` here
    would mean trusting a header the client controls unless the deployment is
    known to strip it, and getting that wrong writes attacker-chosen values
    into the evidence. Deployments behind a proxy should set REMOTE_ADDR
    correctly at the edge.
    """
    return getattr(request, "META", {}).get("REMOTE_ADDR") or None
