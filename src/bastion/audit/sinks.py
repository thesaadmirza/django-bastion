"""Where events go.

More than one sink is the point. The database gives queryability and the chain;
a log sink gives you somewhere the application cannot rewrite. Shipping to a
system under different administrative control is the strongest tamper control
available, and it is not this module -- it is the sink you point at your SIEM.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
from typing import Any, Protocol

logger = logging.getLogger("bastion.audit")


class AuditSink(Protocol):
    """Receives a recorded event.

    A sink must not raise. Losing an audit record is bad; failing a login
    because a downstream collector is unreachable is worse, and the recorder
    enforces that by catching everything. Sinks that need delivery guarantees
    should queue rather than block.
    """

    def record(self, payload: dict[str, Any]) -> None: ...


class DatabaseSink:
    """Writes to ``AuditEvent`` with a sequence number and chained hash."""

    def record(self, payload: dict[str, Any]) -> None:
        from bastion.audit.models import AuditChain, AuditEvent

        event = AuditEvent(
            event_type=str(payload["event_type"]),
            occurred_at=payload["occurred_at"],
            outcome=str(payload["outcome"]),
            actor_pseudonym=payload.get("actor_pseudonym", ""),
            actor_type=payload.get("actor_type", "user"),
            source_ip=payload.get("source_ip"),
            target_type=payload.get("target_type", ""),
            target_id=payload.get("target_id", ""),
            subject=payload.get("subject", ""),
            issuer=payload.get("issuer", ""),
            connection=payload.get("connection", ""),
            on_behalf_of=payload.get("on_behalf_of", ""),
            auth_protocol=payload.get("auth_protocol", ""),
            auth_methods=payload.get("auth_methods", []),
            session_id=payload.get("session_id", ""),
            correlation_id=payload.get("correlation_id", ""),
            changes=payload.get("changes", {}),
            reason=payload.get("reason", ""),
            is_privileged=payload.get("is_privileged", False),
            severity=str(payload.get("severity", "info")),
            context=payload.get("context", {}),
            chain=payload.get("chain", "default"),
        )
        AuditChain.append(event)


class LoggingSink:
    """Emits one JSON object per event to the ``bastion.audit`` logger.

    Useful on its own for shipping to a collector, and useful alongside the
    database sink as a second copy the application does not own.
    """

    def record(self, payload: dict[str, Any]) -> None:
        serialisable = dict(payload)
        occurred = serialisable.get("occurred_at")
        if isinstance(occurred, dt.datetime):
            serialisable["occurred_at"] = occurred.isoformat()
        serialisable["event_type"] = str(serialisable.get("event_type", ""))
        serialisable["outcome"] = str(serialisable.get("outcome", ""))
        serialisable["severity"] = str(serialisable.get("severity", ""))
        logger.info(json.dumps(serialisable, sort_keys=True, default=str))


class NullSink:
    """Discards everything. For tests that do not care."""

    def record(self, payload: dict[str, Any]) -> None:
        return
