"""Recording which Django session a login created, and ending it later.

Two operations, and the asymmetry between them is the point. Recording happens
on the login path where a mistake costs somebody their sign-in, so it never
raises. Revoking happens on a path that exists to take access away, so it
reports exactly how many sessions it ended and lets the caller audit the
number.

The session store is the authority. A ``FederatedSession`` row is only an
index: deleting the row revokes nothing, and the store has to be told
separately. Every function here does both, in that order, so a crash between
them leaves a dead index entry rather than a live session nobody can find.
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib.sessions.backends.base import SessionBase
from django.utils import timezone

from bastion.models import FederatedIdentity, FederatedSession

logger = logging.getLogger(__name__)


def _store() -> Any:
    """The configured session engine's store class.

    Resolved per call rather than at import, the same way Django's own session
    middleware does it, so ``override_settings(SESSION_ENGINE=...)`` is honoured
    and a project that swaps engines does not need a restart to be believed.
    """
    from importlib import import_module

    from django.conf import settings

    engine = import_module(settings.SESSION_ENGINE)
    return engine.SessionStore


def record(
    *,
    identity: FederatedIdentity,
    session_key: str,
    sid: str,
    connection: str,
) -> None:
    """Note that this Django session belongs to this provider session.

    Never raises. This runs immediately after a successful login, and a person
    who has just authenticated correctly should not be turned away because an
    index write failed -- the cost of losing the row is that back-channel
    logout cannot find that one session, which is a smaller harm than refusing
    the login outright. It is logged at error level because it is still wrong.

    ``update_or_create`` on ``session_key`` rather than ``create``: session
    keys are unique and reused only after a flush, but a store that hands back
    a key we already hold should overwrite the stale row rather than raise.
    """
    try:
        FederatedSession.objects.update_or_create(
            session_key=session_key,
            defaults={
                "identity": identity,
                "sid": sid or "",
                "connection": connection,
                "created_at": timezone.now(),
            },
        )
    except Exception:
        logger.exception(
            "Could not record the federated session for %s; back-channel "
            "logout will not be able to end this session by sid.",
            identity.subject,
        )


def _delete(rows: list[FederatedSession]) -> int:
    """Flush each session out of the store, then drop the index rows.

    The store first. A row deleted before its session is a session nobody can
    find any more, which is the one outcome worse than either half failing.

    A store that raises on one key must not strand the rest, so each is
    attempted on its own. The count returned is sessions actually ended, not
    rows matched, because that number is what goes into the audit record.
    """
    if not rows:
        return 0

    store = _store()
    ended = 0
    cleared: list[int] = []

    for row in rows:
        try:
            session: SessionBase = store(session_key=row.session_key)
            session.delete()
        except Exception:
            # Keep the index row: the session may still be live, and a row that
            # points at it is the only way anything will try again.
            logger.exception("Could not end session %s", row.session_key[:8])
            continue
        ended += 1
        cleared.append(row.pk)

    if cleared:
        FederatedSession.objects.filter(pk__in=cleared).delete()
    return ended


def revoke_by_sid(*, issuer: str, sid: str) -> int:
    """End the one session a provider session identifier names."""
    rows = list(
        FederatedSession.objects.filter(identity__issuer=issuer, sid=sid).select_related("identity")
    )
    return _delete(rows)


def revoke_by_subject(*, issuer: str, subject: str) -> int:
    """End every session this identity holds.

    What a logout token carrying ``sub`` and no ``sid`` is asking for. It is
    the broader reading on purpose: the provider is saying this person is
    signed out, not that one of their browsers is.
    """
    rows = list(
        FederatedSession.objects.filter(
            identity__issuer=issuer, identity__subject=subject
        ).select_related("identity")
    )
    return _delete(rows)


def forget(session_key: str) -> None:
    """Drop the index row for a session that ended by other means.

    Called on ordinary sign-out. Without it the table keeps a row per logout
    forever, and the next login for that person is measured against a growing
    list of sessions that stopped existing months ago.
    """
    FederatedSession.objects.filter(session_key=session_key).delete()
