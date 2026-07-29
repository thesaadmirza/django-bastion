"""Database helpers shared across the package.

Currently one thing: reissuing a transaction the server aborted to break a
deadlock. Both MySQL and PostgreSQL document that as the application's job, and
this package has two places that need it, so it lives here rather than in
whichever module happened to need it first.
"""

from __future__ import annotations

import functools
import logging
import time
from collections.abc import Callable
from typing import Any, TypeVar

from django.db import OperationalError, connection

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

#: How many times a transaction may be reissued. Small on purpose: contention
#: here is short-lived, and a long retry loop holding a request thread is its
#: own availability problem.
ATTEMPTS = 4

#: Base delay, doubled each attempt. Without a pause the retry re-enters the
#: contention it just lost.
BACKOFF = 0.02

#: Server codes meaning "you lost a lock race, try again", as opposed to
#: anything else OperationalError covers. Matching on these rather than
#: retrying every OperationalError keeps a broken connection or a full disk
#: from being retried three times before it is reported.
#:
#: MySQL 1213 deadlock, 1205 lock wait timeout. PostgreSQL 40001 serialization
#: failure, 40P01 deadlock detected.
MYSQL_LOCK_ERRORS = frozenset({1205, 1213})
POSTGRES_LOCK_STATES = frozenset({"40001", "40P01"})


def is_lock_contention(exc: OperationalError) -> bool:
    """Whether the server aborted this transaction over a lock, not a fault."""
    cause = exc.__cause__ or exc

    # psycopg exposes the state directly on older versions and under .diag on
    # newer ones, so both are worth asking.
    diag = getattr(cause, "diag", None)
    states = (getattr(cause, "sqlstate", None), getattr(diag, "sqlstate", None))
    if any(state in POSTGRES_LOCK_STATES for state in states):
        return True

    # Annotated because the empty-tuple default would otherwise narrow this to
    # tuple[()], and indexing it becomes an error rather than a runtime check.
    args: tuple[Any, ...] = getattr(cause, "args", ())
    return bool(args) and isinstance(args[0], int) and args[0] in MYSQL_LOCK_ERRORS


def retry_on_lock_contention(reset: Callable[..., None] | None = None) -> Callable[[F], F]:
    """Reissue the wrapped call when the server aborts it over a lock.

    Must wrap the *outermost* transaction, not one nested inside it. A deadlock
    marks the whole transaction for rollback, so retrying an inner block leaves
    the outer one already broken and the retry fails on the first query. When
    that is the situation the wrapper does not pretend otherwise: it detects the
    open transaction, logs once, and re-raises so the caller can decide.

    ``reset`` is called between attempts with the same arguments, for callers
    that have to put an object's state back before trying again.
    """

    def decorate(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if connection.in_atomic_block:
                # Retrying here cannot work. Say so once rather than burning
                # the attempts and reporting the last failure as if it were
                # transient.
                try:
                    return func(*args, **kwargs)
                except OperationalError as exc:
                    if is_lock_contention(exc):
                        logger.warning(
                            "%s lost a lock race inside an enclosing transaction, so it "
                            "cannot be retried here. The outermost transaction has to "
                            "restart instead.",
                            func.__qualname__,
                        )
                    raise

            for attempt in range(ATTEMPTS - 1):
                try:
                    return func(*args, **kwargs)
                except OperationalError as exc:
                    if not is_lock_contention(exc):
                        raise
                    if reset is not None:
                        reset(*args, **kwargs)
                    time.sleep(BACKOFF * (2**attempt))

            # Last attempt outside the loop, so there is no accumulator to
            # carry an exception past it and no unreachable branch to appease.
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate
