"""Retrying an append that lost a lock race.

The trigger is backend-specific -- only MySQL's InnoDB reliably deadlocks on
the chain head -- but the decision of what to retry and how often is not, so it
is tested here with synthetic errors and runs on every backend.

That separation matters. tests/test_audit_concurrency.py proves real contention
is survived on a real server; this file proves the policy is right, including
the cases a passing concurrency run never reaches: exhaustion, and refusing to
retry a fault that is not contention at all.
"""

from __future__ import annotations

import pytest
from django.db import OperationalError

from bastion.audit import models
from bastion.audit.events import Event
from bastion.audit.models import AuditChain, AuditEvent, _is_lock_contention


class MySQLError(Exception):
    """Stands in for the driver exception Django wraps, which carries the
    server's numeric code as its first argument."""

    def __init__(self, code: int, message: str = "") -> None:
        super().__init__(code, message)


class PostgresError(Exception):
    """psycopg exposes the SQLSTATE rather than a numeric code."""

    def __init__(self, sqlstate: str) -> None:
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


def wrapped(cause: Exception) -> OperationalError:
    """Django re-raises driver errors with the original attached."""
    error = OperationalError(str(cause))
    error.__cause__ = cause
    return error


class TestContentionDetection:
    @pytest.mark.parametrize("code", [1213, 1205], ids=["deadlock", "lock-wait-timeout"])
    def test_mysql_lock_errors_are_contention(self, code: int) -> None:
        assert _is_lock_contention(wrapped(MySQLError(code, "try restarting")))

    @pytest.mark.parametrize(
        "state", ["40001", "40P01"], ids=["serialization-failure", "deadlock-detected"]
    )
    def test_postgres_lock_states_are_contention(self, state: str) -> None:
        assert _is_lock_contention(wrapped(PostgresError(state)))

    def test_an_unrelated_mysql_error_is_not_contention(self) -> None:
        """1114 is "table is full". Retrying it three times delays the report
        of a disk problem and fixes nothing."""
        assert not _is_lock_contention(wrapped(MySQLError(1114, "table is full")))

    def test_an_unrelated_sqlstate_is_not_contention(self) -> None:
        assert not _is_lock_contention(wrapped(PostgresError("53100")))

    def test_an_error_with_no_cause_is_not_contention(self) -> None:
        assert not _is_lock_contention(OperationalError("connection already closed"))

    def test_a_sqlstate_carried_on_diag_is_recognised(self) -> None:
        """Some psycopg versions only expose it under .diag."""

        class Diag:
            sqlstate = "40P01"

        cause = Exception("deadlock detected")
        cause.diag = Diag()  # type: ignore[attr-defined]
        assert _is_lock_contention(wrapped(cause))


@pytest.mark.django_db
class TestRetryPolicy:
    @pytest.fixture(autouse=True)
    def _no_waiting(self, monkeypatch) -> None:
        monkeypatch.setattr(models.time, "sleep", lambda _: None)

    def event(self) -> AuditEvent:
        import datetime as dt

        return AuditEvent(
            event_type=Event.LOGIN_SUCCEEDED,
            occurred_at=dt.datetime.now(tz=dt.UTC),
            outcome="success",
        )

    def test_an_append_that_deadlocks_once_still_lands(self, monkeypatch) -> None:
        calls: list[int] = []
        real = AuditChain._append_once.__func__  # type: ignore[attr-defined]

        def flaky(cls, event):
            calls.append(1)
            if len(calls) == 1:
                raise wrapped(MySQLError(1213, "Deadlock found"))
            return real(cls, event)

        monkeypatch.setattr(AuditChain, "_append_once", classmethod(flaky))
        AuditChain.append(self.event())

        assert len(calls) == 2
        assert AuditEvent.objects.count() == 1
        assert AuditEvent.objects.get().chain_seq == 1

    def test_the_retry_does_not_turn_into_an_update(self, monkeypatch) -> None:
        """The failed save leaves a primary key on the instance. Reusing it
        would make the retry update a row the rollback removed."""
        seen: list[object] = []
        real = AuditChain._append_once.__func__  # type: ignore[attr-defined]

        def flaky(cls, event):
            seen.append(event.pk)
            if len(seen) == 1:
                event.pk = 4242
                event._state.adding = False
                raise wrapped(MySQLError(1213, "Deadlock found"))
            return real(cls, event)

        monkeypatch.setattr(AuditChain, "_append_once", classmethod(flaky))
        AuditChain.append(self.event())

        assert seen == [None, None], "the retry inherited a stale primary key"
        assert AuditEvent.objects.count() == 1

    def test_persistent_contention_eventually_raises(self, monkeypatch) -> None:
        calls: list[int] = []

        def always_deadlock(cls, event):
            calls.append(1)
            raise wrapped(MySQLError(1213, "Deadlock found"))

        monkeypatch.setattr(AuditChain, "_append_once", classmethod(always_deadlock))
        with pytest.raises(OperationalError):
            AuditChain.append(self.event())

        assert len(calls) == models._APPEND_ATTEMPTS

    def test_a_non_contention_error_is_not_retried(self, monkeypatch) -> None:
        """Retrying a full disk delays the report and fixes nothing."""
        calls: list[int] = []

        def disk_full(cls, event):
            calls.append(1)
            raise wrapped(MySQLError(1114, "table is full"))

        monkeypatch.setattr(AuditChain, "_append_once", classmethod(disk_full))
        with pytest.raises(OperationalError):
            AuditChain.append(self.event())

        assert len(calls) == 1

    def test_the_backoff_grows(self, monkeypatch) -> None:
        """A retry with no pause re-enters the contention it just lost."""
        waits: list[float] = []
        monkeypatch.setattr(models.time, "sleep", waits.append)

        def always_deadlock(cls, event):
            raise wrapped(MySQLError(1213, "Deadlock found"))

        monkeypatch.setattr(AuditChain, "_append_once", classmethod(always_deadlock))
        with pytest.raises(OperationalError):
            AuditChain.append(self.event())

        assert waits == sorted(waits) and len(set(waits)) == len(waits)
