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

from bastion import db
from bastion.audit.events import Event
from bastion.audit.models import AuditChain, AuditEvent
from bastion.db import is_lock_contention


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
        assert is_lock_contention(wrapped(MySQLError(code, "try restarting")))

    @pytest.mark.parametrize(
        "state", ["40001", "40P01"], ids=["serialization-failure", "deadlock-detected"]
    )
    def test_postgres_lock_states_are_contention(self, state: str) -> None:
        assert is_lock_contention(wrapped(PostgresError(state)))

    def test_an_unrelated_mysql_error_is_not_contention(self) -> None:
        """1114 is "table is full". Retrying it three times delays the report
        of a disk problem and fixes nothing."""
        assert not is_lock_contention(wrapped(MySQLError(1114, "table is full")))

    def test_an_unrelated_sqlstate_is_not_contention(self) -> None:
        assert not is_lock_contention(wrapped(PostgresError("53100")))

    def test_an_error_with_no_cause_is_not_contention(self) -> None:
        assert not is_lock_contention(OperationalError("connection already closed"))

    def test_a_sqlstate_carried_on_diag_is_recognised(self) -> None:
        """Some psycopg versions only expose it under .diag."""

        class Diag:
            sqlstate = "40P01"

        cause = Exception("deadlock detected")
        cause.diag = Diag()  # type: ignore[attr-defined]
        assert is_lock_contention(wrapped(cause))


@pytest.mark.django_db(transaction=True)
class TestRetryPolicy:
    """``transaction=True`` is load-bearing.

    The default fixture runs each test inside an atomic block that is never
    committed. The retry deliberately declines to run inside one -- a deadlock
    marks the whole transaction for rollback, so reissuing anything nested in it
    fails on the first query -- so under the default fixture nothing would ever
    be retried and every test below would pass for the wrong reason.
    """

    @pytest.fixture(autouse=True)
    def _no_waiting(self, monkeypatch) -> None:
        monkeypatch.setattr(db.time, "sleep", lambda _: None)

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

        assert len(calls) == db.ATTEMPTS

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
        monkeypatch.setattr(db.time, "sleep", waits.append)

        def always_deadlock(cls, event):
            raise wrapped(MySQLError(1213, "Deadlock found"))

        monkeypatch.setattr(AuditChain, "_append_once", classmethod(always_deadlock))
        with pytest.raises(OperationalError):
            AuditChain.append(self.event())

        assert waits == sorted(waits) and len(set(waits)) == len(waits)


@pytest.mark.django_db
class TestFailuresFrom:
    """The bounded count the break-glass throttle asks for."""

    def record(self, ip: str, reason: str = "bad-password") -> None:
        import datetime as dt

        AuditChain.append(
            AuditEvent(
                event_type=Event.PROTOCOL_FALLBACK,
                occurred_at=dt.datetime.now(tz=dt.UTC),
                outcome="failure",
                auth_protocol="break_glass",
                source_ip=ip,
                reason=reason,
            )
        )

    def since(self):
        import datetime as dt

        from django.utils import timezone

        return timezone.now() - dt.timedelta(seconds=900)

    def test_it_stops_at_the_limit(self) -> None:
        """The caller asked whether there were three, not how many there were.
        Counting them all would let whoever produced them set the cost."""
        for _ in range(50):
            self.record("10.0.0.1")

        counted = AuditEvent.objects.failures_from(
            "10.0.0.1", since=self.since(), protocol="break_glass", limit=3
        )
        assert counted == 3

    def test_it_counts_everything_when_nothing_is_ignored(self) -> None:
        self.record("10.0.0.1", reason="bad-password")
        self.record("10.0.0.1", reason="throttled")

        counted = AuditEvent.objects.failures_from(
            "10.0.0.1", since=self.since(), protocol="break_glass", limit=10
        )
        assert counted == 2

    def test_it_can_ignore_a_reason(self) -> None:
        self.record("10.0.0.1", reason="bad-password")
        self.record("10.0.0.1", reason="throttled")

        counted = AuditEvent.objects.failures_from(
            "10.0.0.1",
            since=self.since(),
            protocol="break_glass",
            limit=10,
            ignoring="throttled",
        )
        assert counted == 1

    def test_it_is_scoped_to_one_address(self) -> None:
        self.record("10.0.0.1")
        self.record("10.0.0.2")

        counted = AuditEvent.objects.failures_from(
            "10.0.0.1", since=self.since(), protocol="break_glass", limit=10
        )
        assert counted == 1


@pytest.mark.django_db(transaction=True)
class TestNestedTransaction:
    """What happens when the caller already owns a transaction.

    This is the common case, not the exotic one: every audit write during a
    login happens inside ``SSOBackend.resolve_or_provision``, which is atomic.
    A deadlock there has already marked that transaction for rollback, so a
    retry at this level would reissue into a broken transaction and report the
    resulting failure as if it were the original one.
    """

    def event(self) -> AuditEvent:
        import datetime as dt

        return AuditEvent(
            event_type=Event.LOGIN_SUCCEEDED,
            occurred_at=dt.datetime.now(tz=dt.UTC),
            outcome="success",
        )

    def test_it_does_not_retry_inside_an_enclosing_transaction(self, monkeypatch) -> None:
        from django.db import transaction

        calls: list[int] = []

        def always_deadlock(cls, event):
            calls.append(1)
            raise wrapped(MySQLError(1213, "Deadlock found"))

        monkeypatch.setattr(AuditChain, "_append_once", classmethod(always_deadlock))
        monkeypatch.setattr(db.time, "sleep", lambda _: pytest.fail("slept inside a transaction"))

        with pytest.raises(OperationalError), transaction.atomic():
            AuditChain.append(self.event())

        assert calls == [1], "retried inside a transaction that was already doomed"

    def test_it_says_so_rather_than_failing_silently(self, monkeypatch, caplog) -> None:
        from django.db import transaction

        def always_deadlock(cls, event):
            raise wrapped(MySQLError(1213, "Deadlock found"))

        monkeypatch.setattr(AuditChain, "_append_once", classmethod(always_deadlock))

        with pytest.raises(OperationalError), transaction.atomic():
            AuditChain.append(self.event())

        assert "cannot be retried here" in caplog.text

    def test_a_normal_call_still_retries(self, monkeypatch) -> None:
        """Guard against the in_atomic_block check swallowing every retry."""
        calls: list[int] = []
        real = AuditChain._append_once.__func__  # type: ignore[attr-defined]

        def flaky(cls, event):
            calls.append(1)
            if len(calls) == 1:
                raise wrapped(MySQLError(1213, "Deadlock found"))
            return real(cls, event)

        monkeypatch.setattr(AuditChain, "_append_once", classmethod(flaky))
        monkeypatch.setattr(db.time, "sleep", lambda _: None)

        AuditChain.append(self.event())
        assert len(calls) == 2
