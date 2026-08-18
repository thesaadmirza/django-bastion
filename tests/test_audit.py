"""The audit log.

Two properties carry most of the weight here.

Events are pseudonymous from the start, so erasure can sever the link to a
person without touching a record or breaking the chain. Several tests assert
that no identifier ever reaches the table in the first place.

The sequence is gapless, which is what lets an exported sample be shown to be
complete. Auditors challenge completeness far more often than content.
"""

from __future__ import annotations

import datetime as dt

import pytest
from django.contrib.auth import get_user_model

from bastion.audit.events import Event, Outcome, Severity
from bastion.audit.models import (
    AppendOnly,
    AuditActor,
    AuditChain,
    AuditEvent,
    forget_actor,
    verify_chain,
)
from bastion.audit.recorder import emit
from bastion.audit.sinks import DatabaseSink, LoggingSink

pytestmark = pytest.mark.django_db

User = get_user_model()


@pytest.fixture
def user():
    return User.objects.create_user(username="alice", email="alice@example.test")


class TestPseudonymity:
    def test_an_event_stores_no_user_identifier(self, user) -> None:
        """The whole erasure design rests on this. If a user id, an email or a
        username ever lands in the table, deleting the mapping row stops being
        sufficient.

        Checking the pseudonym for the digits of the primary key would be a
        flaky test rather than a strict one: a random base64url token contains
        any given character about half the time. The properties that actually
        matter are that identifying strings are absent from the record, and
        that the token is not derived from the key.
        """
        emit(Event.LOGIN_SUCCEEDED, actor=user)
        event = AuditEvent.objects.get()

        serialised = str(event.__dict__)
        assert "alice" not in serialised
        assert "alice@example.test" not in serialised
        assert event.actor_pseudonym != str(user.pk)
        assert len(event.actor_pseudonym) >= 32

    def test_the_token_is_not_derived_from_the_user(self) -> None:
        """Two users created identically must not produce related tokens.

        A derived token would be reversible by anyone who can enumerate users,
        which would defeat erasure entirely.
        """
        tokens = set()
        for index in range(5):
            person = User.objects.create_user(username=f"person-{index}")
            emit(Event.LOGIN_SUCCEEDED, actor=person)
            tokens.add(AuditActor.objects.get(user=person).pseudonym)
        assert len(tokens) == 5

    def test_the_same_user_gets_a_stable_token(self, user) -> None:
        emit(Event.LOGIN_SUCCEEDED, actor=user)
        emit(Event.LOGIN_SUCCEEDED, actor=user)
        assert len({e.actor_pseudonym for e in AuditEvent.objects.all()}) == 1

    def test_different_users_get_different_tokens(self, user) -> None:
        other = User.objects.create_user(username="bob")
        emit(Event.LOGIN_SUCCEEDED, actor=user)
        emit(Event.LOGIN_SUCCEEDED, actor=other)
        assert len({e.actor_pseudonym for e in AuditEvent.objects.all()}) == 2

    def test_an_actorless_event_is_allowed(self) -> None:
        emit(Event.LOGIN_FAILED, outcome=Outcome.FAILURE)
        assert AuditEvent.objects.get().actor_pseudonym == ""


class TestErasure:
    def test_forgetting_severs_the_link_but_keeps_the_events(self, user) -> None:
        emit(Event.LOGIN_SUCCEEDED, actor=user)
        emit(Event.LOGIN_SUCCEEDED, actor=user)

        affected = forget_actor(user, reason="subject access request 41")

        assert affected == 2
        assert AuditActor.objects.filter(user=user).count() == 0
        # The events survive. What is destroyed is the only route back.
        assert AuditEvent.objects.filter(event_type=Event.LOGIN_SUCCEEDED).count() == 2

    def test_the_chain_survives_erasure(self, user) -> None:
        """The reason events are pseudonymous rather than redacted after the
        fact: redaction would rewrite records and break the chain."""
        emit(Event.LOGIN_SUCCEEDED, actor=user)
        emit(Event.LOGIN_SUCCEEDED, actor=user)
        forget_actor(user)

        ok, problems = verify_chain()
        assert ok, problems

    def test_erasure_is_itself_recorded(self, user) -> None:
        emit(Event.LOGIN_SUCCEEDED, actor=user)
        forget_actor(user, reason="subject access request 41")
        record = AuditEvent.objects.get(event_type=Event.ACTOR_FORGOTTEN)
        assert record.reason == "subject access request 41"

    def test_forgetting_an_unknown_user_is_a_no_op(self, user) -> None:
        assert forget_actor(user) == 0


class TestAppendOnly:
    def test_an_event_cannot_be_modified(self) -> None:
        emit(Event.LOGIN_SUCCEEDED)
        event = AuditEvent.objects.get()
        event.reason = "rewritten"
        with pytest.raises(AppendOnly):
            event.save()

    def test_an_event_cannot_be_deleted(self) -> None:
        emit(Event.LOGIN_SUCCEEDED)
        with pytest.raises(AppendOnly):
            AuditEvent.objects.get().delete()


class TestChain:
    def test_the_sequence_is_gapless(self) -> None:
        for _ in range(5):
            emit(Event.LOGIN_SUCCEEDED)
        assert [e.chain_seq for e in AuditEvent.objects.in_order()] == [1, 2, 3, 4, 5]

    def test_each_record_links_to_the_previous(self) -> None:
        for _ in range(3):
            emit(Event.LOGIN_SUCCEEDED)
        events = list(AuditEvent.objects.in_order())
        assert events[0].prev_hash == ""
        assert events[1].prev_hash == events[0].record_hash
        assert events[2].prev_hash == events[1].record_hash

    def test_a_clean_chain_verifies(self) -> None:
        for _ in range(4):
            emit(Event.LOGIN_SUCCEEDED)
        ok, problems = verify_chain()
        assert ok and problems == []

    def test_a_rewritten_record_is_detected(self) -> None:
        for _ in range(3):
            emit(Event.LOGIN_SUCCEEDED)
        # Bypassing the append-only guard, the way a direct database edit would.
        AuditEvent.objects.filter(chain_seq=2).update(reason="tampered")

        ok, problems = verify_chain()
        assert not ok
        assert any("does not match its hash" in p for p in problems)

    def test_a_removed_record_is_detected(self) -> None:
        for _ in range(4):
            emit(Event.LOGIN_SUCCEEDED)
        AuditEvent.objects.filter(chain_seq=2).delete()

        ok, problems = verify_chain()
        assert not ok
        assert any("sequence gap" in p for p in problems)

    def test_a_recomputed_chain_is_not_detected(self) -> None:
        """Stated as a test because the limit belongs in the record, not only
        in a docstring. Hash chaining is tamper evidence, not immutability: an
        adversary with write access recomputes it. The control that actually
        helps is shipping events somewhere they do not administer."""
        for _ in range(3):
            emit(Event.LOGIN_SUCCEEDED)

        target = AuditEvent.objects.get(chain_seq=2)
        target.reason = "tampered"
        AuditEvent.objects.filter(pk=target.pk).update(
            reason="tampered", record_hash=target.compute_hash()
        )
        # Relink the successor so the chain stays internally consistent.
        third = AuditEvent.objects.get(chain_seq=3)
        third.prev_hash = target.compute_hash()
        AuditEvent.objects.filter(pk=third.pk).update(
            prev_hash=third.prev_hash, record_hash=third.compute_hash()
        )

        ok, _ = verify_chain()
        assert ok, "expected the recomputed chain to pass; the limit is real"

    def test_the_head_is_tracked_for_external_anchoring(self) -> None:
        emit(Event.LOGIN_SUCCEEDED)
        head = AuditChain.objects.get(name="default")
        assert head.last_seq == 1
        assert head.last_hash == AuditEvent.objects.get().record_hash


class TestSinks:
    def test_a_failing_sink_does_not_raise(self, settings, caplog) -> None:
        """Losing a record is bad. Failing a login because a collector is
        unreachable is worse."""

        class Exploding:
            def record(self, payload):
                raise RuntimeError("collector is down")

        from bastion.audit import recorder

        recorder._sinks = [Exploding(), DatabaseSink()]
        try:
            emit(Event.LOGIN_SUCCEEDED)
        finally:
            recorder.reset_sinks()

        assert AuditEvent.objects.count() == 1
        assert "failed" in caplog.text.lower()

    def test_the_logging_sink_emits_json(self, caplog) -> None:
        import json
        import logging

        from bastion.audit import recorder

        recorder._sinks = [LoggingSink()]
        try:
            with caplog.at_level(logging.INFO, logger="bastion.audit"):
                emit(Event.LOGIN_SUCCEEDED, connection="corp")
        finally:
            recorder.reset_sinks()

        payload = json.loads(caplog.records[-1].message)
        assert payload["event_type"] == "auth.login.succeeded"
        assert payload["connection"] == "corp"


class TestRequestContext:
    def test_the_session_key_is_hashed(self, rf) -> None:
        """A session key is a live credential. An audit table is exactly the
        sort of place it should not be sitting in clear."""
        from django.contrib.sessions.backends.db import SessionStore

        request = rf.get("/")
        request.session = SessionStore()
        request.session.create()

        emit(Event.LOGIN_SUCCEEDED, request=request)
        event = AuditEvent.objects.get()
        assert event.session_id
        assert event.session_id != request.session.session_key

    def test_the_client_address_is_recorded(self, rf) -> None:
        request = rf.get("/", REMOTE_ADDR="203.0.113.4")
        emit(Event.LOGIN_SUCCEEDED, request=request)
        assert AuditEvent.objects.get().source_ip == "203.0.113.4"

    def test_a_forwarded_header_is_not_trusted(self, rf) -> None:
        """Parsing X-Forwarded-For here would write attacker-chosen values into
        the evidence unless the edge is known to strip it."""
        request = rf.get("/", REMOTE_ADDR="10.0.0.1", HTTP_X_FORWARDED_FOR="198.51.100.9")
        emit(Event.LOGIN_SUCCEEDED, request=request)
        assert AuditEvent.objects.get().source_ip == "10.0.0.1"


class TestSchema:
    def test_records_carry_a_schema_version(self) -> None:
        emit(Event.LOGIN_SUCCEEDED)
        assert AuditEvent.objects.get().schema_version >= 1

    def test_recorded_at_is_distinct_from_occurred_at(self) -> None:
        past = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
        emit(Event.LOGIN_SUCCEEDED, occurred_at=past)
        event = AuditEvent.objects.get()
        assert event.occurred_at == past
        assert event.recorded_at > past

    def test_changes_are_structured_not_prose(self) -> None:
        emit(
            Event.ROLE_GRANTED,
            changes={"is_staff": {"from": False, "to": True}},
            severity=Severity.NOTICE,
        )
        assert AuditEvent.objects.get().changes["is_staff"]["to"] is True


class TestClientAddressResolution:
    """``client_address`` is the single definition of "the client address".

    The break-glass throttle counts audit rows by ``source_ip`` and derives its
    own key from this function, so anything it returns has to be a value the
    recorder can actually store — otherwise the two agree only by coincidence.
    """

    def test_a_real_address_is_returned(self, rf) -> None:
        from bastion.audit.recorder import client_address

        assert client_address(rf.post("/", REMOTE_ADDR="203.0.113.7")) == "203.0.113.7"

    def test_ipv6_is_returned(self, rf) -> None:
        from bastion.audit.recorder import client_address

        assert client_address(rf.post("/", REMOTE_ADDR="2001:db8::1")) == "2001:db8::1"

    def test_a_missing_address_is_none(self, rf) -> None:
        from bastion.audit.recorder import client_address

        request = rf.post("/")
        request.META.pop("REMOTE_ADDR", None)
        assert client_address(request) is None

    def test_something_that_is_not_an_address_is_none(self, rf) -> None:
        """PostgreSQL stores this column as inet, so a value that is not an
        address raises on the way to the driver — on a write, where the
        recorder's broad catch swallows it and loses the whole record, and on a
        lookup, where it escapes into the caller."""
        from bastion.audit.recorder import client_address

        assert client_address(rf.post("/", REMOTE_ADDR="not-an-address")) is None

    def test_a_request_with_no_meta_at_all_is_none(self) -> None:
        from bastion.audit.recorder import client_address

        assert client_address(object()) is None
