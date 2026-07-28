"""The small surfaces of the security core.

String representations, queryset helpers, and the last few error branches.
None of it is clever. It is here because the core carries a 100% gate, and a
gate with exemptions carved into it stops telling you anything.

``__str__`` in particular is not filler: these objects are rendered in the
Django admin and in ``manage.py shell`` during an incident, and a ``__str__``
that raises turns a changelist into a 500 at the worst possible moment.
"""

from __future__ import annotations

import datetime as dt
import logging

import pytest

from bastion.audit.events import Event, Outcome
from bastion.audit.models import AuditActor, AuditChain, AuditEvent, export_manifest
from bastion.audit.recorder import emit
from bastion.audit.sinks import LoggingSink, NullSink
from bastion.breakglass.models import BreakGlassAccount
from bastion.claims import Verified
from bastion.exceptions import (
    ClaimValidationError,
    ConfigurationError,
    TransactionExpired,
)
from bastion.protocols.oidc import quirks
from bastion.protocols.oidc.transaction import CacheTransactionStore, Transaction


@pytest.mark.django_db
class TestAuditRepr:
    def test_an_actor_renders_as_its_pseudonym(self, django_user_model) -> None:
        user = django_user_model.objects.create_user(username="alice")
        actor = AuditActor.for_user(user)
        assert str(actor) == actor.pseudonym

    def test_an_event_renders_sequence_type_and_outcome(self) -> None:
        emit(Event.LOGIN_SUCCEEDED, outcome=Outcome.SUCCESS)
        event = AuditEvent.objects.get()
        assert str(event) == f"1 {Event.LOGIN_SUCCEEDED.value} success"

    def test_a_chain_renders_name_and_head(self) -> None:
        emit(Event.LOGIN_SUCCEEDED)
        assert str(AuditChain.objects.get()) == "default@1"

    def test_events_can_be_filtered_by_actor(self, django_user_model) -> None:
        alice = django_user_model.objects.create_user(username="alice")
        bob = django_user_model.objects.create_user(username="bob")
        emit(Event.LOGIN_SUCCEEDED, actor=alice)
        emit(Event.LOGIN_SUCCEEDED, actor=bob)

        pseudonym = AuditActor.for_user(alice).pseudonym
        assert AuditEvent.objects.for_actor(pseudonym).count() == 1

    def test_a_manifest_can_be_scoped_to_a_window(self) -> None:
        """Auditors ask for a period, not the whole table, and the manifest has
        to describe the slice they were handed."""
        emit(Event.LOGIN_SUCCEEDED)
        emit(Event.LOGIN_FAILED)

        cutoff = AuditEvent.objects.in_order().last().occurred_at
        manifest = export_manifest(since=cutoff)

        assert manifest["count"] == 1
        assert manifest["since"] == cutoff.isoformat()
        # The head still describes the whole chain, which is what makes a
        # partial export checkable against the full one.
        assert manifest["chain_head_seq"] == 2


class TestSinks:
    @pytest.fixture(autouse=True)
    def _capture_info(self, caplog):
        caplog.set_level(logging.INFO, logger="bastion.audit")

    def test_a_datetime_is_made_serialisable(self, caplog) -> None:
        LoggingSink().record(
            {"event_type": Event.LOGIN_SUCCEEDED, "occurred_at": dt.datetime(2026, 7, 28)}
        )
        assert "2026-07-28T00:00:00" in caplog.text

    def test_an_already_formatted_timestamp_is_left_alone(self, caplog) -> None:
        LoggingSink().record({"event_type": "x", "occurred_at": "already-a-string"})
        assert "already-a-string" in caplog.text

    def test_the_null_sink_discards(self) -> None:
        assert NullSink().record({"event_type": "x"}) is None


@pytest.mark.django_db
def test_a_break_glass_account_renders_its_user(django_user_model) -> None:
    user = django_user_model.objects.create_user(username="root")
    account = BreakGlassAccount.objects.create(user=user, reason="last way in")
    assert str(account) == "break-glass: root"


class TestSubjectExtraction:
    """Every vendor adapter must refuse a token with no usable subject, because
    the alternative is federating an account onto an empty string."""

    @pytest.mark.parametrize(
        "adapter",
        [quirks.OktaQuirks(), quirks.GoogleQuirks(), quirks.KeycloakQuirks()],
        ids=["okta", "google", "keycloak"],
    )
    @pytest.mark.parametrize(
        "claims", [{}, {"sub": ""}, {"sub": 42}], ids=["absent", "empty", "int"]
    )
    def test_a_missing_subject_is_refused(self, adapter, claims: dict) -> None:
        with pytest.raises(ClaimValidationError, match="sub is missing"):
            adapter.subject(claims)

    def test_entra_reports_an_unverified_email(self) -> None:
        """xms_edov present and false is a real answer, not an absent one, and
        conflating the two is how an unverified address gets auto-linked."""
        adapter = quirks.EntraQuirks()
        assert adapter.email_verified({"xms_edov": False}) is Verified.NO
        assert adapter.email_verified({"xms_edov": True}) is Verified.YES
        assert adapter.email_verified({}) is Verified.UNKNOWN


class TestTransactionLifetime:
    def test_saving_an_already_expired_transaction_is_a_configuration_error(self) -> None:
        """A non-positive TTL means the configured lifetime is broken. Storing
        it would produce a login that fails on the round trip every time."""
        now = dt.datetime(2026, 7, 28, tzinfo=dt.UTC)
        transaction = Transaction(
            state="s",
            nonce="n",
            code_verifier="v" * 43,
            connection="default",
            created_at=now - dt.timedelta(minutes=10),
            expires_at=now - dt.timedelta(minutes=5),
        )
        store = CacheTransactionStore(clock=lambda: now)
        with pytest.raises(ConfigurationError, match="expires in the past"):
            store.save(transaction)

    def test_loading_an_expired_transaction_is_refused(self) -> None:
        """The cache TTL and our own clock can disagree — a backend with coarse
        expiry, or one that never expires at all — so the deadline is checked
        again on the way out."""
        now = dt.datetime(2026, 7, 28, tzinfo=dt.UTC)
        clock = {"now": now}
        transaction = Transaction(
            state="s",
            nonce="n",
            code_verifier="v" * 43,
            connection="default",
            created_at=now,
            expires_at=now + dt.timedelta(minutes=5),
        )
        store = CacheTransactionStore(clock=lambda: clock["now"])
        store.save(transaction)

        clock["now"] = now + dt.timedelta(minutes=6)
        with pytest.raises(TransactionExpired):
            store.consume("s")
