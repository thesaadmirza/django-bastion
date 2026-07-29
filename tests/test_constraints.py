"""The database constraints, verified on whatever backend is configured.

These are the guarantees the support matrix makes claims about, so they are
checked rather than asserted in prose. Run under BASTION_TEST_DB=postgres and
=mysql as well as the default SQLite; all three must pass.

Both constraints are plain unique constraints over concrete columns. That is a
deliberate choice, not an accident: a partial constraint carrying a ``condition``
is silently ignored by MySQL and MariaDB, which would leave the guarantee absent
on those backends with nothing to indicate it. Anything relying on a condition
belongs in application logic that runs everywhere, or in a Tier 1-only feature
that says so.
"""

from __future__ import annotations

import datetime as dt

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, connection, transaction

from bastion.audit.events import Event
from bastion.audit.models import AuditEvent
from bastion.models import FederatedIdentity


def an_event(chain_seq: int, chain: str = "default") -> AuditEvent:
    event = AuditEvent(
        event_type=Event.LOGIN_SUCCEEDED,
        occurred_at=dt.datetime.now(tz=dt.UTC),
        outcome="success",
        chain=chain,
        chain_seq=chain_seq,
        prev_hash="",
    )
    event.record_hash = event.compute_hash()
    return event


@pytest.mark.django_db
class TestAuditSequenceUniqueness:
    """The constraint that turns a lost lock race into a hard failure rather
    than a silently forked chain."""

    def test_a_duplicate_sequence_number_is_refused(self) -> None:
        an_event(1).save()
        with pytest.raises(IntegrityError), transaction.atomic():
            an_event(1).save()

    def test_the_same_sequence_in_another_chain_is_allowed(self) -> None:
        """The constraint is scoped to the chain, so a second chain starts at
        one again rather than continuing someone else's numbering."""
        an_event(1).save()
        an_event(1, chain="tenant-b").save()
        assert AuditEvent.objects.count() == 2

    def test_the_constraint_exists_on_this_backend(self) -> None:
        """Named explicitly, because a constraint Django believes in but the
        server never created is the failure this whole file exists to catch."""
        constraints = connection.introspection.get_constraints(
            connection.cursor(), AuditEvent._meta.db_table
        )
        unique_sets = [
            tuple(sorted(details["columns"]))
            for details in constraints.values()
            if details["unique"]
        ]
        assert ("chain", "chain_seq") in unique_sets


@pytest.mark.django_db
class TestIdentityUniqueness:
    """One federated identity per (issuer, subject). Without it the same
    provider account could be linked to two local users, and which one a login
    lands in becomes a matter of row order."""

    def test_a_duplicate_issuer_and_subject_is_refused(self) -> None:
        user_model = get_user_model()
        alice = user_model.objects.create_user(username="alice")
        bob = user_model.objects.create_user(username="bob")

        FederatedIdentity.objects.create(
            user=alice, issuer="https://idp.test", subject="s-1", subject_source="sub"
        )
        with pytest.raises(IntegrityError), transaction.atomic():
            FederatedIdentity.objects.create(
                user=bob, issuer="https://idp.test", subject="s-1", subject_source="sub"
            )

    def test_the_same_subject_from_another_issuer_is_allowed(self) -> None:
        """Subjects are only unique within an issuer. Treating them as globally
        unique would let one provider claim another's accounts."""
        user_model = get_user_model()
        alice = user_model.objects.create_user(username="alice")
        bob = user_model.objects.create_user(username="bob")

        FederatedIdentity.objects.create(
            user=alice, issuer="https://idp-a.test", subject="s-1", subject_source="sub"
        )
        FederatedIdentity.objects.create(
            user=bob, issuer="https://idp-b.test", subject="s-1", subject_source="sub"
        )
        assert FederatedIdentity.objects.count() == 2

    def test_the_constraint_exists_on_this_backend(self) -> None:
        constraints = connection.introspection.get_constraints(
            connection.cursor(), FederatedIdentity._meta.db_table
        )
        unique_sets = [
            tuple(sorted(details["columns"]))
            for details in constraints.values()
            if details["unique"]
        ]
        assert ("issuer", "subject") in unique_sets


@pytest.mark.django_db
def test_no_constraint_depends_on_a_condition() -> None:
    """A guard on the claim above.

    Django accepts ``UniqueConstraint(condition=...)`` against MySQL and
    MariaDB and then does not create it, so the guarantee disappears with no
    error. If someone adds one, this fails and the support matrix has to be
    revisited rather than quietly becoming wrong.
    """
    offenders = [
        f"{model.__name__}.{constraint.name}"
        for model in (AuditEvent, FederatedIdentity)
        for constraint in model._meta.constraints
        if getattr(constraint, "condition", None) is not None
    ]
    assert offenders == [], (
        f"conditional constraints are silently dropped on MySQL/MariaDB: {offenders}"
    )
