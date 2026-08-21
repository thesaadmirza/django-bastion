"""Who holds admin access, and on what basis.

The rows that matter are the ones with no basis: an account somebody ticked
is_staff on holds exactly what a group claim granted this morning, and only one
of them leaves a record.

The distinction this module exists to protect is between "no record, and none
was ever purged" and "no record, but the chain has been purged". Reporting the
first when the second is true accuses somebody of ticking a box by hand on the
strength of a retention policy doing its job.
"""

from __future__ import annotations

from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.utils import timezone

from bastion.access import Basis, holders, unattributable_grants
from bastion.audit.events import Event, Severity
from bastion.audit.models import AuditActor, AuditChain
from bastion.audit.recorder import emit

pytestmark = pytest.mark.django_db

User = get_user_model()


def admin(username: str, **kwargs: object) -> object:
    kwargs.setdefault("is_staff", True)
    return User.objects.create(username=username, email=f"{username}@example.com", **kwargs)


def by_username(found: list) -> dict:
    return {h.username: h for h in found}


def grant(user: object, field: str = "is_staff", connection: str = "corp") -> None:
    """A grant the way apply_flags records one."""
    emit(
        Event.ROLE_GRANTED,
        actor=user,
        connection=connection,
        changes={field: {"from": False, "to": True}},
        is_privileged=True,
        severity=Severity.NOTICE,
    )


class TestWhoIsListed:
    def test_only_privileged_accounts_appear(self) -> None:
        admin("boss")
        User.objects.create(username="ordinary", is_staff=False)
        assert list(by_username(holders())) == ["boss"]

    def test_superusers_are_listed_even_without_staff(self) -> None:
        admin("root", is_staff=False, is_superuser=True)
        assert by_username(holders())["root"].is_superuser is True

    def test_an_inactive_admin_still_appears(self) -> None:
        """Switched off is not the same as gone, and a review wants both."""
        admin("retired", is_active=False)
        assert by_username(holders())["retired"].is_active is False

    def test_superusers_sort_first(self) -> None:
        admin("staffer")
        admin("root", is_superuser=True)
        assert holders()[0].username == "root"


class TestTheBasis:
    def test_a_grant_on_the_chain_is_reported_with_its_connection(self) -> None:
        user = admin("granted")
        grant(user, connection="corp")
        holder = by_username(holders())["granted"]
        assert holder.basis is Basis.GRANTED_BY_SSO
        assert holder.connection == "corp"
        assert holder.granted_at is not None

    def test_no_record_and_no_purge_is_reported_as_outside_sso(self) -> None:
        admin("by-hand")
        holder = by_username(holders())["by-hand"]
        assert holder.basis is Basis.OUTSIDE_SSO

    def test_no_record_with_a_purged_chain_is_not_blamed_on_anybody(self) -> None:
        """The distinction this module exists for. A purged chain means the
        grant may have been recorded and removed on schedule, and saying
        "set by hand" there is an accusation the data does not support.
        """
        admin("old-timer")
        AuditChain.objects.update_or_create(name="default", defaults={"purged_through_seq": 42})
        holder = by_username(holders())["old-timer"]
        assert holder.basis is Basis.BEFORE_THE_WINDOW
        assert "purged" in " ".join(holder.notes)

    def test_a_revocation_is_not_mistaken_for_a_grant(self) -> None:
        """ROLE_GRANTED carries changes; a flag going false is not a basis."""
        user = admin("demoted")
        emit(
            Event.ROLE_GRANTED,
            actor=user,
            connection="corp",
            changes={"is_superuser": {"from": True, "to": False}},
            is_privileged=True,
            severity=Severity.NOTICE,
        )
        assert by_username(holders())["demoted"].basis is Basis.OUTSIDE_SSO

    def test_a_grant_of_an_unrelated_field_is_not_a_basis(self) -> None:
        user = admin("odd")
        emit(
            Event.ROLE_GRANTED,
            actor=user,
            connection="corp",
            changes={"is_chatty": {"from": False, "to": True}},
            is_privileged=True,
            severity=Severity.NOTICE,
        )
        assert by_username(holders())["odd"].basis is Basis.OUTSIDE_SSO


class TestIdentities:
    def test_an_account_with_no_identity_is_flagged(self) -> None:
        """Exactly the ones worth looking at: they predate SSO."""
        admin("legacy")
        assert by_username(holders())["legacy"].predates_sso is True

    def test_an_account_with_one_is_not(self) -> None:
        from bastion.models import FederatedIdentity

        user = admin("modern")
        FederatedIdentity.objects.create(
            user=user, issuer="https://idp.test", subject="s-1", connection="corp"
        )
        holder = by_username(holders())["modern"]
        assert holder.predates_sso is False
        assert holder.identities == ("https://idp.test s-1",)


class TestBreakGlass:
    def test_a_break_glass_admin_is_marked(self) -> None:
        from bastion.breakglass.models import BreakGlassAccount

        user = admin("emergency")
        BreakGlassAccount.objects.create(user=user, reason="the bad morning")
        assert by_username(holders())["emergency"].break_glass is True


class TestUnattributableGrants:
    def test_a_grant_whose_actor_was_erased_is_counted(self) -> None:
        """Erasure deletes the link and leaves the events. Counting them is the
        difference between accounting for every grant and quietly skipping
        some."""
        user = admin("forgotten")
        grant(user)
        AuditActor.objects.filter(user=user).delete()
        assert unattributable_grants() == 1

    def test_a_resolvable_grant_is_not_counted(self) -> None:
        grant(admin("present"))
        assert unattributable_grants() == 0


class TestTheCommand:
    def _run(self, *args: str) -> str:
        out = StringIO()
        call_command("bastion_access", *args, stdout=out, stderr=StringIO())
        return out.getvalue()

    def test_it_says_so_when_nobody_holds_anything(self) -> None:
        assert "Nobody holds" in self._run()

    def test_an_unexplained_admin_is_visible(self) -> None:
        admin("by-hand")
        output = self._run()
        assert "by-hand" in output
        assert "outside SSO" in output

    def test_unexplained_only_filters(self) -> None:
        grant(admin("granted"))
        admin("by-hand")
        output = self._run("--unexplained-only")
        assert "by-hand" in output
        assert "granted" not in output

    def test_the_summary_counts_what_a_review_asks(self) -> None:
        admin("by-hand")
        assert "1 account(s) can reach the admin" in self._run()
        assert "1 have no grant on the audit chain" in self._run()

    def test_json_is_parseable(self) -> None:
        import json

        grant(admin("granted"))
        payload = json.loads(self._run("--json"))
        assert payload["holders"][0]["basis"] == "granted_by_sso"
        assert payload["unattributable_grants"] == 0

    def test_erased_grants_are_reported_in_the_summary(self) -> None:
        user = admin("forgotten")
        grant(user)
        AuditActor.objects.filter(user=user).delete()
        assert "cannot account for every grant" in self._run()


class TestItDoesNotLieAboutWhatItKnows:
    def test_a_purged_chain_never_reports_outside_sso(self) -> None:
        """The whole point. Once the chain has been purged, absence of a record
        is not evidence of anything."""
        for name in ("a", "b", "c"):
            admin(name)
        AuditChain.objects.update_or_create(name="default", defaults={"purged_through_seq": 1})

        bases = {h.basis for h in holders()}
        assert Basis.OUTSIDE_SSO not in bases
        assert bases == {Basis.BEFORE_THE_WINDOW}

    def test_the_grant_lookup_does_not_reach_into_another_actor(self) -> None:
        """Two admins, one grant. The other must not inherit it.

        The second account has to have acted for this to test anything: an
        account with no audit actor never reaches the grant lookup at all, so
        an earlier version of this test passed with the actor filter deleted.
        The realistic shape is somebody who has signed in and whose is_staff
        was then ticked by hand -- exactly where a missing filter would hand
        them somebody else's grant as evidence.
        """
        granted = admin("granted")
        other = admin("other")
        grant(granted)
        emit(
            Event.USER_PROVISIONED,
            actor=other,
            connection="corp",
            severity=Severity.INFO,
        )

        found = by_username(holders())
        assert found["granted"].basis is Basis.GRANTED_BY_SSO
        assert found["other"].basis is Basis.OUTSIDE_SSO

    def test_the_most_recent_grant_wins(self) -> None:
        user = admin("twice")
        grant(user, connection="old")
        later = timezone.now() + timezone.timedelta(hours=1)
        emit(
            Event.ROLE_GRANTED,
            actor=user,
            connection="new",
            changes={"is_staff": {"from": False, "to": True}},
            is_privileged=True,
            severity=Severity.NOTICE,
            occurred_at=later,
        )
        assert by_username(holders())["twice"].connection == "new"
