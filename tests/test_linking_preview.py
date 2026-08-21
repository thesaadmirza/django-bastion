"""The adoption preview.

The property worth protecting is agreement. A preview that says "nothing will
happen" and is wrong is worse than no preview, because it is reassuring at
exactly the moment it should not be -- so the last class here drives the real
adoption path against the same fixtures and asserts the two answer the same.
"""

from __future__ import annotations

from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import override_settings

from bastion.linking import Outcome, preview

pytestmark = pytest.mark.django_db

User = get_user_model()

LINKING_ON = {
    "IDENTITY": {
        "LINKING_POLICY": "verified_email_once",
        "LINKABLE_EMAIL_DOMAINS": ["example.com"],
    }
}


def account(username: str, email: str, **kwargs: object) -> object:
    return User.objects.create(username=username, email=email, **kwargs)


def by_username(candidates: list) -> dict:
    return {c.username: c for c in candidates}


@pytest.fixture
def linking_on(settings: object) -> None:
    """Adoption on, one pinned domain."""
    settings.BASTION = LINKING_ON  # type: ignore[attr-defined]


@pytest.mark.usefixtures("linking_on")
class TestWhatWouldBeAdopted:
    def test_a_pinned_domain_with_one_holder_is_eligible(self) -> None:
        account("ada", "ada@example.com")
        found = by_username(preview())
        assert found["ada"].outcome is Outcome.ELIGIBLE

    def test_an_unpinned_domain_is_skipped_and_says_which(self) -> None:
        account("grace", "grace@elsewhere.test")
        candidate = by_username(preview())["grace"]
        assert candidate.outcome is Outcome.SKIPPED
        assert "elsewhere.test" in candidate.reason

    def test_no_address_is_skipped(self) -> None:
        account("nobody", "")
        assert by_username(preview())["nobody"].outcome is Outcome.SKIPPED

    def test_two_holders_are_both_ambiguous(self) -> None:
        account("ada", "shared@example.com")
        account("ada2", "shared@example.com")
        found = by_username(preview())
        assert found["ada"].outcome is Outcome.AMBIGUOUS
        assert found["ada2"].outcome is Outcome.AMBIGUOUS

    def test_case_is_folded_the_way_the_query_folds_it(self) -> None:
        """Adoption matches with email__iexact, so two addresses differing only
        in case are two holders of one address."""
        account("ada", "Shared@Example.com")
        account("ada2", "shared@example.com")
        assert by_username(preview())["ada"].outcome is Outcome.AMBIGUOUS

    def test_privilege_is_reported_because_it_is_what_review_is_for(self) -> None:
        account("root", "root@example.com", is_staff=True, is_superuser=True)
        assert by_username(preview())["root"].privileged is True

    def test_eligible_privileged_accounts_sort_first(self) -> None:
        account("plain", "plain@example.com")
        account("root", "root@example.com", is_staff=True)
        account("skipped", "skipped@elsewhere.test")
        assert [c.username for c in preview()][:2] == ["root", "plain"]


@pytest.mark.usefixtures("linking_on")
class TestAlreadyLinked:
    def test_an_account_with_an_identity_is_skipped(self) -> None:
        from bastion.models import FederatedIdentity

        user = account("ada", "ada@example.com")
        FederatedIdentity.objects.create(
            user=user, issuer="https://idp.test", subject="s-1", connection="corp"
        )
        candidate = by_username(preview())["ada"]
        assert candidate.outcome is Outcome.SKIPPED
        assert "already linked" in candidate.reason

    def test_a_linked_twin_does_not_make_the_other_ambiguous(self) -> None:
        """The adoption query counts only unlinked holders, so one linked and
        one unlinked account sharing an address has exactly one candidate.

        Counting both would report this as ambiguous and tell an administrator
        nothing would happen, immediately before it did.
        """
        from bastion.models import FederatedIdentity

        linked = account("old", "shared@example.com")
        FederatedIdentity.objects.create(
            user=linked, issuer="https://idp.test", subject="s-1", connection="corp"
        )
        account("new", "shared@example.com")

        found = by_username(preview())
        assert found["new"].outcome is Outcome.ELIGIBLE
        assert found["old"].outcome is Outcome.SKIPPED


@pytest.mark.usefixtures("linking_on")
class TestBreakGlass:
    def test_a_break_glass_account_is_never_adopted(self) -> None:
        from bastion.breakglass.models import BreakGlassAccount

        user = account("emergency", "emergency@example.com")
        BreakGlassAccount.objects.create(user=user, reason="the morning the IdP is wrong")
        candidate = by_username(preview())["emergency"]
        assert candidate.outcome is Outcome.SKIPPED
        assert "break-glass" in candidate.reason


class TestPolicyOff:
    def test_nothing_is_reported_when_linking_is_off(self) -> None:
        account("ada", "ada@example.com")
        assert preview() == []


@pytest.mark.usefixtures("linking_on")
class TestTheCommand:
    def _run(self, *args: str) -> str:
        out = StringIO()
        call_command("bastion_link_preview", *args, stdout=out, stderr=StringIO())
        return out.getvalue()

    def test_it_names_the_condition_it_cannot_check(self) -> None:
        """Every eligible row depends on the provider marking the address
        verified, which is not knowable here. Saying so is the point."""
        account("ada", "ada@example.com")
        assert "verified" in self._run()

    def test_eligible_only_filters(self) -> None:
        account("ada", "ada@example.com")
        account("grace", "grace@elsewhere.test")
        output = self._run("--eligible-only")
        assert "ada@example.com" in output
        assert "grace@elsewhere.test" not in output

    def test_json_is_parseable(self) -> None:
        import json

        account("ada", "ada@example.com")
        payload = json.loads(self._run("--json"))
        assert payload["candidates"][0]["outcome"] == "eligible"
        assert "verified" in payload["conditional_on"]

    def test_the_count_is_reported(self) -> None:
        account("root", "root@example.com", is_staff=True)
        account("grace", "grace@elsewhere.test")
        assert "1 of 2 accounts would be adopted, 1 of them privileged" in self._run()

    def test_it_says_so_when_the_policy_is_off(self) -> None:
        with override_settings(BASTION={"IDENTITY": {"LINKING_POLICY": "subject_only"}}):
            assert "subject_only" in self._run()


@pytest.mark.usefixtures("linking_on")
class TestThePreviewAgreesWithTheRealThing:
    """The only property that makes a preview worth having.

    Each fixture is run through the preview and through the backend's actual
    adoption path. A row the preview calls eligible must be adopted; anything
    else must not be.
    """

    def _adopts(self, email: str) -> bool:
        from bastion.backends import SSOBackend
        from bastion.claims import IdentityClaims, Verified
        from bastion.connections import Connection

        claims = IdentityClaims(
            issuer="https://idp.test",
            subject="brand-new-subject",
            subject_source="sub",
            email=email,
            email_verified=Verified.YES,
        )
        connection = Connection(identifier="corp", issuer="https://idp.test", client_id="cid")
        return SSOBackend().link_existing_user(claims, connection) is not None

    @pytest.mark.parametrize(
        ("setup", "email"),
        [
            ("eligible", "ada@example.com"),
            ("unpinned domain", "grace@elsewhere.test"),
            ("two holders", "shared@example.com"),
        ],
    )
    def test_they_agree(self, setup: str, email: str) -> None:
        account("ada", "ada@example.com")
        account("grace", "grace@elsewhere.test")
        account("twin-a", "shared@example.com")
        account("twin-b", "shared@example.com")

        previewed = [c for c in preview() if c.email.lower() == email.lower()]
        said_eligible = any(c.outcome is Outcome.ELIGIBLE for c in previewed)

        assert said_eligible == self._adopts(email), (
            f"{setup}: the preview said eligible={said_eligible} and the backend did the opposite"
        )
