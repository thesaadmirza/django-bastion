"""The public harness, used the way a project integrating this would use it.

Deliberately written against `bastion.testing` only, with no reach into
internals, because that is the whole claim: a project can test the paths that
matter without building a provider or knowing where bastion keeps its
transactions.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import SESSION_KEY, get_user_model
from django.test import Client

from bastion.testing import Harness, harness

pytestmark = pytest.mark.django_db

User = get_user_model()


class TestTheOrdinaryCase:
    def test_a_login_establishes_a_session(self, client: Client) -> None:
        rig = harness()
        with rig.installed():
            response = rig.login(client)
        assert response.status_code == 302
        assert SESSION_KEY in client.session

    def test_it_provisions_a_user(self, client: Client) -> None:
        rig = harness()
        with rig.installed():
            rig.login(client)
        assert User.objects.count() == 1

    def test_no_network_and_no_certificate(self) -> None:
        """The claim that makes this usable at all: bastion refuses a plain-http
        issuer with no localhost exemption, and the fake still needs none of the
        TLS scaffolding an integrator would otherwise build."""
        rig = harness()
        assert rig.connection.issuer.startswith("https://")
        assert rig.connection.transport is rig.transport


class TestShapingTheAssertion:
    """The paths a real provider will not produce on demand."""

    def test_an_unverified_address_is_refused(self, client: Client) -> None:
        rig = harness()
        with rig.installed():
            response = rig.login(client, email_verified=False)
        assert SESSION_KEY not in client.session
        assert response.status_code != 302

    def test_group_membership_reaches_the_flags(self, client: Client) -> None:
        rig = harness(staff_groups=("django-staff",))
        with rig.installed():
            rig.login(client, groups=["django-staff"])
        assert User.objects.get().is_staff

    def test_incomplete_group_evidence_does_not_escalate(self, client: Client) -> None:
        """Entra above its overage threshold sends a pointer rather than the
        list. Granting on that would be granting on evidence never gathered."""
        rig = harness(vendor="entra", staff_groups=("django-staff",))
        with rig.installed():
            rig.login(client, claims=rig.idp.with_group_overage())
        assert not User.objects.get().is_staff

    def test_a_whole_claim_set_still_gets_the_live_nonce(self, client: Client) -> None:
        """The builders carry the provider's placeholder nonce. Threading the
        live one through by hand is the friction this removes."""
        rig = harness(staff_groups=("django-staff",))
        with rig.installed():
            response = rig.login(client, claims=rig.idp.with_groups(["django-staff"]))
        assert response.status_code == 302
        assert User.objects.get().is_staff


class TestTheFlowItself:
    def test_the_nonce_comes_from_the_authorization_url(self, client: Client) -> None:
        """Not from a private attribute. This is the thing that made the flow
        hard to drive from outside."""
        rig = harness()
        with rig.installed():
            request = rig.begin(client)
        assert request.nonce and request.state
        assert request.nonce in request.url

    def test_a_replayed_state_is_refused(self, client: Client) -> None:
        rig = harness()
        with rig.installed():
            request = rig.begin(client)
            first = rig.complete(client, request)
            second = rig.complete(client, request)
        assert first.status_code == 302
        assert second.status_code != 302

    def test_a_mismatched_nonce_is_refused(self, client: Client) -> None:
        """One of the four the issue named. A caller-supplied nonce wins, so
        the mismatch is one keyword rather than a hand-built token."""
        rig = harness()
        with rig.installed():
            request = rig.begin(client)
            response = rig.complete(client, request, nonce="not-the-one-that-was-minted")
        assert SESSION_KEY not in client.session
        assert response.status_code != 302

    def test_requests_are_recorded_for_assertions(self, client: Client) -> None:
        rig = harness()
        with rig.installed():
            rig.begin(client)
            rig.begin(client)
        assert len(rig.requests) == 2
        assert rig.requests[0].state != rig.requests[1].state

    def test_the_patching_is_undone_on_exit(self, client: Client) -> None:
        import bastion.views

        before = bastion.views.get_connection
        rig = harness()
        with rig.installed():
            pass
        assert bastion.views.get_connection is before


class TestUnhelpfulFailures:
    """A harness that fails obscurely is one people stop using."""

    def test_a_non_redirect_from_begin_says_so(self, client: Client) -> None:
        rig = harness()
        with pytest.raises(AssertionError, match="expected a redirect"):
            rig.begin(client, path="/no-such-view/")

    def test_a_redirect_somewhere_else_says_what_was_missing(self, client: Client) -> None:
        """A 302 to a login page is still a 302. The message has to name the
        thing that was not there rather than claim the status was wrong."""
        rig = harness()
        with pytest.raises(AssertionError, match="state or nonce"):
            rig.begin(client, path="/admin/")

    def test_an_authorization_url_without_a_nonce_says_which(self) -> None:
        from bastion.testing import AuthorizationRequest

        with pytest.raises(AssertionError, match="nonce"):
            AuthorizationRequest.from_location("https://idp.test/authorize?state=abc")


class TestVendors:
    @pytest.mark.parametrize("vendor", ["generic", "entra", "okta", "google", "keycloak"])
    def test_every_shipped_profile_can_be_driven(self, client: Client, vendor: str) -> None:
        """A profile in the registry that the harness cannot drive is one no
        project can test against."""
        rig = harness(vendor=vendor)
        with rig.installed():
            response = rig.login(client)
        assert response.status_code == 302, f"{vendor} could not complete a login"

    def test_the_harness_is_typed_as_advertised(self) -> None:
        rig = harness()
        assert isinstance(rig, Harness)
