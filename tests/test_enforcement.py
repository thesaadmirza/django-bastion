"""Two settings that were declared, documented, and read by nothing.

Both were found by reading every ``get_setting`` call site against the settings
reference rather than by a failing test, which is the point: a control that is
not enforced has no failing test to find, and the docs said both were on.

``IDENTITY["REQUIRE_VERIFIED_EMAIL"]`` defaulted to ``True`` and a user whose
provider marked the address unverified was provisioned and, with a matching
group, made staff.

``ADMIN["require_mfa"]`` defaulted to ``True`` and enforced nothing, so the
README quickstart -- which sets it -- read as MFA-protected and was not.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.contrib.auth import SESSION_KEY, get_user_model
from django.test import Client

from bastion import connections as connections_module
from bastion.claims import IdentityClaims, Verified
from bastion.connections import Connection
from bastion.exceptions import TokenError
from bastion.flows import _check_email_verification
from bastion.views import SESSION_MFA_KEY
from tests.idp.provider import FakeIdP
from tests.idp.transport import FakeTransport
from tests.test_login_flow import login, make_connection, only_connections

pytestmark = pytest.mark.django_db

User = get_user_model()


@pytest.fixture
def transport(idp: FakeIdP) -> FakeTransport:
    return FakeTransport(idp=idp)


def wire(idp: FakeIdP, transport: FakeTransport, monkeypatch, **overrides: Any) -> Connection:
    built = make_connection(idp, transport, **overrides)
    monkeypatch.setattr(connections_module, "get_connection", lambda name=None: built)
    monkeypatch.setattr("bastion.views.get_connection", lambda name=None: built)
    monkeypatch.setattr("bastion.views.get_setting", only_connections)
    return built


def claims(email: str | None, verified: Verified) -> IdentityClaims:
    return IdentityClaims(
        issuer="https://idp.example.test",
        subject="s",
        subject_source="sub",
        email=email,
        email_verified=verified,
    )


class TestVerifiedEmail:
    """Only an explicit false is refused, and the tri-state is why."""

    def test_an_explicitly_unverified_address_is_refused(self) -> None:
        with pytest.raises(TokenError):
            _check_email_verification(claims("a@b.test", Verified.NO))

    def test_a_verified_address_passes(self) -> None:
        _check_email_verification(claims("a@b.test", Verified.YES))

    def test_an_unknown_verification_state_passes(self) -> None:
        """Entra emits no ``email_verified`` at all.

        Treating absent as unverified would refuse every Entra login, which is
        the entire reason ``Verified`` is a tri-state rather than a bool. The
        setting name promises more than this and the docs now say so.
        """
        _check_email_verification(claims("a@b.test", Verified.UNKNOWN))

    def test_no_address_at_all_passes(self, settings) -> None:
        """A provider that sends no address cannot have lied about one.

        Refusing here would break any connection whose scopes exclude email.
        """
        _check_email_verification(claims(None, Verified.NO))

    def test_the_setting_turns_it_off(self, settings) -> None:
        settings.BASTION = {"IDENTITY": {"REQUIRE_VERIFIED_EMAIL": False}}
        _check_email_verification(claims("a@b.test", Verified.NO))

    def test_the_default_is_on(self, settings) -> None:
        """A deployment that never mentions IDENTITY still gets the check.

        It read as on and did nothing, so anything short of on-by-default would
        be a silent relaxation of what the docs already promised.
        """
        settings.BASTION = {"CONNECTIONS": {}}
        with pytest.raises(TokenError):
            _check_email_verification(claims("a@b.test", Verified.NO))

    def test_end_to_end_the_login_is_refused_and_nobody_is_provisioned(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        """The behaviour that was missing, at the level someone would hit it."""
        connection = wire(idp, transport, monkeypatch)
        response = login(client, connection, transport, idp, email_verified=False)

        assert response.status_code == 400
        assert SESSION_KEY not in client.session
        assert not User.objects.exists(), "an unverified address was provisioned"

    def test_the_refusal_is_audited_as_a_rejected_assertion(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        from bastion.audit.models import AuditEvent

        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp, email_verified=False)

        assert AuditEvent.objects.filter(event_type="auth.assertion.rejected").exists()


@pytest.fixture
def sso_configured(settings):
    settings.BASTION = {
        "CONNECTIONS": {"corp": {"issuer": "https://idp.example.test", "client_id": "cid"}},
        "ADMIN": {"require_mfa": True},
    }


@pytest.fixture
def staff_user():
    user = User.objects.create_user(username="staffer", email="staff@example.test")
    user.is_staff = True
    user.set_unusable_password()
    user.save()
    return user


class TestAdminRequiresMfa:
    def test_the_default_is_off(self, settings) -> None:
        """And the change from True is a fix, not a relaxation.

        It read as True and enforced nothing, so no deployment ever had admin
        MFA from this key. Defaulting it on now would lock out every deployment
        whose provider does not emit ``amr``, which is opt-in on several of
        them: a control that depends on a claim the provider may omit cannot
        fail closed by default without bricking the admin it protects.
        """
        from bastion.conf import get_setting

        settings.BASTION = {"CONNECTIONS": {}}
        assert get_setting("ADMIN")["require_mfa"] is False

    @pytest.mark.usefixtures("sso_configured")
    def test_a_staff_session_without_a_second_factor_is_refused(
        self, client: Client, staff_user
    ) -> None:
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        response = client.get("/admin/login/")

        assert response.status_code == 403

    @pytest.mark.usefixtures("sso_configured")
    def test_a_staff_session_with_one_is_let_through(self, client: Client, staff_user) -> None:
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        session = client.session
        session[SESSION_MFA_KEY] = True
        session.save()

        assert client.get("/admin/").status_code == 200

    @pytest.mark.usefixtures("sso_configured")
    def test_every_admin_url_is_gated_not_only_the_login(self, client: Client, staff_user) -> None:
        """Enforced in has_permission, which admin_view calls on every request.

        Checking only at sign-in would mean turning the setting on had no effect
        on the sessions that already exist, which is the opposite of what
        someone enabling an MFA requirement during an incident expects.
        """
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        response = client.get("/admin/bastion/federatedidentity/")

        assert response.status_code in (302, 403)
        assert b"Site administration" not in response.content

    @pytest.mark.usefixtures("sso_configured")
    def test_the_page_says_the_factor_is_missing_not_the_group(
        self, client: Client, staff_user
    ) -> None:
        """Naming the group here sends the person to a service desk that will
        add them to one and change nothing."""
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        body = client.get("/admin/login/").content

        assert b"second factor" in body
        assert b"membership of" not in body

    @pytest.mark.usefixtures("sso_configured")
    def test_the_refusal_is_audited(self, client: Client, staff_user) -> None:
        from bastion.audit.models import AuditEvent

        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        client.get("/admin/login/")

        event = AuditEvent.objects.filter(event_type="auth.mfa.missing").latest("chain_seq")
        assert event.outcome == "denied"
        assert event.is_privileged is True

    @pytest.mark.usefixtures("sso_configured")
    def test_a_non_staff_user_is_still_told_about_the_group(self, client: Client) -> None:
        """Narrow on purpose.

        Someone who is neither staff nor MFA-satisfied needs the group first,
        so the MFA wording would send them chasing the wrong thing.
        """
        user = User.objects.create_user(username="nobody", email="nobody@example.test")
        user.set_unusable_password()
        user.save()
        client.force_login(user, backend="bastion.backends.SSOBackend")

        body = client.get("/admin/login/").content
        assert b"second factor" not in body

    def test_it_is_off_unless_asked_for(self, client: Client, staff_user, settings) -> None:
        settings.BASTION = {
            "CONNECTIONS": {"corp": {"issuer": "https://idp.example.test", "client_id": "cid"}}
        }
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        assert client.get("/admin/").status_code == 200

    def test_a_real_login_records_whether_the_factor_was_there(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        """The session key has to be written by the login path, not only by
        tests that set it by hand."""
        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp, amr=["pwd", "mfa"])

        assert client.session[SESSION_MFA_KEY] is True

    def test_and_records_its_absence(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)

        assert client.session[SESSION_MFA_KEY] is False


class TestSuccessUrl:
    """``BASTION["SUCCESS_URL"]`` was declared, documented, and read by nothing.

    ``views.py`` used its own ``DEFAULT_SUCCESS_URL`` constant, so setting it
    changed where nobody landed. There was already a test asserting
    ``get_setting("SUCCESS_URL")`` returns an override, which passed throughout:
    it proved the settings machinery worked, not that anything called it. That
    is the shape of a test that gives false confidence, and the ones below assert
    the redirect instead.
    """

    def test_the_default_is_the_site_root(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        connection = wire(idp, transport, monkeypatch)
        response = login(client, connection, transport, idp)

        assert response.status_code == 302
        assert response["Location"] == "/"

    def test_a_configured_value_is_where_the_login_lands(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch, settings
    ) -> None:
        settings.BASTION = {"SUCCESS_URL": "/dashboard/"}
        connection = wire(idp, transport, monkeypatch)
        response = login(client, connection, transport, idp)

        assert response["Location"] == "/dashboard/"

    def test_an_explicit_next_still_wins(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch, settings
    ) -> None:
        """The setting is the fallback, not an override.

        Someone sent to a deep link has to land on it; SUCCESS_URL answers the
        case where nothing said where to go.
        """
        from urllib.parse import parse_qs, urlparse

        settings.BASTION = {"SUCCESS_URL": "/dashboard/"}
        connection = wire(idp, transport, monkeypatch)

        begun = client.get("/sso/login/?next=/reports/")
        state = parse_qs(urlparse(begun["Location"]).query)["state"][0]

        from tests.test_login_flow import finish

        response = finish(client, connection, transport, idp, state)
        assert response["Location"] == "/reports/"

    def test_a_hostile_next_falls_back_to_the_setting(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch, settings
    ) -> None:
        """begin_login discards an off-host ``next`` before it is ever stored.

        So the fallback is what a rejected one lands on, and it must be the
        configured value rather than the old hardcoded root.
        """
        from urllib.parse import parse_qs, urlparse

        settings.BASTION = {"SUCCESS_URL": "/dashboard/"}
        connection = wire(idp, transport, monkeypatch)

        begun = client.get("/sso/login/?next=https://evil.test/")
        state = parse_qs(urlparse(begun["Location"]).query)["state"][0]

        from tests.test_login_flow import finish

        response = finish(client, connection, transport, idp, state)
        assert response["Location"] == "/dashboard/"
