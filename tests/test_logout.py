"""RP-initiated logout.

The property under test is that **the local session always dies and the
provider session dies whenever the provider allows it**. Those are two separate
outcomes and the difference is what the person is told, so most of what follows
asserts on which of the two happened rather than only on a status code.

The failure this exists to prevent: clearing the Django session, returning
people to the admin, and having the provider hand back a fresh authorization
code with no prompt. The person pressed Log out and is still signed in.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import SESSION_KEY, get_user_model
from django.test import Client

from bastion import connections as connections_module
from bastion.connections import Connection
from bastion.protocols.oidc.transaction import build_end_session_url
from bastion.views import SESSION_CONNECTION_KEY, SESSION_ID_TOKEN_KEY
from tests.idp.provider import FakeIdP
from tests.idp.transport import FakeTransport
from tests.test_login_flow import login, make_connection

pytestmark = pytest.mark.django_db

User = get_user_model()


@pytest.fixture
def transport(idp: FakeIdP) -> FakeTransport:
    return FakeTransport(idp=idp)


def wire(idp: FakeIdP, transport: FakeTransport, monkeypatch, **overrides: Any) -> Connection:
    built = make_connection(idp, transport, **overrides)
    monkeypatch.setattr(connections_module, "get_connection", lambda name=None: built)
    monkeypatch.setattr("bastion.views.get_connection", lambda name=None: built)
    monkeypatch.setattr("bastion.views.get_setting", lambda key: {"corp": {}})
    return built


def query_of(location: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(location).query)


class TestTheUrlBuilder:
    """Unit level, so the parameter rules are pinned without a session."""

    def test_client_id_is_always_sent(self) -> None:
        url = build_end_session_url("https://idp.test/logout", client_id="cid")
        assert query_of(url)["client_id"] == ["cid"]

    def test_optional_parameters_are_omitted_rather_than_blank(self) -> None:
        query = query_of(build_end_session_url("https://idp.test/logout", client_id="cid"))
        assert "id_token_hint" not in query
        assert "post_logout_redirect_uri" not in query

    def test_an_endpoint_with_an_existing_query_is_appended_to(self) -> None:
        url = build_end_session_url("https://idp.test/logout?tenant=a", client_id="cid")
        assert query_of(url)["tenant"] == ["a"]
        assert query_of(url)["client_id"] == ["cid"]

    def test_the_hint_and_the_return_uri_are_passed_through(self) -> None:
        url = build_end_session_url(
            "https://idp.test/logout",
            client_id="cid",
            id_token_hint="the.id.token",
            post_logout_redirect_uri="https://app.test/done/",
        )
        query = query_of(url)
        assert query["id_token_hint"] == ["the.id.token"]
        assert query["post_logout_redirect_uri"] == ["https://app.test/done/"]


class TestMethod:
    def test_get_is_refused(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        """A GET that signs people out is reachable from any third-party page.

        On this route it would also bounce the browser at the provider's logout
        endpoint, so the answer is 405 and not a redirect.
        """
        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)

        assert client.get("/sso/logout/").status_code == 405
        assert SESSION_KEY in client.session, "a refused GET must not sign anyone out"


class TestTheLocalSessionAlwaysDies:
    def test_the_session_is_cleared(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)
        assert SESSION_KEY in client.session

        client.post("/sso/logout/")

        assert SESSION_KEY not in client.session

    def test_an_unreachable_provider_still_signs_the_person_out_here(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        """The local sign-out must not depend on the provider being up.

        Reversing the order is the tempting mistake: it makes the happy path
        read better and it means a provider outage leaves administrators signed
        in to a system they were trying to leave.
        """
        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)

        from bastion.exceptions import DiscoveryError

        def refuse() -> None:
            raise DiscoveryError("provider is down")

        monkeypatch.setattr(connection, "metadata", refuse)
        response = client.post("/sso/logout/")

        assert SESSION_KEY not in client.session
        assert response.status_code == 200
        assert b"still signed in with your identity provider" in response.content

    def test_a_connection_removed_since_login_still_signs_the_person_out(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)

        from bastion.exceptions import ConfigurationError

        def gone(name: str | None = None) -> Connection:
            raise ConfigurationError("no connection named 'corp'")

        monkeypatch.setattr("bastion.views.get_connection", gone)
        response = client.post("/sso/logout/")

        assert SESSION_KEY not in client.session
        assert response.status_code == 200


class TestTheProviderSession:
    def test_the_browser_is_sent_to_the_end_session_endpoint(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)

        response = client.post("/sso/logout/")

        assert response.status_code == 302
        assert response["Location"].startswith(f"{idp.issuer}/logout")
        assert query_of(response["Location"])["client_id"] == [idp.client_id]

    def test_a_provider_with_no_end_session_endpoint_gets_a_page_that_says_so(
        self, client: Client, google_idp: FakeIdP, monkeypatch
    ) -> None:
        """Google publishes none, and the person has to be told.

        Redirecting them to the home page here would be the same lie the whole
        change exists to remove: they would believe they had signed out.
        """
        transport = FakeTransport(idp=google_idp)
        connection = wire(google_idp, transport, monkeypatch, provider="google")
        login(client, connection, transport, google_idp, email_verified=True)

        response = client.post("/sso/logout/")

        assert response.status_code == 200
        assert b"still signed in with your identity provider" in response.content

    def test_the_referrer_policy_is_set_on_both_outcomes(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)
        assert client.post("/sso/logout/")["Referrer-Policy"] == "no-referrer"


class TestTheIdTokenHint:
    """Off by default, because it keeps a credential in the session store."""

    def test_nothing_is_stored_by_default(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)

        assert client.session[SESSION_CONNECTION_KEY] == "corp"
        assert SESSION_ID_TOKEN_KEY not in client.session

        assert "id_token_hint" not in query_of(client.post("/sso/logout/")["Location"])

    def test_store_id_token_puts_the_hint_on_the_logout_request(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        """Without the hint the provider may ask for confirmation.

        Keycloak does, and a logout a person has to confirm is a logout some
        of them abandon on the page that says "are you sure".
        """
        connection = wire(idp, transport, monkeypatch, store_id_token=True)
        login(client, connection, transport, idp)

        stored = client.session[SESSION_ID_TOKEN_KEY]
        assert stored.count(".") == 2, "a compact JWS, not the decoded claims"

        assert query_of(client.post("/sso/logout/")["Location"])["id_token_hint"] == [stored]

    def test_the_hint_does_not_survive_the_logout(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        connection = wire(idp, transport, monkeypatch, store_id_token=True)
        login(client, connection, transport, idp)
        client.post("/sso/logout/")

        assert SESSION_ID_TOKEN_KEY not in client.session

    def test_the_result_never_prints_the_token(self) -> None:
        """LoginResult reaches tracebacks and debug pages. It must be inert."""
        from bastion.claims import IdentityClaims
        from bastion.flows import LoginResult
        from bastion.protocols.oidc.transaction import MemoryTransactionStore, start_transaction

        result = LoginResult(
            identity=IdentityClaims(issuer="https://i.test", subject="s", subject_source="sub"),
            transaction=start_transaction(connection="corp", store=MemoryTransactionStore()),
            id_token="header.secret-payload.signature",
        )
        assert "secret-payload" not in repr(result)
        assert "[redacted]" in repr(result)


class TestThePostLogoutRedirect:
    def test_it_is_absent_unless_configured(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        """An unregistered value is refused by the provider outright.

        Keycloak answers "Invalid redirect uri" and nobody gets logged out, so
        sending nothing is the safer default and the deployment opts in once it
        has registered a value.
        """
        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)

        location = client.post("/sso/logout/")["Location"]
        assert "post_logout_redirect_uri" not in query_of(location)

    def test_a_configured_value_is_sent(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        connection = wire(
            idp, transport, monkeypatch, post_logout_redirect_uri="https://app.test/bye/"
        )
        login(client, connection, transport, idp)

        location = client.post("/sso/logout/")["Location"]
        assert query_of(location)["post_logout_redirect_uri"] == ["https://app.test/bye/"]


class TestAudit:
    def test_a_logout_is_recorded(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        from bastion.audit.models import AuditEvent

        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)
        client.post("/sso/logout/")

        event = AuditEvent.objects.filter(event_type="auth.logout").latest("chain_seq")
        assert event.outcome == "success"
        assert event.connection == "corp"

    def test_rp_initiated_is_true_when_the_provider_was_actually_reached(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        from bastion.audit.models import AuditEvent

        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)
        client.post("/sso/logout/")

        event = AuditEvent.objects.filter(event_type="auth.logout").latest("chain_seq")
        assert event.context["rp_initiated"] is True

    def test_rp_initiated_is_false_when_only_the_local_session_went(
        self, client: Client, google_idp: FakeIdP, monkeypatch
    ) -> None:
        """An investigation into "they said they logged out" needs this field.

        Without it the log cannot distinguish a full sign-out from a local one,
        which is the difference between an account still being reachable from
        that browser and not. The tempting implementation reads the field off
        the session rather than off the outcome, which reports a clean sign-out
        for a provider that was never contacted.
        """
        from bastion.audit.models import AuditEvent

        transport = FakeTransport(idp=google_idp)
        connection = wire(google_idp, transport, monkeypatch, provider="google")
        login(client, connection, transport, google_idp, email_verified=True)
        client.post("/sso/logout/")

        event = AuditEvent.objects.filter(event_type="auth.logout").latest("chain_seq")
        assert event.context["rp_initiated"] is False
        assert event.connection == "corp", "the connection is still recorded"

    def test_rp_initiated_is_false_when_the_provider_was_unreachable(
        self, client: Client, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        from bastion.audit.models import AuditEvent
        from bastion.exceptions import DiscoveryError

        connection = wire(idp, transport, monkeypatch)
        login(client, connection, transport, idp)

        def refuse() -> None:
            raise DiscoveryError("provider is down")

        monkeypatch.setattr(connection, "metadata", refuse)
        client.post("/sso/logout/")

        event = AuditEvent.objects.filter(event_type="auth.logout").latest("chain_seq")
        assert event.context["rp_initiated"] is False
