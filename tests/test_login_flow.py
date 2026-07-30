"""End-to-end login, from the authorization request to an established session.

Everything below drives the real views through Django's test client. The only
thing faked is the network.
"""

from __future__ import annotations

import datetime as dt
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import SESSION_KEY, get_user_model
from django.test import Client

from bastion import connections as connections_module
from bastion.connections import Connection
from bastion.models import FederatedIdentity
from tests.idp.provider import FakeIdP
from tests.idp.transport import FakeTransport

pytestmark = pytest.mark.django_db

User = get_user_model()


@pytest.fixture
def transport(idp: FakeIdP) -> FakeTransport:
    return FakeTransport(idp=idp)


def make_connection(idp: FakeIdP, transport: FakeTransport, **overrides: Any) -> Connection:
    from bastion.protocols.oidc.transaction import MemoryTransactionStore

    # The provider mints at a fixed timestamp so that unit tests are
    # deterministic. The flow validates against wall-clock time, as it must, so
    # for an end-to-end run the two have to agree.
    idp.now = dt.datetime.now(tz=dt.UTC)

    defaults: dict[str, Any] = {
        "identifier": "corp",
        "issuer": idp.issuer,
        "client_id": idp.client_id,
        "client_secret": "shh",
        "provider": idp.vendor if idp.vendor != "generic" else "generic",
        "transport": transport,
        "transactions": MemoryTransactionStore(),
    }
    defaults.update(overrides)
    return Connection(**defaults)


@pytest.fixture
def connection(idp: FakeIdP, transport: FakeTransport, monkeypatch) -> Connection:
    built = make_connection(idp, transport)
    monkeypatch.setattr(connections_module, "get_connection", lambda name=None: built)
    monkeypatch.setattr("bastion.views.get_connection", lambda name=None: built)
    monkeypatch.setattr("bastion.views.get_setting", lambda key: {"corp": {}})
    return built


def start(client: Client) -> str:
    """Hit the begin view and return the state parameter it minted."""
    response = client.get("/sso/login/")
    assert response.status_code == 302
    return parse_qs(urlparse(response["Location"]).query)["state"][0]


def finish(
    client: Client,
    connection: Connection,
    transport: FakeTransport,
    idp: FakeIdP,
    state: str,
    **claim_overrides: Any,
):
    """Complete the callback with an ID token bound to the live nonce."""
    # The transaction is consumed by the view, so read the nonce first.
    record = connection.transactions._records[state]  # type: ignore[attr-defined]
    claims = dict(idp.base_claims(nonce=record.nonce, **claim_overrides))
    transport.token_responses = [
        (200, {"id_token": idp.id_token_with(claims), "token_type": "Bearer"})
    ]
    return client.get(f"/sso/callback/?state={state}&code=the-code")


def login(client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP, **kw):
    return finish(client, connection, transport, idp, start(client), **kw)


class TestBackendRefusals:
    """Anything the auth backend raises has to reach a rendered page.

    The try/except in the callback wrapped only complete_login, so provisioning
    and resolution ran outside every handler. A username collision surfaced as
    an unhandled IntegrityError and a 500, which is both a bad page and a
    stack trace on a request an attacker can trigger.
    """

    def test_a_provisioning_conflict_renders_rather_than_500s(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        from django.contrib.auth import get_user_model

        from bastion.claims import IdentityClaims

        # Take the username the incoming subject would be provisioned under.
        claims = IdentityClaims(
            issuer=connection.issuer,
            subject=idp.base_claims()["sub"],
            subject_source="sub",
        )
        get_user_model().objects.create_user(username=claims.subject[:150])

        response = login(client, connection, transport, idp)

        assert response.status_code != 500, "a collision must not reach the 500 handler"
        assert response.status_code in (400, 403)
        assert SESSION_KEY not in client.session

    def test_the_refusal_is_audited(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        from django.contrib.auth import get_user_model

        from bastion.audit.models import AuditEvent

        get_user_model().objects.create_user(username=idp.base_claims()["sub"][:150])
        login(client, connection, transport, idp)

        assert AuditEvent.objects.filter(event_type="auth.login.failed").exists()

    def test_the_page_does_not_leak_the_reason(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        """Same policy as every other pre-session failure: one body, one code,
        and a reference to correlate with the log."""
        from django.contrib.auth import get_user_model

        get_user_model().objects.create_user(username=idp.base_claims()["sub"][:150])
        body = login(client, connection, transport, idp).content.decode().lower()

        assert "integrityerror" not in body
        assert "provisioningconflict" not in body
        assert "traceback" not in body


class TestHappyPath:
    def test_a_full_round_trip_establishes_a_session(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        response = login(client, connection, transport, idp)
        assert response.status_code == 302
        assert SESSION_KEY in client.session

    def test_the_authorization_request_carries_pkce(
        self, client: Client, connection: Connection
    ) -> None:
        response = client.get("/sso/login/")
        params = parse_qs(urlparse(response["Location"]).query)
        assert params["code_challenge_method"] == ["S256"]
        assert params["code_challenge"]

    def test_a_user_is_provisioned(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        login(client, connection, transport, idp)
        user = User.objects.get()
        assert user.email == "test.person@example.test"

    def test_the_provisioned_user_has_no_usable_password(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        """An account reachable with a password is an account that bypasses
        the identity provider."""
        login(client, connection, transport, idp)
        assert User.objects.get().has_usable_password() is False

    def test_the_identity_is_recorded(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        login(client, connection, transport, idp)
        identity = FederatedIdentity.objects.get()
        assert identity.issuer == idp.issuer
        assert identity.subject == "user-0001"
        assert identity.subject_source == "sub"

    def test_a_second_login_reuses_the_identity(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        login(client, connection, transport, idp)
        login(client, connection, transport, idp)
        assert User.objects.count() == 1
        assert FederatedIdentity.objects.count() == 1


class TestSessionHandling:
    def test_pre_authentication_session_data_does_not_survive(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        """auth.login only cycles the key when SESSION_KEY is absent, and
        cycle_key keeps the data either way. The flush is what guarantees
        nothing crosses the privilege transition."""
        session = client.session
        session["something_from_before"] = "leaked"
        session.save()

        login(client, connection, transport, idp)
        assert "something_from_before" not in client.session

    def test_the_session_key_changes(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        state = start(client)
        before = client.session.session_key
        finish(client, connection, transport, idp, state)
        assert client.session.session_key != before

    def test_transaction_state_is_not_left_in_the_session(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        login(client, connection, transport, idp)
        assert not any("nonce" in str(k) or "verifier" in str(k) for k in client.session.keys())


class TestFailureHandling:
    def test_a_replayed_state_fails(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        state = start(client)
        record = connection.transactions._records[state]  # type: ignore[attr-defined]
        claims = dict(idp.base_claims(nonce=record.nonce))
        token = idp.id_token_with(claims)

        transport.token_responses = [(200, {"id_token": token})]
        assert client.get(f"/sso/callback/?state={state}&code=c").status_code == 302

        transport.token_responses = [(200, {"id_token": token})]
        assert client.get(f"/sso/callback/?state={state}&code=c").status_code == 400

    def test_an_unknown_state_fails(self, client: Client, connection: Connection) -> None:
        assert client.get("/sso/callback/?state=made-up&code=c").status_code == 400

    def test_a_missing_code_fails(self, client: Client, connection: Connection) -> None:
        state = start(client)
        assert client.get(f"/sso/callback/?state={state}").status_code == 400

    def test_a_provider_error_fails(self, client: Client, connection: Connection) -> None:
        state = start(client)
        response = client.get(f"/sso/callback/?state={state}&error=access_denied")
        assert response.status_code == 400

    def test_a_mismatched_callback_issuer_fails(
        self, client: Client, connection: Connection
    ) -> None:
        """IdP mix-up: a callback carrying another provider's issuer."""
        state = start(client)
        response = client.get(f"/sso/callback/?state={state}&code=c&iss=https://attacker.test")
        assert response.status_code == 400

    def test_a_wrong_nonce_fails(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        state = start(client)
        claims = dict(idp.base_claims(nonce="not-the-transaction-nonce"))
        transport.token_responses = [(200, {"id_token": idp.id_token_with(claims)})]
        assert client.get(f"/sso/callback/?state={state}&code=c").status_code == 400

    def test_every_pre_auth_failure_renders_the_same_body(
        self, client: Client, connection: Connection, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        """Varying the page by cause tells whoever is probing which of their
        guesses was closer."""
        unknown = client.get("/sso/callback/?state=nope&code=c")

        state = start(client)
        no_code = client.get(f"/sso/callback/?state={state}")

        state = start(client)
        claims = dict(idp.base_claims(nonce="wrong"))
        transport.token_responses = [(200, {"id_token": idp.id_token_with(claims)})]
        bad_nonce = client.get(f"/sso/callback/?state={state}&code=c")

        bodies = {_without_reference(r.content) for r in (unknown, no_code, bad_nonce)}
        statuses = {r.status_code for r in (unknown, no_code, bad_nonce)}
        assert len(bodies) == 1
        assert statuses == {400}

    def test_the_failure_page_carries_no_referrer_policy(
        self, client: Client, connection: Connection
    ) -> None:
        response = client.get("/sso/callback/?state=nope&code=c")
        assert response["Referrer-Policy"] == "no-referrer"


def _without_reference(body: bytes) -> bytes:
    """Strip the correlation id, which is random per request by design."""
    import re

    return re.sub(rb"[0-9A-F]{4}-[0-9A-F]{4}", b"REF", body)


class TestPrivilegeMapping:
    def test_staff_group_grants_staff(
        self, client: Client, transport: FakeTransport, idp: FakeIdP, monkeypatch
    ) -> None:
        built = make_connection(idp, transport, staff_groups=("django-staff",))
        monkeypatch.setattr("bastion.views.get_connection", lambda name=None: built)
        monkeypatch.setattr("bastion.views.get_setting", lambda key: {"corp": {}})

        login(client, built, transport, idp, groups=["django-staff"])
        assert User.objects.get().is_staff is True

    def test_superuser_is_revoked_when_the_group_goes_away(
        self, client: Client, transport: FakeTransport, idp: FakeIdP, monkeypatch
    ) -> None:
        """Two-way, unlike is_staff. A revoked superuser must lose it at once."""
        built = make_connection(idp, transport, superuser_groups=("django-admins",))
        monkeypatch.setattr("bastion.views.get_connection", lambda name=None: built)
        monkeypatch.setattr("bastion.views.get_setting", lambda key: {"corp": {}})

        login(client, built, transport, idp, groups=["django-admins"])
        assert User.objects.get().is_superuser is True

        login(client, built, transport, idp, groups=[])
        assert User.objects.get().is_superuser is False

    def test_staff_is_promote_only(
        self, client: Client, transport: FakeTransport, idp: FakeIdP, monkeypatch
    ) -> None:
        """An identity provider hiccup must not lock every administrator out
        of the admin."""
        built = make_connection(idp, transport, staff_groups=("django-staff",))
        monkeypatch.setattr("bastion.views.get_connection", lambda name=None: built)
        monkeypatch.setattr("bastion.views.get_setting", lambda key: {"corp": {}})

        login(client, built, transport, idp, groups=["django-staff"])
        login(client, built, transport, idp, groups=[])
        assert User.objects.get().is_staff is True


class TestEntra:
    @pytest.fixture
    def entra_connection(self, entra_idp: FakeIdP, monkeypatch) -> Connection:
        transport = FakeTransport(idp=entra_idp)
        built = make_connection(entra_idp, transport, provider="entra")
        monkeypatch.setattr("bastion.views.get_connection", lambda name=None: built)
        monkeypatch.setattr("bastion.views.get_setting", lambda key: {"corp": {}})
        built.transport = transport
        return built

    def test_the_identity_is_keyed_on_oid(
        self, client: Client, entra_connection: Connection, entra_idp: FakeIdP
    ) -> None:
        transport = entra_connection.transport  # type: ignore[assignment]
        login(client, entra_connection, transport, entra_idp, subject="alice")
        identity = FederatedIdentity.objects.get()
        assert identity.subject == "oid-alice"
        assert identity.subject_source == "oid"

    def test_a_pairwise_sub_change_does_not_create_a_second_account(
        self, client: Client, entra_connection: Connection, entra_idp: FakeIdP
    ) -> None:
        """Entra mints a different sub per application registration. Keyed on
        oid, the same person stays one account."""
        transport = entra_connection.transport  # type: ignore[assignment]
        login(client, entra_connection, transport, entra_idp, subject="alice")
        login(client, entra_connection, transport, entra_idp, subject="alice")
        assert User.objects.count() == 1

    def test_group_overage_blocks_privilege_escalation(
        self, client: Client, entra_idp: FakeIdP, monkeypatch
    ) -> None:
        transport = FakeTransport(idp=entra_idp)
        built = make_connection(
            entra_idp, transport, provider="entra", staff_groups=("django-staff",)
        )
        monkeypatch.setattr("bastion.views.get_connection", lambda name=None: built)
        monkeypatch.setattr("bastion.views.get_setting", lambda key: {"corp": {}})

        state = start(client)
        record = built.transactions._records[state]  # type: ignore[attr-defined]
        claims = dict(entra_idp.with_group_overage(nonce=record.nonce))
        transport.token_responses = [(200, {"id_token": entra_idp.id_token_with(claims)})]

        response = client.get(f"/sso/callback/?state={state}&code=c")
        assert response.status_code == 302
        assert User.objects.get().is_staff is False
