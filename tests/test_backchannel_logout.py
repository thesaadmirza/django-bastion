"""Back-channel logout, end to end through the real view.

The provider posts a signed logout token and the session it names stops
working. These drive Django's test client against the actual endpoint; the only
thing faked is the network.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from typing import Any
from unittest.mock import patch

import pytest
from django.contrib.auth import SESSION_KEY, get_user_model
from django.test import Client

from bastion.audit.events import Event
from bastion.audit.models import AuditEvent
from bastion.models import FederatedSession, SeenLogoutToken
from bastion.protocols.oidc.logout import BACKCHANNEL_LOGOUT_EVENT, MAX_AGE
from bastion.testing.harness import Harness, harness

pytestmark = pytest.mark.django_db

User = get_user_model()

URL = "/sso/backchannel-logout/"


def b64u_json(payload: Any) -> str:
    """A base64url segment, for building tokens that are broken on purpose."""
    raw = json.dumps(payload).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def logout_token(rig: Harness, **overrides: Any) -> str:
    """Mint a logout token the specification would call valid."""
    now = rig.idp.now or dt.datetime.now(tz=dt.UTC)
    claims: dict[str, Any] = {
        "iss": rig.idp.issuer,
        "aud": rig.idp.client_id,
        "iat": int(now.timestamp()),
        "jti": "logout-1",
        "sub": "subject-1",
        "sid": "session-1",
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    claims.update(overrides)
    return rig.idp.id_token_with({k: v for k, v in claims.items() if v is not None})


def sign_in(rig: Harness, client: Client, *, sid: str = "session-1") -> None:
    """Complete a real login, so there is a session to end."""
    rig.login(client, sub="subject-1", sid=sid)
    assert SESSION_KEY in client.session, "precondition: the login should have worked"


class TestTheSessionIndex:
    def test_a_login_records_the_provider_session(self) -> None:
        rig = harness()
        client = Client()
        with rig.installed():
            sign_in(rig, client)

        row = FederatedSession.objects.get()
        assert row.sid == "session-1"
        assert row.session_key == client.session.session_key

    def test_a_provider_that_sends_no_sid_still_gets_a_row(self) -> None:
        """sid is optional. Without one the session can still be ended by
        subject, which is what a sub-only logout token asks for."""
        rig = harness()
        client = Client()
        with rig.installed():
            rig.login(client, sub="subject-1")

        row = FederatedSession.objects.get()
        assert row.sid == ""

    def test_signing_out_drops_the_row(self) -> None:
        """Otherwise the table keeps one row per sign-out forever."""
        rig = harness()
        client = Client()
        with rig.installed():
            sign_in(rig, client)
            assert FederatedSession.objects.count() == 1
            client.post("/sso/logout/")

        assert FederatedSession.objects.count() == 0


class TestEndingSessions:
    def test_a_valid_token_ends_the_named_session(self) -> None:
        rig = harness()
        client = Client()
        with rig.installed():
            sign_in(rig, client)
            response = client.post(URL, {"logout_token": logout_token(rig)})

        assert response.status_code == 200
        assert SESSION_KEY not in client.session, "the session should be gone"
        assert FederatedSession.objects.count() == 0

    def test_a_subject_token_ends_every_session_that_identity_holds(self) -> None:
        """Two browsers, one person, one sub-only token."""
        rig = harness()
        first, second = Client(), Client()
        with rig.installed():
            sign_in(rig, first, sid="session-1")
            sign_in(rig, second, sid="session-2")
            assert FederatedSession.objects.count() == 2

            response = client_post(rig, first, sid=None)

        assert response.status_code == 200
        assert SESSION_KEY not in first.session
        assert SESSION_KEY not in second.session

    def test_a_sid_token_leaves_the_other_session_alone(self) -> None:
        """The narrower reading really is narrower."""
        rig = harness()
        first, second = Client(), Client()
        with rig.installed():
            sign_in(rig, first, sid="session-1")
            sign_in(rig, second, sid="session-2")

            response = client_post(rig, first, sid="session-1")

        assert response.status_code == 200
        assert SESSION_KEY not in first.session
        assert SESSION_KEY in second.session, "only the named session should end"

    def test_a_token_for_a_session_we_never_saw_still_succeeds(self) -> None:
        """Nothing to end is not a failure. The provider is telling us
        something ended; having already forgotten it is a fine outcome, and
        answering 400 would make the provider retry forever."""
        rig = harness()
        client = Client()
        with rig.installed():
            response = client.post(URL, {"logout_token": logout_token(rig, sid="unknown")})

        assert response.status_code == 200


def client_post(rig: Harness, client: Client, *, sid: str | None) -> Any:
    token = logout_token(rig, sid=sid)
    return client.post(URL, {"logout_token": token})


class TestRefusals:
    def _refused(self, rig: Harness, **overrides: Any) -> Any:
        client = Client()
        with rig.installed():
            return client.post(URL, {"logout_token": logout_token(rig, **overrides)})

    def test_a_replayed_token_is_refused(self) -> None:
        """Single use is what stops a captured token ending sessions forever."""
        rig = harness()
        client = Client()
        with rig.installed():
            sign_in(rig, client)
            token = logout_token(rig)
            first = client.post(URL, {"logout_token": token})
            second = client.post(URL, {"logout_token": token})

        assert first.status_code == 200
        assert second.status_code == 400

    def test_a_token_signed_by_the_wrong_key_is_refused(self) -> None:
        rig = harness()
        other = harness(identifier="other")
        client = Client()
        with rig.installed():
            forged = other.idp.id_token_with(
                {
                    "iss": rig.idp.issuer,
                    "aud": rig.idp.client_id,
                    "iat": int(dt.datetime.now(tz=dt.UTC).timestamp()),
                    "jti": "forged-1",
                    "sid": "session-1",
                    "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
                }
            )
            response = client.post(URL, {"logout_token": forged})

        assert response.status_code == 400

    def test_an_id_token_posted_here_is_refused(self) -> None:
        """The nonce rule, exercised the way it would actually be attacked:
        somebody captures an ID token and posts it at this endpoint hoping the
        two paths share a validator."""
        rig = harness()
        client = Client()
        with rig.installed():
            response = client.post(URL, {"logout_token": rig.idp.id_token()})

        assert response.status_code == 400

    def test_a_missing_token_is_refused(self) -> None:
        rig = harness()
        client = Client()
        with rig.installed():
            response = client.post(URL, {})
        assert response.status_code == 400

    def test_a_token_that_is_not_a_jws_is_refused(self) -> None:
        rig = harness()
        client = Client()
        with rig.installed():
            response = client.post(URL, {"logout_token": "not-a-token"})
        assert response.status_code == 400

    def test_an_unknown_issuer_is_refused(self) -> None:
        assert self._refused(harness(), iss="https://elsewhere.test").status_code == 400

    def test_an_expired_token_is_refused(self) -> None:
        rig = harness()
        old = dt.datetime.now(tz=dt.UTC) - MAX_AGE - dt.timedelta(minutes=5)
        assert self._refused(rig, iat=int(old.timestamp())).status_code == 400

    def test_get_is_not_allowed(self) -> None:
        rig = harness()
        client = Client()
        with rig.installed():
            assert client.get(URL).status_code == 405

    def test_a_refusal_says_nothing_about_which_check_failed(self) -> None:
        """An attacker probing the endpoint should not be able to tell a bad
        signature from a stale timestamp.

        Both tokens are posted at the *same* installed connection, which is the
        only way the two causes are comparable: minting under a second harness
        and installing that one too would verify the signature happily and
        compare two things that failed for the same reason.
        """
        rig = harness()
        other = harness(identifier="other")
        client = Client()
        old = dt.datetime.now(tz=dt.UTC) - MAX_AGE - dt.timedelta(minutes=5)

        with rig.installed():
            forged = other.idp.id_token_with(
                {
                    "iss": rig.idp.issuer,
                    "aud": rig.idp.client_id,
                    "iat": int(dt.datetime.now(tz=dt.UTC).timestamp()),
                    "jti": "forged-2",
                    "sid": "session-1",
                    "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
                }
            )
            bad_signature = client.post(URL, {"logout_token": forged})
            stale = client.post(URL, {"logout_token": logout_token(rig, iat=int(old.timestamp()))})

        assert bad_signature.status_code == stale.status_code == 400
        assert bad_signature.content == stale.content


class TestResponseShape:
    def test_success_is_not_cached(self) -> None:
        """The specification asks for no-store. @never_cache sets that and
        more, so the assertion is on the directive rather than the whole
        header."""
        rig = harness()
        client = Client()
        with rig.installed():
            sign_in(rig, client)
            response = client.post(URL, {"logout_token": logout_token(rig)})
        assert "no-store" in response["Cache-Control"]

    def test_failure_is_not_cached_either(self) -> None:
        rig = harness()
        client = Client()
        with rig.installed():
            response = client.post(URL, {"logout_token": "nope"})
        assert "no-store" in response["Cache-Control"]

    def test_no_csrf_token_is_required(self) -> None:
        """The provider has no cookie of ours and no way to get a CSRF token.
        The signature is what stands in for it."""
        rig = harness()
        client = Client(enforce_csrf_checks=True)
        with rig.installed():
            sign_in(rig, client)
            response = client.post(URL, {"logout_token": logout_token(rig)})
        assert response.status_code == 200


class TestAudit:
    def test_a_revocation_is_recorded_with_its_scope_and_count(self) -> None:
        rig = harness()
        client = Client()
        with rig.installed():
            sign_in(rig, client)
            client.post(URL, {"logout_token": logout_token(rig)})

        record = AuditEvent.objects.filter(event_type=Event.SESSION_REVOKED).get()
        assert record.context["scope"] == "sid"
        assert record.context["sessions_ended"] == 1

    def test_a_refused_token_is_recorded_too(self) -> None:
        """A rejected logout token is what an attempt to forge one looks
        like, so it is the record most worth having."""
        rig = harness()
        client = Client()
        with rig.installed():
            client.post(URL, {"logout_token": "nope"})

        assert AuditEvent.objects.filter(event_type=Event.ASSERTION_REJECTED).exists()


class TestRouting:
    def test_the_named_route_works(self) -> None:
        rig = harness()
        client = Client()
        with rig.installed():
            sign_in(rig, client)
            response = client.post(
                f"/sso/backchannel-logout/{rig.connection.identifier}/",
                {"logout_token": logout_token(rig)},
            )
        assert response.status_code == 200
        assert SESSION_KEY not in client.session

    def test_a_named_route_for_an_unknown_connection_is_refused(self) -> None:
        rig = harness()
        client = Client()
        with rig.installed():
            response = client.post(
                "/sso/backchannel-logout/nosuch/", {"logout_token": logout_token(rig)}
            )
        assert response.status_code == 400

    def test_a_named_route_with_no_token_is_refused(self) -> None:
        """The named route resolves without reading the token, so an empty one
        reaches the validator rather than being caught during routing. That is
        the only path to the emptiness check, and without this it looks dead.
        """
        rig = harness()
        client = Client()
        with rig.installed():
            response = client.post(f"/sso/backchannel-logout/{rig.connection.identifier}/", {})
        assert response.status_code == 400

    def test_no_configured_connections_is_refused(self) -> None:
        """Nothing to match the token against, so nothing to act on."""
        rig = harness()
        client = Client()
        with rig.installed(), patch("bastion.backchannel.all_connections", dict):
            response = client.post(URL, {"logout_token": logout_token(rig)})
        assert response.status_code == 400

    @pytest.mark.parametrize(
        ("token", "case"),
        [
            ("a.!!!not-base64!!!.c", "payload is not decodable"),
            (f"a.{b64u_json([1, 2, 3])}.c", "payload is not an object"),
            (f"a.{b64u_json({'sub': 'x'})}.c", "payload names no issuer"),
            (f"a.{b64u_json({'iss': 42})}.c", "issuer is not a string"),
            (f"a.{b64u_json({'iss': ''})}.c", "issuer is empty"),
        ],
    )
    def test_an_unroutable_token_is_refused(self, token: str, case: str) -> None:
        """Routing reads the issuer from an unverified payload, so every shape
        that read can fail on has to fail closed rather than raise."""
        rig = harness()
        client = Client()
        with rig.installed():
            response = client.post(URL, {"logout_token": token})
        assert response.status_code == 400, case


class TestFailingSafe:
    def test_a_login_survives_the_index_write_failing(self) -> None:
        """The index is a convenience for later. Somebody who authenticated
        correctly should not be turned away because it could not be written.
        """
        rig = harness()
        client = Client()
        with (
            rig.installed(),
            patch(
                "bastion.models.FederatedSession.objects.update_or_create",
                side_effect=RuntimeError("database is having a day"),
            ),
        ):
            rig.login(client, sub="subject-1", sid="session-1")

        assert SESSION_KEY in client.session, "the login should still have worked"
        assert FederatedSession.objects.count() == 0

    def test_a_session_store_failure_keeps_the_index_row(self) -> None:
        """The row is the only thing that will make anything try again, so a
        store that refused must not have its row dropped."""
        rig = harness()
        client = Client()
        with rig.installed():
            sign_in(rig, client)
            with patch(
                "bastion.sessions._store",
                return_value=_RefusingStore,
            ):
                response = client.post(URL, {"logout_token": logout_token(rig)})

        assert response.status_code == 200, "the token was valid; the store was not"
        assert FederatedSession.objects.count() == 1, "the row should survive"

    def test_the_audited_count_is_sessions_ended_not_rows_matched(self) -> None:
        rig = harness()
        client = Client()
        with rig.installed():
            sign_in(rig, client)
            with patch("bastion.sessions._store", return_value=_RefusingStore):
                client.post(URL, {"logout_token": logout_token(rig)})

        record = AuditEvent.objects.filter(event_type=Event.SESSION_REVOKED).get()
        assert record.context["sessions_ended"] == 0


class _RefusingStore:
    """A session store that cannot delete anything."""

    def __init__(self, session_key: str | None = None) -> None:
        self.session_key = session_key

    def delete(self, session_key: str | None = None) -> None:
        raise RuntimeError("session backend is unavailable")


class TestReplayTableHousekeeping:
    def test_expired_rows_are_purged(self) -> None:
        SeenLogoutToken.objects.create(
            issuer="https://idp.test",
            jti="old",
            expires_at=dt.datetime.now(tz=dt.UTC) - dt.timedelta(hours=1),
        )
        SeenLogoutToken.objects.create(
            issuer="https://idp.test",
            jti="current",
            expires_at=dt.datetime.now(tz=dt.UTC) + dt.timedelta(hours=1),
        )

        assert SeenLogoutToken.purge_expired() == 1
        assert [row.jti for row in SeenLogoutToken.objects.all()] == ["current"]

    def test_using_the_endpoint_purges_as_it_goes(self) -> None:
        """The table has to stay bounded without anyone running a command."""
        SeenLogoutToken.objects.create(
            issuer="https://idp.test",
            jti="old",
            expires_at=dt.datetime.now(tz=dt.UTC) - dt.timedelta(hours=1),
        )
        rig = harness()
        client = Client()
        with rig.installed():
            sign_in(rig, client)
            client.post(URL, {"logout_token": logout_token(rig)})

        assert not SeenLogoutToken.objects.filter(jti="old").exists()
