"""Paths the feature tests did not reach.

Written after a coverage run, and grouped by why each was missed rather than by
module. Most are error branches, which is the usual shape: the happy path gets
exercised by everything and the refusals get exercised by nothing.
"""

from __future__ import annotations

from io import StringIO
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client

from bastion.breakglass.models import BreakGlassAccount
from bastion.conf import DEFAULTS, dynamic_setting, get_setting
from bastion.connections import Connection
from bastion.diagnostics import Status, check_connection
from bastion.exceptions import ConfigurationError
from bastion.protocols.oidc.transaction import MemoryTransactionStore
from tests.idp.provider import FakeIdP
from tests.idp.transport import FakeTransport
from tests.test_login_flow import only_connections

User = get_user_model()


# --------------------------------------------------------------------------- #
# Settings resolution
# --------------------------------------------------------------------------- #


class TestDynamicSetting:
    """The descriptor is public API and was, until now, untested.

    It exists so an auth backend can resolve configuration lazily rather than
    in ``__init__``, which Django calls on every permission check. Shipping the
    mechanism without exercising it would have been worse than not having it.
    """

    def test_it_reads_through_to_the_setting(self) -> None:
        class Holder:
            IDENTITY = dynamic_setting[dict]()

        assert Holder().IDENTITY == get_setting("IDENTITY")

    def test_it_uses_a_default_when_given(self) -> None:
        class Holder:
            NOT_A_REAL_SETTING = dynamic_setting[str]("fallback")

        assert Holder().NOT_A_REAL_SETTING == "fallback"

    def test_it_is_read_only(self) -> None:
        """A settings value that can be assigned at runtime is one that will
        be assigned at runtime, in a request handler, by accident."""

        class Holder:
            IDENTITY = dynamic_setting[dict]()

        with pytest.raises(AttributeError, match="read-only"):
            Holder().IDENTITY = {}

    def test_accessing_it_on_the_class_returns_the_descriptor(self) -> None:
        class Holder:
            IDENTITY = dynamic_setting[dict]()

        assert isinstance(Holder.IDENTITY, dynamic_setting)


class TestGetSetting:
    def test_an_unknown_setting_without_a_default_raises(self) -> None:
        with pytest.raises(AttributeError):
            get_setting("NOT_A_SETTING")

    def test_an_unknown_setting_with_a_default_returns_it(self) -> None:
        assert get_setting("NOT_A_SETTING", "fallback") == "fallback"

    def test_a_scalar_override_replaces_rather_than_merges(self, settings) -> None:
        settings.BASTION = {"SUCCESS_URL": "/elsewhere/"}
        assert get_setting("SUCCESS_URL") == "/elsewhere/"

    def test_every_default_is_reachable(self) -> None:
        for name in DEFAULTS:
            assert get_setting(name) is not None


# --------------------------------------------------------------------------- #
# View error branches
# --------------------------------------------------------------------------- #


@pytest.mark.django_db
class TestConnectionResolution:
    def test_no_connections_is_a_configuration_error(self, client: Client, settings) -> None:
        settings.BASTION = {"CONNECTIONS": {}}
        with pytest.raises(ConfigurationError, match="no connections"):
            client.get("/sso/login/")

    def test_several_connections_without_a_name_is_an_error(self, client: Client, settings) -> None:
        settings.BASTION = {
            "CONNECTIONS": {
                "a": {"issuer": "https://a.test", "client_id": "x"},
                "b": {"issuer": "https://b.test", "client_id": "y"},
            }
        }
        with pytest.raises(ConfigurationError, match="must name one"):
            client.get("/sso/login/")

    def test_an_unreachable_provider_returns_502_not_500(self, client: Client, settings) -> None:
        """A provider being down is not our bug, and should not look like one."""
        settings.BASTION = {
            "CONNECTIONS": {"corp": {"issuer": "https://nowhere.invalid", "client_id": "x"}}
        }
        assert client.get("/sso/login/").status_code == 502


@pytest.mark.django_db
class TestGroupMatchRequirement:
    """``require_group_match`` turns an authenticated-but-unprivileged login
    into a refusal with a page that says something useful."""

    @pytest.fixture
    def strict_connection(self, idp: FakeIdP, monkeypatch) -> Connection:
        transport = FakeTransport(idp=idp)
        import datetime as dt

        idp.now = dt.datetime.now(tz=dt.UTC)
        built = Connection(
            identifier="corp",
            issuer=idp.issuer,
            client_id=idp.client_id,
            client_secret="shh",
            transport=transport,
            transactions=MemoryTransactionStore(),
            staff_groups=("django-staff",),
            require_group_match=True,
        )
        monkeypatch.setattr("bastion.views.get_connection", lambda name=None: built)
        monkeypatch.setattr("bastion.views.get_setting", only_connections)
        built.transport = transport
        return built

    def _login(self, client: Client, connection: Connection, idp: FakeIdP, groups: list[str]):
        response = client.get("/sso/login/")
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(response["Location"]).query)["state"][0]
        record = connection.transactions._records[state]  # type: ignore[attr-defined]
        claims = dict(idp.base_claims(nonce=record.nonce, groups=groups))
        connection.transport.token_responses = [  # type: ignore[attr-defined]
            (200, {"id_token": idp.id_token_with(claims)})
        ]
        return client.get(f"/sso/callback/?state={state}&code=c")

    def test_a_matching_group_signs_in(
        self, client: Client, strict_connection: Connection, idp: FakeIdP
    ) -> None:
        response = self._login(client, strict_connection, idp, ["django-staff"])
        assert response.status_code == 302

    def test_no_matching_group_is_refused(
        self, client: Client, strict_connection: Connection, idp: FakeIdP
    ) -> None:
        response = self._login(client, strict_connection, idp, ["unrelated"])
        assert response.status_code == 403

    def test_the_refusal_names_the_group_required(
        self, client: Client, strict_connection: Connection, idp: FakeIdP
    ) -> None:
        response = self._login(client, strict_connection, idp, ["unrelated"])
        assert b"django-staff" in response.content

    def test_the_refusal_names_the_account_used(
        self, client: Client, strict_connection: Connection, idp: FakeIdP
    ) -> None:
        response = self._login(client, strict_connection, idp, ["unrelated"])
        assert b"test.person@example.test" in response.content

    def test_no_session_is_established_on_refusal(
        self, client: Client, strict_connection: Connection, idp: FakeIdP
    ) -> None:
        """Authenticated is not signed in. A refused login must not leave a
        usable session behind."""
        self._login(client, strict_connection, idp, ["unrelated"])
        assert "_auth_user_id" not in client.session


# --------------------------------------------------------------------------- #
# Diagnostics branches
# --------------------------------------------------------------------------- #


@pytest.mark.django_db
class TestDiagnosticsBranches:
    def test_a_public_client_warns_about_the_missing_secret(self, idp: FakeIdP) -> None:
        connection = Connection(
            identifier="corp",
            issuer=idp.issuer,
            client_id=idp.client_id,
            transport=FakeTransport(idp=idp),
            transactions=MemoryTransactionStore(),
        )
        report = check_connection(connection, offline=True)
        found = {r.name: r.status for r in report.results}
        assert found["client authentication"] is Status.WARN

    def test_a_provider_advertising_no_algorithms_warns(self, idp: FakeIdP) -> None:
        transport = FakeTransport(idp=idp)
        document = dict(idp.discovery_document())
        document.pop("id_token_signing_alg_values_supported")
        transport.discovery_override = document

        connection = Connection(
            identifier="corp",
            issuer=idp.issuer,
            client_id=idp.client_id,
            client_secret="x",
            transport=transport,
            transactions=MemoryTransactionStore(),
        )
        found = {r.name: r.status for r in check_connection(connection).results}
        assert found["signing algorithms"] is Status.WARN

    def test_the_clock_check_is_skipped_without_transport_support(self, idp: FakeIdP) -> None:
        connection = Connection(
            identifier="corp",
            issuer=idp.issuer,
            client_id=idp.client_id,
            client_secret="x",
            transport=FakeTransport(idp=idp),
            transactions=MemoryTransactionStore(),
        )
        found = {r.name: r.status for r in check_connection(connection).results}
        assert found["clock skew"] is Status.INFO

    def test_an_unreachable_key_set_fails(self, idp: FakeIdP) -> None:
        """Discovery can succeed while the key set is unreachable — different
        host, different failure. Every login fails until it is fixed."""
        transport = FakeTransport(idp=idp)
        document = dict(idp.discovery_document())
        document["jwks_uri"] = "https://idp.example.test/nothing-served-here"
        transport.discovery_override = document

        connection = Connection(
            identifier="corp",
            issuer=idp.issuer,
            client_id=idp.client_id,
            client_secret="x",
            transport=transport,
            transactions=MemoryTransactionStore(),
        )
        report = check_connection(connection)
        found = {r.name: r.status for r in report.results}
        assert found["signing keys"] is Status.FAIL
        assert report.failed

    @pytest.mark.parametrize(
        ("offset_seconds", "expected"),
        [(0, Status.OK), (45, Status.WARN), (600, Status.FAIL)],
        ids=["in-sync", "drifting", "broken"],
    )
    def test_clock_skew_is_graded(
        self, idp: FakeIdP, offset_seconds: int, expected: Status
    ) -> None:
        """Skew produces the least informative failure in the flow: a token
        that verifies perfectly and is then rejected as expired."""
        import datetime as dt

        class ClockedTransport(FakeTransport):
            def server_time(self, url: str) -> dt.datetime:
                return dt.datetime.now(tz=dt.UTC) + dt.timedelta(seconds=offset_seconds)

        connection = Connection(
            identifier="corp",
            issuer=idp.issuer,
            client_id=idp.client_id,
            client_secret="x",
            transport=ClockedTransport(idp=idp),
            transactions=MemoryTransactionStore(),
        )
        found = {r.name: r.status for r in check_connection(connection).results}
        assert found["clock skew"] is expected

    def test_a_transport_returning_no_clock_is_tolerated(self, idp: FakeIdP) -> None:
        class SilentClock(FakeTransport):
            def server_time(self, url: str) -> None:
                return None

        connection = Connection(
            identifier="corp",
            issuer=idp.issuer,
            client_id=idp.client_id,
            client_secret="x",
            transport=SilentClock(idp=idp),
            transactions=MemoryTransactionStore(),
        )
        found = {r.name: r.status for r in check_connection(connection).results}
        assert found["clock skew"] is Status.INFO


@pytest.mark.django_db
class TestBreakGlassDiagnostics:
    @pytest.fixture
    def enabled(self, settings):
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["bastion.breakglass.service.log_only_sink"],
            }
        }

    def test_a_single_account_warns(self, enabled) -> None:
        from bastion.diagnostics import check_project

        user = User.objects.create_user(username="one", password="x")
        BreakGlassAccount.objects.create(user=user, reason="r")
        found = {r.name: r.status for r in check_project().results}
        assert found["break-glass accounts"] is Status.WARN

    def test_two_accounts_pass(self, enabled) -> None:
        from django.utils import timezone

        from bastion.diagnostics import check_project

        for name in ("one", "two"):
            user = User.objects.create_user(username=name, password="x")
            BreakGlassAccount.objects.create(
                user=user, reason="r", last_validated_at=timezone.now()
            )
        found = {r.name: r.status for r in check_project().results}
        assert found["break-glass accounts"] is Status.OK

    def test_stale_validation_warns(self, enabled) -> None:
        from bastion.diagnostics import check_project

        for name in ("one", "two"):
            user = User.objects.create_user(username=name, password="x")
            BreakGlassAccount.objects.create(user=user, reason="r")
        found = {r.name: r.status for r in check_project().results}
        assert found["break-glass validation"] is Status.WARN


# --------------------------------------------------------------------------- #
# Command branches
# --------------------------------------------------------------------------- #


def run_breakglass(*args: str, **kwargs: Any) -> str:
    out = StringIO()
    call_command("bastion_breakglass", *args, stdout=out, stderr=StringIO(), **kwargs)
    return out.getvalue()


@pytest.mark.django_db
class TestBreakGlassCommandBranches:
    @pytest.fixture
    def enabled(self, settings):
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["bastion.breakglass.service.log_only_sink"],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }

    def test_list_with_no_accounts(self, enabled) -> None:
        assert "No break-glass accounts" in run_breakglass("list")

    def test_grant_requires_a_user(self, enabled) -> None:
        with pytest.raises(CommandError, match="--user is required"):
            run_breakglass("grant", "--reason", "x")

    def test_an_unknown_user_is_reported(self, enabled) -> None:
        with pytest.raises(CommandError, match="no user named"):
            run_breakglass("grant", "--user", "ghost", "--reason", "x")

    def test_revoke_on_a_non_break_glass_account(self, enabled) -> None:
        User.objects.create_user(username="ordinary", password="x")
        with pytest.raises(CommandError, match="not a break-glass account"):
            run_breakglass("revoke", "--user", "ordinary")

    def test_a_drill_on_a_non_break_glass_account(self, enabled) -> None:
        User.objects.create_user(username="ordinary", password="x")
        with pytest.raises(CommandError, match="not an active break-glass"):
            run_breakglass("drill", "--user", "ordinary")

    def test_granting_twice_reactivates(self, enabled) -> None:
        user = User.objects.create_user(username="candidate", password="x")
        run_breakglass("grant", "--user", "candidate", "--reason", "first")
        BreakGlassAccount.objects.filter(user=user).update(is_active=False)
        run_breakglass("grant", "--user", "candidate", "--reason", "again")
        assert BreakGlassAccount.objects.get(user=user).is_active is True

    def test_revoke_succeeds_when_a_spare_exists(self, enabled) -> None:
        for name in ("one", "two"):
            User.objects.create_user(username=name, password="x")
            run_breakglass("grant", "--user", name, "--reason", "r")
        run_breakglass("revoke", "--user", "one")
        assert BreakGlassAccount.objects.active().count() == 1

    def test_check_reports_an_inactive_user(self, enabled) -> None:
        user = User.objects.create_user(username="one", password="x")
        BreakGlassAccount.objects.create(user=user, reason="r")
        User.objects.filter(pk=user.pk).update(is_active=False)
        with pytest.raises(CommandError):
            run_breakglass("check")
