"""The diagnostic command.

The property most worth protecting here is that the command does not lie. A
clean run must not imply that things it cannot check are fine, so several tests
assert the presence of "unverifiable" results rather than their absence.
"""

from __future__ import annotations

import json
from io import StringIO
from typing import Any

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from bastion.connections import Connection
from bastion.diagnostics import Status, check_connection, check_project
from bastion.protocols.oidc.transaction import MemoryTransactionStore
from tests.idp.provider import FakeIdP
from tests.idp.transport import FakeTransport


def build(idp: FakeIdP, transport: FakeTransport, **overrides: Any) -> Connection:
    defaults: dict[str, Any] = {
        "identifier": "corp",
        "issuer": idp.issuer,
        "client_id": idp.client_id,
        "client_secret": "shh",
        "transport": transport,
        "transactions": MemoryTransactionStore(),
    }
    defaults.update(overrides)
    return Connection(**defaults)


def statuses(results: list[Any]) -> dict[str, Status]:
    return {r.name: r.status for r in results}


@pytest.fixture
def transport(idp: FakeIdP) -> FakeTransport:
    return FakeTransport(idp=idp)


class TestHealthyConnection:
    def test_discovery_and_keys_pass(self, idp: FakeIdP, transport: FakeTransport) -> None:
        report = check_connection(build(idp, transport))
        found = statuses(report.results)
        assert found["discovery"] is Status.OK
        assert found["signing keys"] is Status.OK
        assert not report.failed

    def test_compatible_algorithms_pass(self, idp: FakeIdP, transport: FakeTransport) -> None:
        report = check_connection(build(idp, transport))
        assert statuses(report.results)["signing algorithms"] is Status.OK


class TestBrokenConnection:
    def test_unreachable_discovery_fails(self, idp: FakeIdP, transport: FakeTransport) -> None:
        from bastion.protocols.oidc.transport import TransportError

        transport.fail_with = TransportError("connection refused")
        report = check_connection(build(idp, transport))
        assert report.failed
        assert statuses(report.results)["discovery"] is Status.FAIL

    def test_nothing_downstream_runs_once_discovery_fails(
        self, idp: FakeIdP, transport: FakeTransport
    ) -> None:
        from bastion.protocols.oidc.transport import TransportError

        transport.fail_with = TransportError("connection refused")
        report = check_connection(build(idp, transport))
        assert "signing keys" not in statuses(report.results)

    def test_symmetric_only_provider_fails(self, idp: FakeIdP, transport: FakeTransport) -> None:
        """A provider offering only HS256 would fail every login. Refusing the
        symmetric family is deliberate, so this has to be caught at setup."""
        document = dict(idp.discovery_document())
        document["id_token_signing_alg_values_supported"] = ["HS256"]
        transport.discovery_override = document

        report = check_connection(build(idp, transport))
        assert statuses(report.results)["signing algorithms"] is Status.FAIL
        assert report.failed


class TestLogoutCapability:
    def test_a_provider_with_logout_passes(self, idp: FakeIdP, transport: FakeTransport) -> None:
        report = check_connection(build(idp, transport))
        assert statuses(report.results)["logout"] is Status.OK

    def test_google_warns(self, google_idp: FakeIdP) -> None:
        transport = FakeTransport(idp=google_idp)
        report = check_connection(build(google_idp, transport, provider="google"))
        assert statuses(report.results)["logout"] is Status.WARN
        assert not report.failed


class TestHonesty:
    """A clean run must not imply that unverifiable things are fine."""

    def test_group_mapping_is_reported_as_unverifiable(
        self, idp: FakeIdP, transport: FakeTransport
    ) -> None:
        connection = build(idp, transport, staff_groups=("django-staff",))
        report = check_connection(connection)
        assert statuses(report.results)["group mapping"] is Status.UNVERIFIABLE

    def test_the_hint_names_the_specific_provider_traps(
        self, idp: FakeIdP, transport: FakeTransport
    ) -> None:
        connection = build(idp, transport, staff_groups=("django-staff",))
        hint = next(
            r.hint for r in check_connection(connection).results if r.name == "group mapping"
        )
        assert "Okta" in hint and "Entra" in hint and "Google" in hint

    def test_mfa_requirement_is_reported_as_unverifiable(
        self, idp: FakeIdP, transport: FakeTransport
    ) -> None:
        report = check_connection(build(idp, transport, require_mfa=True))
        assert statuses(report.results)["MFA requirement"] is Status.UNVERIFIABLE

    def test_the_redirect_uri_is_reported_as_unverifiable(self) -> None:
        report = check_project()
        assert statuses(report.results)["urls"] is Status.UNVERIFIABLE

    def test_break_glass_absence_is_stated(self) -> None:
        report = check_project()
        assert statuses(report.results)["break-glass"] is Status.UNVERIFIABLE

    def test_unverifiable_items_do_not_fail_the_run(
        self, idp: FakeIdP, transport: FakeTransport
    ) -> None:
        connection = build(idp, transport, staff_groups=("x",), require_mfa=True)
        assert not check_connection(connection).failed


class TestOfflineMode:
    def test_no_network_checks_run(self, idp: FakeIdP, transport: FakeTransport) -> None:
        report = check_connection(build(idp, transport), offline=True)
        assert "discovery" not in statuses(report.results)
        assert transport.gets == []

    def test_config_checks_still_run(self, idp: FakeIdP, transport: FakeTransport) -> None:
        report = check_connection(build(idp, transport), offline=True)
        assert "provider" in statuses(report.results)


class TestProjectChecks:
    def test_urls_resolve(self) -> None:
        assert statuses(check_project().results)["urls"] is not Status.FAIL

    @override_settings(ROOT_URLCONF="tests.empty_urls")
    def test_missing_urlconf_fails(self) -> None:
        report = check_project()
        assert statuses(report.results)["urls"] is Status.FAIL
        assert report.failed

    @override_settings(AUTHENTICATION_BACKENDS=["django.contrib.auth.backends.ModelBackend"])
    def test_a_missing_backend_fails(self) -> None:
        report = check_project()
        assert statuses(report.results)["auth backend"] is Status.FAIL

    @override_settings(SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies")
    def test_signed_cookies_warns(self) -> None:
        assert statuses(check_project().results)["session engine"] is Status.WARN


class TestCommand:
    def _run(self, *args: str, **kwargs: Any) -> str:
        out = StringIO()
        call_command("bastion_doctor", *args, stdout=out, stderr=StringIO(), **kwargs)
        return out.getvalue()

    @override_settings(BASTION={"CONNECTIONS": {}})
    def test_no_connections_is_an_error(self) -> None:
        with pytest.raises(CommandError, match="No connections"):
            self._run()

    def test_json_output_is_parseable(
        self, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        connection = build(idp, transport)
        monkeypatch.setattr(
            "bastion.management.commands.bastion_doctor.get_connection",
            lambda name: connection,
        )
        monkeypatch.setattr(
            "bastion.management.commands.bastion_doctor.get_setting",
            lambda key: {"corp": {}},
        )
        payload = json.loads(self._run("--json"))
        assert payload["ok"] is True
        assert any(r["connection"] == "corp" for r in payload["reports"])

    def test_a_failure_exits_non_zero(
        self, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        from bastion.protocols.oidc.transport import TransportError

        transport.fail_with = TransportError("refused")
        connection = build(idp, transport)
        monkeypatch.setattr(
            "bastion.management.commands.bastion_doctor.get_connection",
            lambda name: connection,
        )
        monkeypatch.setattr(
            "bastion.management.commands.bastion_doctor.get_setting",
            lambda key: {"corp": {}},
        )
        with pytest.raises(CommandError):
            self._run()

    def test_strict_promotes_warnings(self, google_idp: FakeIdP, monkeypatch) -> None:
        """Google's missing logout endpoint is a warning by default."""
        transport = FakeTransport(idp=google_idp)
        connection = build(google_idp, transport, provider="google")
        monkeypatch.setattr(
            "bastion.management.commands.bastion_doctor.get_connection",
            lambda name: connection,
        )
        monkeypatch.setattr(
            "bastion.management.commands.bastion_doctor.get_setting",
            lambda key: {"corp": {}},
        )
        self._run()  # tolerated
        with pytest.raises(CommandError):
            self._run("--strict")

    def test_an_unknown_connection_is_reported_not_raised(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "bastion.management.commands.bastion_doctor.get_setting",
            lambda key: {"corp": {}},
        )
        with pytest.raises(CommandError):
            self._run("does-not-exist")
