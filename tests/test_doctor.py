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
from bastion.testing.provider import FakeIdP
from bastion.testing.transport import FakeTransport

# The project checks query break-glass accounts, so the whole module needs a
# database now.
pytestmark = pytest.mark.django_db


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

    def test_advertised_s256_passes(self, idp: FakeIdP, transport: FakeTransport) -> None:
        report = check_connection(build(idp, transport))
        assert statuses(report.results)["PKCE"] is Status.OK


class TestPkceReporting:
    """The doctor has to distinguish a provider that will not do S256 from one
    that simply does not say."""

    def test_an_absent_method_list_is_unverifiable_not_a_failure(
        self, idp: FakeIdP, transport: FakeTransport
    ) -> None:
        """Microsoft's v2.0 document omits the field and accepts S256 anyway.

        This used to fail discovery outright, so bastion_doctor refused every
        Entra deployment on its first run and told the operator to turn off
        require_s256 -- which is not what was wrong.
        """
        idp.discovery_overrides = {"code_challenge_methods_supported": None}
        report = check_connection(build(idp, transport))

        assert statuses(report.results)["PKCE"] is Status.UNVERIFIABLE
        assert statuses(report.results)["discovery"] is Status.OK
        assert not report.failed, "a silent provider must not fail the run"

    def test_a_method_list_without_s256_fails(self, idp: FakeIdP, transport: FakeTransport) -> None:
        idp.discovery_overrides = {"code_challenge_methods_supported": ["plain"]}
        report = check_connection(build(idp, transport))
        assert report.failed

    def test_the_unverifiable_note_explains_why_it_is_not_a_problem(
        self, idp: FakeIdP, transport: FakeTransport
    ) -> None:
        idp.discovery_overrides = {"code_challenge_methods_supported": None}
        report = check_connection(build(idp, transport))
        pkce = next(r for r in report.results if r.name == "PKCE")
        assert "optional" in (pkce.hint or "").lower()


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

    def test_a_connection_that_can_never_onboard_anybody_warns(
        self, idp: FakeIdP, transport: FakeTransport
    ) -> None:
        """require_privileged_user with no group lists and no row surviving a
        refusal refuses every first sign-in and leaves nothing to grant on.

        Discovering that during an onboarding is the sort of thing this command
        exists to prevent.
        """
        connection = build(idp, transport)
        connection.require_privileged_user = True
        connection.persist_refused_identities = False
        assert statuses(check_connection(connection).results)["group mapping"] is Status.WARN

    def test_mfa_requirement_is_reported_as_unverifiable(
        self, idp: FakeIdP, transport: FakeTransport
    ) -> None:
        report = check_connection(build(idp, transport, require_mfa=True))
        assert statuses(report.results)["MFA requirement"] is Status.UNVERIFIABLE

    @override_settings(SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"))
    def test_the_redirect_uri_is_reported_as_unverifiable(self) -> None:
        """Even with the scheme resolved, whether it is registered at the
        provider is not knowable from here."""
        report = check_project()
        assert statuses(report.results)["urls"] is Status.UNVERIFIABLE

    def test_break_glass_being_off_is_stated(self) -> None:
        """Disabled is a legitimate choice, but it must be a stated one: a
        provider outage locks out everyone, including whoever would fix it."""
        report = check_project()
        assert statuses(report.results)["break-glass"] is Status.WARN

    def test_an_empty_network_allowlist_warns(self, settings) -> None:
        """The same finding as bastion.W032, in the tool an operator actually
        runs before going live."""
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["bastion.breakglass.service.log_only_sink"],
                "ALLOWED_NETWORKS": [],
            }
        }
        assert statuses(check_project().results)["break-glass network"] is Status.WARN

    def test_a_configured_network_allowlist_passes(self, settings) -> None:
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["bastion.breakglass.service.log_only_sink"],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }
        assert statuses(check_project().results)["break-glass network"] is Status.OK

    def test_alerting_is_reported_as_unverifiable_when_configured(self, settings) -> None:
        """Sinks being listed is not evidence an alert arrives. Only a drill
        establishes that, and the doctor says so rather than showing green."""
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["bastion.breakglass.service.log_only_sink"],
            }
        }
        report = check_project()
        assert statuses(report.results)["break-glass alerting"] is Status.UNVERIFIABLE

    def test_enabled_without_alerting_fails(self, settings) -> None:
        settings.BASTION = {"BREAK_GLASS": {"ENABLED": True, "ALERT_SINKS": []}}
        report = check_project()
        assert statuses(report.results)["break-glass alerting"] is Status.FAIL
        assert report.failed

    def test_enabled_without_accounts_fails(self, settings) -> None:
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["bastion.breakglass.service.log_only_sink"],
            }
        }
        report = check_project()
        assert statuses(report.results)["break-glass accounts"] is Status.FAIL

    def test_unverifiable_items_do_not_fail_the_run(
        self, idp: FakeIdP, transport: FakeTransport
    ) -> None:
        connection = build(idp, transport, staff_groups=("x",), require_mfa=True)
        assert not check_connection(connection).failed


class TestRegistrationCheck:
    """The probe is opt-in, and each verdict has to land as the right status.

    An inconclusive answer reporting OK would be the whole point missed: this
    exists so a deployment stops guessing, not so it gets a second thing to
    guess about.
    """

    @staticmethod
    def _probe(monkeypatch: pytest.MonkeyPatch, verdict: Any) -> None:
        from bastion.protocols.oidc import registration

        monkeypatch.setattr(
            registration,
            "probe_registration",
            lambda **_: registration.Probe(verdict, "detail."),
        )

    @pytest.mark.parametrize(
        ("verdict_name", "expected"),
        [
            ("REGISTERED", Status.OK),
            ("NOT_REGISTERED", Status.FAIL),
            ("CLIENT_REJECTED", Status.FAIL),
            ("INCONCLUSIVE", Status.UNVERIFIABLE),
        ],
    )
    def test_each_verdict_lands_as_the_right_status(
        self,
        idp: FakeIdP,
        transport: FakeTransport,
        monkeypatch: pytest.MonkeyPatch,
        verdict_name: str,
        expected: Status,
    ) -> None:
        from bastion.protocols.oidc.registration import Registration

        self._probe(monkeypatch, getattr(Registration, verdict_name))
        report = check_connection(
            build(idp, transport),
            registration_url="https://admin.example.test/sso/callback/",
        )
        assert statuses(report.results)["redirect uri"] is expected

    def test_the_url_asked_about_is_in_the_output(
        self, idp: FakeIdP, transport: FakeTransport, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """So a mismatch between what was asked and what is registered is
        visible without re-deriving the URL by hand."""
        from bastion.protocols.oidc.registration import Registration

        self._probe(monkeypatch, Registration.NOT_REGISTERED)
        report = check_connection(
            build(idp, transport),
            registration_url="https://admin.example.test/sso/callback/",
        )
        detail = next(r.detail for r in report.results if r.name == "redirect uri")
        assert "https://admin.example.test/sso/callback/" in detail

    def test_it_does_not_run_unless_asked(self, idp: FakeIdP, transport: FakeTransport) -> None:
        report = check_connection(build(idp, transport))
        assert "redirect uri" not in statuses(report.results)

    def test_offline_wins(self, idp: FakeIdP, transport: FakeTransport) -> None:
        """--offline promises no network requests, and this is one."""
        report = check_connection(
            build(idp, transport),
            offline=True,
            registration_url="https://admin.example.test/sso/callback/",
        )
        assert "redirect uri" not in statuses(report.results)


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


def _urls_result(**kwargs: Any):
    from bastion.diagnostics import check_project as run

    return next(r for r in run(**kwargs).results if r.name == "urls")


class TestCallbackUrl:
    """The path alone was right and useless.

    A deployment behind a TLS-terminating load balancer without
    SECURE_PROXY_SSL_HEADER builds ``http://`` redirect URIs while the
    ``https://`` one is registered at the provider. Every sign-in fails with
    redirect_uri_mismatch and nothing in the output points at it, because the
    path in the output is correct. The scheme is knowable here, so it is shown.
    """

    @override_settings(ALLOWED_HOSTS=["api.example.com"], SECURE_PROXY_SSL_HEADER=None)
    def test_the_absolute_url_is_printed(self) -> None:
        assert _urls_result().detail == "Callback URL is http://api.example.com/sso/callback/"

    @override_settings(ALLOWED_HOSTS=["api.example.com"], SECURE_PROXY_SSL_HEADER=None)
    def test_plain_http_warns(self) -> None:
        result = _urls_result()
        assert result.status is Status.WARN
        assert "SECURE_PROXY_SSL_HEADER" in (result.hint or "")

    @override_settings(
        ALLOWED_HOSTS=["api.example.com"],
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
    )
    def test_a_proxy_header_gives_https_and_names_its_assumption(self) -> None:
        result = _urls_result()
        assert result.detail == "Callback URL is https://api.example.com/sso/callback/"
        # The wire form, which is what a proxy is configured with.
        assert "X-Forwarded-Proto: https" in (result.hint or "")

    @override_settings(
        ALLOWED_HOSTS=["api.example.com"],
        SECURE_PROXY_SSL_HEADER=None,
        SECURE_SSL_REDIRECT=True,
    )
    def test_ssl_redirect_gives_https_and_names_the_loop_it_assumes_away(self) -> None:
        result = _urls_result()
        assert result.detail.startswith("Callback URL is https://")
        assert "loops" in (result.hint or "")

    @override_settings(ALLOWED_HOSTS=[], DEBUG=True)
    def test_debug_uses_djangos_own_localhost_default(self) -> None:
        assert "//localhost:8000/" in _urls_result().detail

    @override_settings(ALLOWED_HOSTS=["*"], DEBUG=False)
    def test_a_wildcard_host_falls_back_to_the_path(self) -> None:
        """Better to say what cannot be built than to invent a host."""
        result = _urls_result()
        assert result.detail == "Callback path is /sso/callback/"
        assert "--base-url" in (result.hint or "")

    @override_settings(ALLOWED_HOSTS=["a.example.com", "b.example.com"])
    def test_more_than_one_host_is_stated(self) -> None:
        assert "2 entries in ALLOWED_HOSTS" in _urls_result().detail

    @override_settings(ALLOWED_HOSTS=[".example.com"])
    def test_a_subdomain_pattern_shows_the_bare_domain(self) -> None:
        assert "//example.com/" in _urls_result().detail

    @override_settings(ALLOWED_HOSTS=["api.example.com"], SECURE_PROXY_SSL_HEADER=None)
    def test_base_url_wins_over_every_inference(self) -> None:
        result = _urls_result(base_url="https://admin.example.com")
        assert result.detail == "Callback URL is https://admin.example.com/sso/callback/"
        assert result.status is Status.UNVERIFIABLE

    @override_settings(
        ALLOWED_HOSTS=["api.example.com"],
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
    )
    def test_a_plain_http_base_url_still_warns(self) -> None:
        assert _urls_result(base_url="http://admin.example.com").status is Status.WARN


class TestCommand:
    def _run(self, *args: str, **kwargs: Any) -> str:
        out = StringIO()
        call_command("bastion_doctor", *args, stdout=out, stderr=StringIO(), **kwargs)
        return out.getvalue()

    @override_settings(BASTION={"CONNECTIONS": {}})
    def test_no_connections_is_an_error(self) -> None:
        with pytest.raises(CommandError, match="No connections"):
            self._run()

    @override_settings(ALLOWED_HOSTS=[], DEBUG=False)
    def test_check_registration_refuses_to_guess_the_url(self, monkeypatch) -> None:
        """Asking the provider about a URL the deployment would never send is
        worse than not asking: the answer would be about nothing."""
        monkeypatch.setattr(
            "bastion.management.commands.bastion_doctor.get_setting",
            lambda key: {"corp": {}},
        )
        with pytest.raises(CommandError, match="--base-url"):
            self._run("--check-registration")

    def test_check_registration_asks_about_the_url_the_report_prints(
        self, idp: FakeIdP, transport: FakeTransport, monkeypatch
    ) -> None:
        """One derivation, shared. Two would drift, and the one that got it
        wrong would be the one reporting success."""
        connection = build(idp, transport)
        monkeypatch.setattr(
            "bastion.management.commands.bastion_doctor.get_connection",
            lambda name: connection,
        )
        monkeypatch.setattr(
            "bastion.management.commands.bastion_doctor.get_setting",
            lambda key: {"corp": {}},
        )

        asked: dict[str, Any] = {}

        def record(**kwargs: Any) -> Any:
            from bastion.protocols.oidc.registration import Probe, Registration

            asked.update(kwargs)
            return Probe(Registration.REGISTERED, "detail.")

        monkeypatch.setattr("bastion.protocols.oidc.registration.probe_registration", record)
        self._run("--check-registration", "--base-url", "https://admin.example.com")
        assert asked["redirect_uri"] == "https://admin.example.com/sso/callback/"

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
