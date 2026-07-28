"""Every system check gets a test asserting its specific ID fires.

A check that silently stops firing is worse than no check, because the
deployment looks verified when it is not.
"""

from __future__ import annotations

import pytest
from django.test import override_settings

from bastion import checks
from bastion.conf import get_setting


def _ids(messages: list) -> set[str]:
    return {m.id for m in messages}


class TestCookieSettings:
    @override_settings(SESSION_COOKIE_SECURE=False)
    def test_insecure_session_cookie_is_an_error(self) -> None:
        assert "bastion.E022" in _ids(checks.check_cookie_settings(None))

    @override_settings(SECURE_HSTS_SECONDS=0)
    def test_missing_hsts_is_an_error(self) -> None:
        assert "bastion.E022" in _ids(checks.check_cookie_settings(None))

    def test_secure_defaults_pass(self) -> None:
        assert checks.check_cookie_settings(None) == []


class TestBackendOrdering:
    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "bastion.backends.SSOBackend",
            "django.contrib.auth.backends.ModelBackend",
        ]
    )
    def test_password_fallback_without_breakglass_is_an_error(self) -> None:
        assert "bastion.E023" in _ids(checks.check_backend_ordering(None))

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "bastion.backends.SSOBackend",
            "django.contrib.auth.backends.ModelBackend",
        ],
        BASTION={"BREAK_GLASS": {"ENABLED": True, "ALERT_SINKS": ["x.y"]}},
    )
    def test_password_fallback_with_breakglass_is_allowed(self) -> None:
        assert checks.check_backend_ordering(None) == []

    @override_settings(AUTHENTICATION_BACKENDS=["bastion.backends.SSOBackend"])
    def test_sso_only_passes(self) -> None:
        assert checks.check_backend_ordering(None) == []


class TestBreakGlassAlerting:
    @override_settings(BASTION={"BREAK_GLASS": {"ENABLED": True, "ALERT_SINKS": []}})
    def test_enabled_without_alerting_is_an_error(self) -> None:
        assert "bastion.E100" in _ids(checks.check_breakglass_alerting(None))

    @override_settings(
        BASTION={"BREAK_GLASS": {"ENABLED": True, "ALERT_SINKS": ["myapp.page_oncall"]}}
    )
    def test_enabled_with_alerting_passes(self) -> None:
        assert checks.check_breakglass_alerting(None) == []

    def test_disabled_passes(self) -> None:
        assert checks.check_breakglass_alerting(None) == []


class TestSessionEngine:
    @override_settings(SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies")
    def test_signed_cookies_warns(self) -> None:
        assert "bastion.W030" in _ids(checks.check_session_engine(None))

    def test_db_engine_passes(self) -> None:
        assert checks.check_session_engine(None) == []


class TestIdentityKey:
    @override_settings(BASTION={"IDENTITY": {"KEY": ("email",)}})
    def test_email_as_join_key_is_an_error(self) -> None:
        assert "bastion.E026" in _ids(checks.check_identity_key(None))

    def test_default_key_passes(self) -> None:
        assert checks.check_identity_key(None) == []


class TestSettingsResolution:
    def test_defaults_are_available(self) -> None:
        assert get_setting("IDENTITY")["KEY"] == ("issuer", "subject")

    @override_settings(BASTION={"MAPPING": {"STRICT": False}})
    def test_user_settings_merge_one_level(self) -> None:
        mapping = get_setting("MAPPING")
        assert mapping["STRICT"] is False
        # sibling defaults survive the merge
        assert mapping["MANAGED_GROUPS"] == "prefix:sso-"

    def test_override_settings_invalidates_the_cache(self) -> None:
        assert get_setting("MAPPING")["STRICT"] is True
        with override_settings(BASTION={"MAPPING": {"STRICT": False}}):
            assert get_setting("MAPPING")["STRICT"] is False
        assert get_setting("MAPPING")["STRICT"] is True

    def test_unknown_setting_raises(self) -> None:
        with pytest.raises(AttributeError):
            get_setting("NO_SUCH_SETTING")
