"""Every system check gets a test asserting its specific ID fires.

A check that silently stops firing is worse than no check, because the
deployment looks verified when it is not.
"""

from __future__ import annotations

import pytest
from django.contrib.admin.sites import all_sites
from django.contrib.auth.backends import BaseBackend, ModelBackend
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

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "bastion.backends.SSOBackend",
            "tests.test_checks.UsernameOrEmailBackend",
        ]
    )
    def test_a_modelbackend_subclass_is_an_error(self) -> None:
        """The string match let this through, and it closes nothing.

        Deleting "django.contrib.auth.backends.ModelBackend" from the list made
        the check pass while the subclass went on authenticating with a username
        and a password exactly as before -- a green tick beside an unchanged
        password path.
        """
        messages = checks.check_backend_ordering(None)
        assert "bastion.E023" in _ids(messages)
        assert "UsernameOrEmailBackend" in str(messages[0].msg)

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "bastion.backends.SSOBackend",
            "tests.test_checks.NotAPasswordBackend",
        ]
    )
    def test_an_unrelated_backend_passes(self) -> None:
        """issubclass, not "anything that is not ours"."""
        assert checks.check_backend_ordering(None) == []

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "bastion.backends.SSOBackend",
            "myapp.backends.DoesNotExist",
        ]
    )
    def test_an_unimportable_backend_is_left_to_django(self) -> None:
        """Django raises on it at the first authenticate(); this must not."""
        assert checks.check_backend_ordering(None) == []

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "bastion.backends.SSOBackend",
            "django.contrib.auth.backends.ModelBackend",
        ],
        BASTION={"ADMIN": {"local_login": "elsewhere"}},
    )
    def test_a_declared_password_path_elsewhere_warns_instead(self) -> None:
        """The opt-out for a project where the admin is one part of a bigger app.

        Enabling break-glass to satisfy a check is turning on a credential
        endpoint for the wrong reason. This records the decision instead, and
        keeps recording it on every check run.
        """
        messages = checks.check_backend_ordering(None)
        assert _ids(messages) == {"bastion.W031"}

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "bastion.backends.SSOBackend",
            "django.contrib.auth.backends.ModelBackend",
        ],
        BASTION={
            "ADMIN": {"local_login": "never"},
            "BREAK_GLASS": {"ENABLED": True, "ALERT_SINKS": ["x.y"]},
        },
    )
    def test_never_refuses_a_password_backend_even_with_breakglass(self) -> None:
        assert "bastion.E023" in _ids(checks.check_backend_ordering(None))

    @override_settings(BASTION={"ADMIN": {"local_login": "sometimes"}})
    def test_an_unknown_local_login_value_is_an_error(self) -> None:
        """A typo here would otherwise read as the strictest setting silently."""
        assert "bastion.E024" in _ids(checks.check_backend_ordering(None))

    @override_settings(
        AUTHENTICATION_BACKENDS=["django.contrib.auth.backends.ModelBackend"],
    )
    def test_a_project_with_no_sso_backend_is_not_our_business(self) -> None:
        assert checks.check_backend_ordering(None) == []

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "bastion.backends.SSOBackend",
            "django.contrib.auth.backends.ModelBackend",
        ]
    )
    def test_an_unimportable_modelbackend_is_still_counted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A broken entry elsewhere in the list must not turn the check off, and
        the one path we know the meaning of is still read from its name."""
        import django.utils.module_loading as loading

        def refuse(path: str) -> object:
            raise ImportError(path)

        monkeypatch.setattr(loading, "import_string", refuse)
        assert "bastion.E023" in _ids(checks.check_backend_ordering(None))


class UsernameOrEmailBackend(ModelBackend):
    """The shape from the report: a subclass, with the parent removed."""


class NotAPasswordBackend(BaseBackend):
    pass


class TestBreakGlassNetworks:
    @override_settings(
        BASTION={"BREAK_GLASS": {"ENABLED": True, "ALERT_SINKS": ["x.y"], "ALLOWED_NETWORKS": []}}
    )
    def test_an_empty_allowlist_warns(self) -> None:
        """The warning two docstrings promised and nothing implemented."""
        assert "bastion.W032" in _ids(checks.check_breakglass_networks(None))

    @override_settings(
        BASTION={
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["x.y"],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }
    )
    def test_a_configured_allowlist_passes(self) -> None:
        assert checks.check_breakglass_networks(None) == []

    @override_settings(
        BASTION={
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["x.y"],
                "ALLOWED_NETWORKS": ["10.0.0.0/8", "office"],
            }
        }
    )
    def test_an_entry_that_is_not_a_network_is_an_error(self) -> None:
        """ipaddress raises on it inside the gate, so it is a 500 on the
        emergency login discovered during the emergency."""
        messages = checks.check_breakglass_networks(None)
        assert "bastion.E102" in _ids(messages)
        assert "'office'" in str(messages[0].msg)

    def test_disabled_passes(self) -> None:
        assert checks.check_breakglass_networks(None) == []


class TestLinkingPolicy:
    @override_settings(BASTION={"IDENTITY": {"LINKING_POLICY": "email"}})
    def test_an_unknown_policy_is_an_error(self) -> None:
        """It used to fall through to subject-only, which looks exactly like
        linking that is on and never matches anybody."""
        assert "bastion.E029" in _ids(checks.check_linking_policy(None))

    @override_settings(BASTION={"IDENTITY": {"LINKING_POLICY": "verified_email_once"}})
    def test_linking_without_pinned_domains_is_an_error(self) -> None:
        assert "bastion.E029" in _ids(checks.check_linking_policy(None))

    @override_settings(
        BASTION={
            "IDENTITY": {
                "LINKING_POLICY": "verified_email_once",
                "LINKABLE_EMAIL_DOMAINS": ["example.com"],
            }
        }
    )
    def test_linking_with_pinned_domains_passes(self) -> None:
        assert checks.check_linking_policy(None) == []

    def test_the_default_passes(self) -> None:
        assert checks.check_linking_policy(None) == []


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


GOOD = {"issuer": "https://idp.test", "client_id": "abc", "provider": "entra"}


class TestConnections:
    @override_settings(BASTION={"CONNECTIONS": {"corp": dict(GOOD, client_id="")}})
    def test_empty_client_id_is_a_warning(self) -> None:
        """Absent, not wrong.

        Erroring on it is what forces settings to be written conditionally --
        ``"CONNECTIONS": {...} if CLIENT_ID else {}`` -- just to keep a
        developer checkout and CI booting. The environment says why instead.
        """
        assert _ids(checks.check_connections(None)) == {"bastion.W027"}

    @override_settings(BASTION={"CONNECTIONS": {"corp": {"client_id": "abc"}}})
    def test_missing_issuer_is_a_warning(self) -> None:
        assert _ids(checks.check_connections(None)) == {"bastion.W027"}

    @override_settings(BASTION={"CONNECTIONS": {"corp": dict(GOOD, client_id="")}})
    def test_an_incomplete_connection_still_fails_the_doctor(self) -> None:
        """The warning is not a downgrade of the finding, only of where it stops
        a deploy. The pipeline gate keeps refusing it."""
        import io

        from django.core.management import call_command
        from django.core.management.base import CommandError

        with pytest.raises(CommandError, match="found problems"):
            call_command("bastion_doctor", "--offline", stdout=io.StringIO())

    @override_settings(BASTION={"CONNECTIONS": {"corp": dict(GOOD, provider="nope")}})
    def test_unknown_provider_is_an_error(self) -> None:
        assert "bastion.E027" in _ids(checks.check_connections(None))

    @override_settings(BASTION={"CONNECTIONS": {"corp": dict(GOOD, discovery="https://x.test")}})
    def test_renamed_key_is_an_error(self) -> None:
        assert "bastion.E027" in _ids(checks.check_connections(None))

    @override_settings(BASTION={"CONNECTIONS": {"corp": dict(GOOD, require_group_match=True)}})
    def test_the_old_group_match_key_is_refused_with_its_new_name(self) -> None:
        """Accepted-and-ignored would silently drop the only control stopping an
        unprivileged account from holding a session, which is the opposite of
        what setting it asks for."""
        messages = checks.check_connections(None)
        assert "bastion.E027" in _ids(messages)
        assert "require_privileged_user" in str(messages[0].msg)

    @override_settings(
        BASTION={"CONNECTIONS": {"a": {"client_id": "x"}, "b": {"issuer": "https://b.test"}}}
    )
    def test_every_broken_connection_is_reported(self) -> None:
        """Not just the first. Fixing one at a time is how a deploy takes four tries."""
        messages = checks.check_connections(None)
        assert len(messages) == 2
        # Sorted, so the order is the production code's promise, not luck.
        assert "'a'" in str(messages[0].msg)
        assert "'b'" in str(messages[1].msg)

    @override_settings(BASTION={"CONNECTIONS": {"corp": dict(GOOD, auth_method="nonsense")}})
    def test_a_bad_auth_method_is_an_error_not_a_traceback(self) -> None:
        """It escaped as ValueError and took down every manage.py command."""
        assert "bastion.E027" in _ids(checks.check_connections(None))

    @override_settings(BASTION={"CONNECTIONS": {"corp": dict(GOOD, scopes=None)}})
    def test_an_uniterable_scopes_is_an_error_not_a_traceback(self) -> None:
        assert "bastion.E027" in _ids(checks.check_connections(None))

    @override_settings(BASTION={"CONNECTIONS": {"corp": dict(GOOD, identifier="other")}})
    def test_identifier_is_not_settable_from_config(self) -> None:
        """The loader supplies it; accepting it duplicated the keyword argument."""
        assert "bastion.E027" in _ids(checks.check_connections(None))

    @override_settings(BASTION={"CONNECTIONS": {"corp": dict(GOOD, _lock="nonsense")}})
    def test_private_fields_are_not_settable_from_config(self) -> None:
        """They are init fields, so the bare field list let settings set the lock."""
        assert "bastion.E027" in _ids(checks.check_connections(None))

    @override_settings(BASTION={"CONNECTIONS": {"corp": GOOD}})
    def test_valid_connection_passes(self) -> None:
        assert checks.check_connections(None) == []

    def test_no_connections_passes(self) -> None:
        assert checks.check_connections(None) == []

    def test_no_connections_does_not_import_the_oidc_stack(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Django runs system checks ahead of nearly every management command.

        Importing bastion.connections pulls in the OIDC package and through it
        cryptography -- about 120ms cold -- which every command in every
        environment paid, including the ones with SSO switched off and nothing
        here to check.
        """
        import builtins

        real_import = builtins.__import__
        imported: list[str] = []

        def spy(name: str, *args: object, **kwargs: object) -> object:
            imported.append(name)
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(builtins, "__import__", spy)
        checks.check_connections(None)
        assert "bastion.connections" not in imported

    @override_settings(BASTION={"CONNECTIONS": {"corp": GOOD}})
    def test_a_configured_connection_still_imports_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The other half of the early return: the work still happens when there
        is work."""
        import builtins

        real_import = builtins.__import__
        imported: list[str] = []

        def spy(name: str, *args: object, **kwargs: object) -> object:
            imported.append(name)
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(builtins, "__import__", spy)
        checks.check_connections(None)
        assert "bastion.connections" in imported

    @override_settings(
        BASTION={"CONNECTIONS": {"corp": dict(GOOD, provider="nope")}, "ADMIN": {"enabled": False}},
        ROOT_URLCONF="tests.empty_urls",
    )
    def test_an_unreachable_connection_is_a_warning(self) -> None:
        """A typo in a connection nobody is using should not take the site down.

        The admin integration is off and the login routes are not wired, so
        nothing in this project can reach the entry at all.
        """
        assert _ids(checks.check_connections(None)) == {"bastion.W027"}

    @override_settings(
        BASTION={"CONNECTIONS": {"corp": dict(GOOD, provider="nope")}, "ADMIN": {"enabled": False}},
        ROOT_URLCONF="tests.urls_no_admin",
    )
    def test_routed_login_urls_keep_it_an_error(self) -> None:
        """Turning the admin integration off is not turning SSO off: the entry
        is still reachable at /sso/login/<name>/."""
        assert "bastion.E027" in _ids(checks.check_connections(None))

    @override_settings(
        BASTION={"CONNECTIONS": {"corp": GOOD}, "ADMIN": {"connection": "typo"}},
    )
    def test_admin_pointing_at_nothing_is_an_error(self) -> None:
        assert "bastion.E028" in _ids(checks.check_connections(None))

    @override_settings(BASTION={"CONNECTIONS": {}, "ADMIN": {"connection": "corp"}})
    def test_admin_pointing_at_nothing_with_sso_off_is_a_warning(self) -> None:
        """The state a project is in before its credentials arrive.

        With no connections the admin serves the stock login, so naming one is a
        statement of intent for the environment that has it rather than a broken
        pointer in this one. Erroring here is what makes people write ADMIN
        conditionally.
        """
        assert _ids(checks.check_connections(None)) == {"bastion.W028"}

    @override_settings(
        BASTION={"CONNECTIONS": {"corp": GOOD}, "ADMIN": {"enabled": False, "connection": "typo"}}
    )
    def test_admin_pointing_at_nothing_while_disabled_is_a_warning(self) -> None:
        assert _ids(checks.check_connections(None)) == {"bastion.W028"}

    @override_settings(BASTION={"CONNECTIONS": {"corp": GOOD}, "ADMIN": {"connection": "corp"}})
    def test_admin_pointing_at_a_real_connection_passes(self) -> None:
        assert checks.check_connections(None) == []

    @override_settings(BASTION={"CONNECTIONS": {"corp": GOOD}, "ADMIN": {"connection": None}})
    def test_unset_admin_connection_passes(self) -> None:
        """None is the default. Without the guard, it is a name nothing matches."""
        assert checks.check_connections(None) == []

    @override_settings(BASTION={"CONNECTIONS": {"corp": GOOD}})
    def test_a_site_attribute_pointing_at_nothing_is_an_error(self) -> None:
        """sso_connection beats ADMIN["connection"], so it is the one that matters."""
        from bastion.admin.site import SSOAdminSite

        site = SSOAdminSite()
        site.sso_connection = "typo"
        try:
            assert "bastion.E028" in _ids(checks.check_connections(None))
        finally:
            all_sites.discard(site)

    @override_settings(BASTION={"CONNECTIONS": {"corp": GOOD}})
    def test_a_site_attribute_pointing_at_a_real_connection_passes(self) -> None:
        from bastion.admin.site import SSOAdminSite

        site = SSOAdminSite()
        site.sso_connection = "corp"
        try:
            assert checks.check_connections(None) == []
        finally:
            all_sites.discard(site)

    @override_settings(BASTION={"CONNECTIONS": {"corp": GOOD}})
    def test_check_does_not_populate_the_connection_cache(self) -> None:
        """Running checks must not decide what a later request gets served."""
        from bastion import connections

        connections._cache.clear()
        checks.check_connections(None)
        assert connections._cache == {}


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

    @override_settings(BASTION={"BREAK_GLASS": {"ENABLED": True}})
    def test_user_settings_merge_one_level(self) -> None:
        """On a setting something reads. These used to exercise MAPPING, which
        was declared and read by nothing and is gone."""
        config = get_setting("BREAK_GLASS")
        assert config["ENABLED"] is True
        # sibling defaults survive the merge
        assert config["MAX_FAILURES_PER_IP"] == 5

    def test_override_settings_invalidates_the_cache(self) -> None:
        assert get_setting("BREAK_GLASS")["ENABLED"] is False
        with override_settings(BASTION={"BREAK_GLASS": {"ENABLED": True}}):
            assert get_setting("BREAK_GLASS")["ENABLED"] is True
        assert get_setting("BREAK_GLASS")["ENABLED"] is False

    def test_unknown_setting_raises(self) -> None:
        with pytest.raises(AttributeError):
            get_setting("NO_SUCH_SETTING")
