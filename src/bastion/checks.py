"""Startup system checks.

Every check here is a security invariant that can be verified without a
request. They run under ``manage.py check --deploy``, which
means a missing signing certificate or a cookie flag left at Django's insecure
default is caught before deploy rather than during an outage.

The anti-pattern this exists to avoid is djangosaml2's ``SAML_CONFIG``: an
opaque dict forwarded wholesale to pysaml2 with no validation, where errors
surface at request time in production.

Check IDs are stable and safe to silence individually via
``SILENCED_SYSTEM_CHECKS``. Do not renumber them.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.checks import CheckMessage, Error, Tags, Warning, register

from bastion.conf import get_setting
from bastion.connections import build_connection
from bastion.exceptions import ConfigurationError

# Django's own defaults are wrong for a deployment that carries session
# credentials for administrative access. We do not change them (that would be
# rude for a third-party app); we refuse to start quietly instead.
INSECURE_COOKIE_SETTINGS = (
    ("SESSION_COOKIE_SECURE", True),
    ("CSRF_COOKIE_SECURE", True),
    ("SESSION_COOKIE_HTTPONLY", True),
)


@register(Tags.security, deploy=True)
def check_cookie_settings(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Invariant 22: secure cookies and HSTS in production."""
    errors: list[CheckMessage] = []
    for name, expected in INSECURE_COOKIE_SETTINGS:
        if getattr(settings, name, False) is not expected:
            errors.append(
                Error(
                    f"{name} must be {expected} when django-bastion is installed.",
                    hint=(
                        f"django-bastion puts administrative access behind a session "
                        f"cookie. Django's default for {name} is insecure for that use. "
                        f"Set {name} = {expected}."
                    ),
                    id="bastion.E022",
                )
            )
    if not getattr(settings, "SECURE_HSTS_SECONDS", 0):
        errors.append(
            Error(
                "SECURE_HSTS_SECONDS must be set.",
                hint=(
                    "Without HSTS an attacker who can strip TLS sees the session "
                    "cookie that grants admin access. Start at 3600 and raise it "
                    "once you are confident."
                ),
                id="bastion.E022",
            )
        )
    return errors


@register(Tags.security)
def check_backend_ordering(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Invariant 23: no silent password fallback alongside SSO.

    The point of enterprise SSO is that the password path is gone. A chain that
    tries SSO and quietly falls back to ModelBackend is that control's
    negation. If you need a local password path, it is break-glass, and it is
    configured explicitly.
    """
    backends = list(getattr(settings, "AUTHENTICATION_BACKENDS", []))
    has_model_backend = "django.contrib.auth.backends.ModelBackend" in backends
    has_sso = any(b.startswith("bastion.") for b in backends)
    breakglass_enabled = get_setting("BREAK_GLASS").get("ENABLED", False)

    if has_sso and has_model_backend and not breakglass_enabled:
        return [
            Error(
                "ModelBackend is enabled alongside a bastion backend, but "
                "break-glass is not configured.",
                hint=(
                    "This allows a local password to bypass SSO with no audit "
                    "trail and no alerting. Either remove ModelBackend, or set "
                    'BASTION["BREAK_GLASS"]["ENABLED"] = True and configure an '
                    "allowlist so the fallback is deliberate and monitored."
                ),
                id="bastion.E023",
            )
        ]
    return []


@register(Tags.security)
def check_breakglass_alerting(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Break-glass without alerting is a backdoor with paperwork."""
    config = get_setting("BREAK_GLASS")
    if config.get("ENABLED") and not config.get("ALERT_SINKS"):
        return [
            Error(
                "Break-glass is enabled with no ALERT_SINKS configured.",
                hint=(
                    "Emergency access that nobody is told about is indistinguishable "
                    "from a backdoor. Configure at least one sink in "
                    'BASTION["BREAK_GLASS"]["ALERT_SINKS"].'
                ),
                id="bastion.E100",
            )
        ]
    return []


@register(Tags.security)
def check_breakglass_throttle_storage(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """The throttle counts failures out of the audit table.

    That is what makes it survive a restart and hold across workers, and it
    means removing the database sink turns the throttle off without saying so.
    A silently absent security control is worse than a documented absent one.
    """
    config = get_setting("BREAK_GLASS")
    if not config.get("ENABLED") or not config.get("MAX_FAILURES_PER_IP"):
        return []

    from bastion.audit.recorder import get_sinks
    from bastion.audit.sinks import DatabaseSink

    # Resolved instances, not the configured strings. Matching the name would
    # accept somebody's MyDatabaseSink that writes somewhere else, and reject a
    # subclass under another name that writes exactly where we look.
    if any(isinstance(sink, DatabaseSink) for sink in get_sinks()):
        return []

    return [
        Error(
            "Break-glass throttling is on but no audit DatabaseSink is configured.",
            hint=(
                "MAX_FAILURES_PER_IP counts failures from the audit table, so "
                'without "bastion.audit.sinks.DatabaseSink" in '
                'BASTION["AUDIT"]["SINKS"] nothing is counted and the throttle '
                "never fires. Add the sink, or set MAX_FAILURES_PER_IP to 0 to "
                "say you meant to run without it."
            ),
            id="bastion.E101",
        )
    ]


@register(Tags.security)
def check_connections(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Every configured connection is buildable before anyone tries to log in.

    Connections are built lazily, on the first request that needs one. That is
    right for the network work they own, but it means a missing ``client_id``
    or a typo'd key passes ``manage.py check`` and surfaces as a failed login
    in staging -- the one place where the person hitting it can least tell a
    configuration mistake from an outage.

    Building is the validation, rather than a second list of required keys
    kept in step with the first: unknown keys, unknown providers and bad
    ``auth_method`` values are all caught here for free, and cannot drift.
    Construction touches no network by design.
    """
    errors: list[CheckMessage] = []
    connections = get_setting("CONNECTIONS")

    for identifier in sorted(connections):
        try:
            # Deliberately not get_connection(): reporting every broken entry
            # beats stopping at the first, and the check should not leave a
            # half-populated cache behind.
            build_connection(identifier, dict(connections[identifier]))
        except ConfigurationError as exc:
            errors.append(
                Error(
                    str(exc),
                    hint=(
                        "The connection is built on first use, so this would "
                        "otherwise have appeared as a failed login rather than "
                        'here. Fix the entry in BASTION["CONNECTIONS"].'
                    ),
                    id="bastion.E027",
                )
            )

    admin_connection = get_setting("ADMIN").get("connection")
    if admin_connection is not None and admin_connection not in connections:
        errors.append(
            Error(
                f"ADMIN['connection'] is {admin_connection!r}, which is not configured.",
                hint=(
                    f"Configured: {sorted(connections) or 'none'}. A name that "
                    "resolves to nothing leaves the admin with no way in "
                    "except break-glass."
                ),
                id="bastion.E028",
            )
        )
    return errors


@register(Tags.security)
def check_session_engine(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Deprovisioning cannot revoke sessions the engine will not let us find.

    We can always rotate the auth hash, which kills sessions on every engine.
    But an operator should know that per-user session deletion is unavailable
    before they need it, not after.
    """
    engine = getattr(settings, "SESSION_ENGINE", "")
    if engine.endswith("signed_cookies"):
        return [
            Warning(
                "SESSION_ENGINE is signed_cookies, which stores no server-side session state.",
                hint=(
                    "Individual sessions cannot be enumerated or deleted. "
                    "Deprovisioning still works, because it rotates the session "
                    "auth hash, but you lose per-session revocation and the "
                    "session list in the admin. Prefer db or cached_db."
                ),
                id="bastion.W030",
            )
        ]
    return []


@register(Tags.security)
def check_identity_key(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Invariant 26: never key accounts on a mutable attribute."""
    identity = get_setting("IDENTITY")
    key = tuple(identity.get("KEY", ()))
    if key != ("issuer", "subject"):
        return [
            Error(
                f"IDENTITY['KEY'] is {key!r}, which is not ('issuer', 'subject').",
                hint=(
                    "Email, preferred_username and UPN are all mutable at the "
                    "identity provider. Keying on them means an IdP admin who "
                    "changes an address takes over an account. If you are "
                    "migrating an existing user table, use "
                    "LINKING_POLICY = 'verified_email_once' instead, which links "
                    "once and then pins to the subject."
                ),
                id="bastion.E026",
            )
        ]
    return []
