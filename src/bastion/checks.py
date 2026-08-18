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

from bastion.conf import (
    LINKING_POLICIES,
    LOCAL_LOGIN_POLICIES,
    VERIFIED_EMAIL_ONCE,
    get_setting,
)
from bastion.exceptions import ConfigurationError, IncompleteConfiguration

#: The backend whose presence alongside SSO E023 is about. Matched by class
#: rather than by this string; kept only for the one case where a path cannot
#: be imported at all.
MODEL_BACKEND = "django.contrib.auth.backends.ModelBackend"

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

    Two things this used to get wrong.

    It matched the string ``django.contrib.auth.backends.ModelBackend``, so a
    project whose password backend was a subclass -- a UsernameOrEmailBackend,
    which is a common thing to have -- passed by deleting the parent from the
    list while still authenticating with a username and password exactly as
    before. A check that can be silenced by a change which closes nothing is
    worse than no check, because now there is a green tick beside it. Backends
    are imported and tested with ``issubclass``.

    And it assumed the whole site was behind SSO. That does not fit a project
    where the Django admin is one part of a larger application whose portal and
    API authenticate with passwords and cannot stop:
    ``AUTHENTICATION_BACKENDS`` is global, so the check cannot tell "passwords
    still reach the admin" from "passwords reach a completely separate part of
    the site". Neither can anything else, which is why the answer is declared
    rather than inferred: ``ADMIN["local_login"]`` records the decision, and
    ``"elsewhere"`` turns this into ``bastion.W031`` so the decision stays
    visible on every check run instead of being worked around by enabling an
    emergency credential path nobody wanted.
    """
    policy = get_setting("ADMIN").get("local_login", "breakglass_only")
    if policy not in LOCAL_LOGIN_POLICIES:
        return [
            Error(
                f'ADMIN["local_login"] is {policy!r}, which is not a known value.',
                hint=(
                    f"Use one of {sorted(LOCAL_LOGIN_POLICIES)}. "
                    '"breakglass_only" is the default: a local password reaches '
                    'the site only through break-glass. "never" refuses any '
                    'password backend at all. "elsewhere" says passwords serve '
                    "other parts of this project and the admin is protected by "
                    "the SSO admin site."
                ),
                id="bastion.E024",
            )
        ]

    backends = list(getattr(settings, "AUTHENTICATION_BACKENDS", []))
    if not any(b.startswith("bastion.") for b in backends):
        return []

    password_backends = _password_backends(backends)
    if not password_backends:
        return []

    named = ", ".join(password_backends)
    if policy == "elsewhere":
        return [
            Warning(
                f"{named} authenticates with a local password alongside SSO, "
                'declared as ADMIN["local_login"] = "elsewhere".',
                hint=(
                    "Recorded rather than accepted silently, because it cannot "
                    "be verified from here: any login view in this project can "
                    "put a password-authenticated session in front of the admin, "
                    "whose own permission test only asks for is_staff. Keep the "
                    "password path away from staff accounts, and silence this id "
                    "in SILENCED_SYSTEM_CHECKS once that is true and reviewed."
                ),
                id="bastion.W031",
            )
        ]

    breakglass_enabled = get_setting("BREAK_GLASS").get("ENABLED", False)
    if policy == "never" or not breakglass_enabled:
        return [
            Error(
                f"{named} authenticates with a local password alongside a "
                "bastion backend, and no password path is declared.",
                hint=(
                    "This allows a local password to bypass SSO with no audit "
                    "trail and no alerting. Remove the backend; or set "
                    'BASTION["BREAK_GLASS"]["ENABLED"] = True with an allowlist, '
                    "so the fallback is deliberate and monitored; or, if it "
                    "serves a portal or an API rather than the admin, set "
                    'BASTION["ADMIN"]["local_login"] = "elsewhere" to record '
                    "that decision."
                    + (
                        ' Break-glass is enabled, but local_login is "never", '
                        "which refuses a password backend regardless."
                        if breakglass_enabled
                        else ""
                    )
                ),
                id="bastion.E023",
            )
        ]
    return []


def _password_backends(paths: list[str]) -> list[str]:
    """Configured backends that authenticate with a local password.

    ``issubclass`` against ``ModelBackend`` rather than a match on its dotted
    path: the subclass is the whole point, since that is what a project with a
    UsernameOrEmailBackend actually has, and it authenticates with a password
    just as its parent does.

    A path that cannot be imported is left to Django, which raises on it the
    first time anything authenticates. The one exception is the literal
    ModelBackend path, which is still counted from its name so that a broken
    entry elsewhere in the list cannot turn this check off.

    The catch is deliberately broad. Importing a module runs it, so the failure
    is whatever that module raises, and a check that aborts the check framework
    takes down every ``manage.py`` command -- which this package has already
    shipped once, from a mistyped ``auth_method`` escaping as ``ValueError``.
    """
    from django.contrib.auth.backends import ModelBackend
    from django.utils.module_loading import import_string

    found: list[str] = []
    for path in paths:
        try:
            backend = import_string(path)
        except Exception:
            if path == MODEL_BACKEND:
                found.append(path)
            continue
        if isinstance(backend, type) and issubclass(backend, ModelBackend):
            found.append(path)
    return found


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
def check_breakglass_networks(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """The warning ``ALLOWED_NETWORKS`` was documented as having.

    ``_network_allows`` and the setting's own comment both said an empty list
    meant "anywhere, which the startup check warns about rather than silently
    accepting". No such check existed, so break-glass could be enabled and
    reachable from any address on the internet with nothing said anywhere. A
    docstring that promises a guard is worse than one that admits the gap: the
    reader stops looking.

    Warning rather than error. An emergency route restricted to an office range
    is unreachable from the hotel the incident finds you in, and a package is
    not entitled to decide that trade for a deployment. It is entitled to make
    sure the trade was made deliberately.

    Unparseable entries are a different matter and refuse. ``ipaddress`` raises
    on them at request time, inside the branch that decides whether to answer
    an unauthenticated caller, so a typo there is a 500 on the emergency login
    discovered during the emergency.
    """
    config = get_setting("BREAK_GLASS")
    if not config.get("ENABLED"):
        return []

    networks = list(config.get("ALLOWED_NETWORKS") or [])
    if not networks:
        return [
            Warning(
                "Break-glass is enabled and ALLOWED_NETWORKS is empty, so the "
                "emergency login answers any address on the internet.",
                hint=(
                    'Set BASTION["BREAK_GLASS"]["ALLOWED_NETWORKS"] to the CIDRs '
                    "emergency access should come from, or silence this id to "
                    "record that you decided it should be reachable from "
                    "anywhere. The endpoint is deliberately outside django-axes "
                    "and its own throttle only counts credential failures, so "
                    "the network list is the first gate in front of it."
                ),
                id="bastion.W032",
            )
        ]

    import ipaddress

    bad = []
    for entry in networks:
        try:
            ipaddress.ip_network(str(entry), strict=False)
        except ValueError as exc:
            bad.append(f"{entry!r} ({exc})")
    if bad:
        return [
            Error(
                "ALLOWED_NETWORKS has entries that are not networks: " + ", ".join(bad) + ".",
                hint=(
                    "Each entry is passed to ipaddress.ip_network, which raises "
                    "on anything else. Use CIDR notation, for example "
                    '"10.0.0.0/8" or "203.0.113.7/32".'
                ),
                id="bastion.E102",
            )
        ]
    return []


@register(Tags.security)
def check_linking_policy(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """``LINKING_POLICY`` names a policy that exists, and can do its job.

    Both halves matter. An unrecognised value used to fall through to
    subject-only linking, which looks exactly like linking that is on and never
    matches anybody -- and the way that is discovered is an administrator
    asking why they have two accounts.

    ``verified_email_once`` with no pinned domains is the same failure wearing
    a different hat: the policy is on, every adoption is refused because the
    domain list it checks against is empty, and nothing says so. The pin is
    also the control that makes the policy safe, so a deployment that has not
    set one has not finished turning the feature on.
    """
    identity = get_setting("IDENTITY")
    policy = identity.get("LINKING_POLICY", "subject_only")

    if policy not in LINKING_POLICIES:
        return [
            Error(
                f"IDENTITY['LINKING_POLICY'] is {policy!r}, which is not a known policy.",
                hint=(
                    f"Use one of {sorted(LINKING_POLICIES)}. 'subject_only' never "
                    "adopts a local account. 'verified_email_once' adopts one on "
                    "first sign-in under the conditions in the settings "
                    "reference, then pins to the subject."
                ),
                id="bastion.E029",
            )
        ]

    if policy == VERIFIED_EMAIL_ONCE and not identity.get("LINKABLE_EMAIL_DOMAINS"):
        return [
            Error(
                "IDENTITY['LINKING_POLICY'] is 'verified_email_once' but "
                "LINKABLE_EMAIL_DOMAINS is empty, so no account can ever be linked.",
                hint=(
                    'Set BASTION["IDENTITY"]["LINKABLE_EMAIL_DOMAINS"] to the '
                    'domains you control, for example ["example.com"]. The pin '
                    "is what stops somebody who can prove an address at any "
                    "domain the provider will federate from claiming the local "
                    "account that holds it."
                ),
                id="bastion.E029",
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

    This relies on ``build_connection`` raising ``ConfigurationError`` and
    nothing else. It did not, until adding this check surfaced it -- a bad
    ``auth_method`` escaped as ``ValueError`` and aborted the check framework,
    which runs ahead of nearly every management command.

    **Severity is not uniform, and the split is the useful part.** A missing
    value is a state every deployment passes through: a checkout or a CI run
    whose credentials are not in the environment yet. Refusing to boot on it
    forces settings to be written conditionally just to keep those
    environments alive, which is how a project ends up with an SSO config
    nobody can read. So a missing value warns. A *wrong* value -- an unknown
    key, a provider that does not exist -- is a mistake in every environment,
    and refuses. And when nothing in the project can reach a connection at all,
    both warn: a typo in an entry nobody is using should not take the site
    down.

    ``bastion_doctor`` still fails on every one of these, which is the gate to
    put in a deployment pipeline.
    """
    messages: list[CheckMessage] = []
    connections = get_setting("CONNECTIONS")
    live = _sso_is_live(connections)

    for source, name in _admin_connection_names():
        if name in connections:
            continue
        detail = f"{source} is {name!r}, which is not configured."
        hint = (
            f"Configured: {sorted(connections) or 'none'}. A name "
            "that resolves to nothing leaves the admin with no way "
            "in except break-glass."
        )
        if live:
            messages.append(Error(detail, hint=hint, id="bastion.E028"))
        else:
            # The admin is serving the stock login here, either because
            # ADMIN["enabled"] is off or because no connections exist at all, so
            # the name is a statement of intent for the environment that has
            # one rather than a broken pointer in this one. Erroring is what
            # makes people write ADMIN conditionally.
            messages.append(
                Warning(
                    detail,
                    hint=(
                        hint + " SSO is not live in this environment, so this is "
                        "a warning: the stock login is being served. It becomes "
                        "an error once the admin integration is on and at least "
                        "one connection exists."
                    ),
                    id="bastion.W028",
                )
            )

    if not connections:
        # Before the import, and that is the point of the early return: it pulls
        # in the OIDC package and through it cryptography, about 120ms cold, on
        # every manage.py command in every environment -- including the ones
        # with SSO switched off, which have nothing here to check.
        return messages

    reachable = _connections_are_reachable()
    from bastion.connections import build_connection

    for identifier, config in sorted(connections.items()):
        try:
            # Deliberately not get_connection(): reporting every broken entry
            # beats stopping at the first, and the check should not leave a
            # half-populated cache behind.
            build_connection(identifier, config)
        except IncompleteConfiguration as exc:
            messages.append(
                Warning(
                    str(exc),
                    hint=(
                        "A value is absent rather than wrong, which is what a "
                        "checkout or a CI run without the credentials looks "
                        "like, so this does not stop the site booting. The "
                        "connection cannot sign anyone in until it is filled "
                        "in, and bastion_doctor fails on it."
                    ),
                    id="bastion.W027",
                )
            )
        except ConfigurationError as exc:
            hint = (
                "The connection is built on first use, so this would "
                "otherwise have appeared as a failed login rather than "
                'here. Fix the entry in BASTION["CONNECTIONS"].'
            )
            if reachable:
                messages.append(Error(str(exc), hint=hint, id="bastion.E027"))
            else:
                messages.append(
                    Warning(
                        str(exc),
                        hint=(
                            hint + " This is a warning rather than an error "
                            'because ADMIN["enabled"] is off and bastion.urls is '
                            "not routed, so nothing in this project can reach "
                            "the connection."
                        ),
                        id="bastion.W027",
                    )
                )
    return messages


def _sso_is_live(connections: dict[str, Any]) -> bool:
    """Whether the admin integration is actually serving SSO.

    The same two conditions ``SSOAdminSiteMixin._sso_enabled`` applies, because
    a check that disagreed with the site about whether SSO is on would be
    reporting on a deployment that does not exist.
    """
    return bool(get_setting("ADMIN").get("enabled", True) and connections)


def _connections_are_reachable() -> bool:
    """Whether any request in this project can reach a connection at all.

    Two doors. The admin integration is one, and it is open by default. The
    login routes are the other, and they are open the moment ``bastion.urls``
    is included -- a connection is reachable at ``/sso/login/<name>/`` whatever
    the admin is doing, so a deployment that turned the admin integration off
    and left the routes wired has not turned SSO off.

    Anything unexpected while resolving that counts as reachable. Downgrading
    a real error on the strength of a URLConf we could not read is the wrong
    way round.
    """
    if get_setting("ADMIN").get("enabled", True):
        return True

    from django.urls import NoReverseMatch, reverse

    try:
        reverse("bastion:callback")
    except NoReverseMatch:
        return False
    except Exception:  # pragma: no cover - a URLConf Django will report itself
        return True
    return True


def _admin_connection_names() -> list[tuple[str, str]]:
    """Every place a connection is named for the admin, with where it came from.

    Two of them, and the class attribute wins:
    ``SSOAdminSiteMixin._connection_name`` reads ``self.sso_connection or
    ADMIN["connection"]``. Checking only the setting would validate the pointer
    that loses and pass a site whose ``sso_connection`` is a typo.
    """
    found: list[tuple[str, str]] = []

    configured = get_setting("ADMIN").get("connection")
    if configured is not None:
        found.append(('ADMIN["connection"]', str(configured)))

    # The admin is optional, and a check must not be the thing that requires it.
    try:
        from django.contrib.admin.sites import all_sites

        from bastion.admin.site import SSOAdminSiteMixin
    except ImportError:  # pragma: no cover - django.contrib.admin not installed
        return found

    for site in all_sites:
        name = getattr(site, "sso_connection", None)
        if isinstance(site, SSOAdminSiteMixin) and name is not None:
            found.append((f"{type(site).__name__}.sso_connection", str(name)))
    return found


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
                    "once, from a pinned domain, and then pins to the subject."
                ),
                id="bastion.E026",
            )
        ]
    return []
