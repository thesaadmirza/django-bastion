"""Pre-flight checks for a configured deployment.

Most SSO debugging is a configuration typo three layers down, surfaced as a
failed login with no useful detail. This module walks the whole path before
anyone tries to use it.

It is deliberately honest about its limits. Several things an operator would
like verified simply cannot be, without a real person completing a real login:
whether the redirect URI is registered at the provider, whether the group claim
is actually emitted, whether MFA will be asserted. Those are reported as
"cannot verify" rather than quietly omitted, because a green run that silently
skipped the interesting question is worse than no run at all.
"""

from __future__ import annotations

import datetime as dt
import enum
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from bastion.conf import get_setting
from bastion.connections import Connection
from bastion.exceptions import BastionError
from bastion.protocols.oidc.jose import ALLOWED_ALGORITHMS

#: Beyond this, token validation starts failing for reasons that look like
#: anything but a clock.
CLOCK_SKEW_WARN = dt.timedelta(seconds=30)
CLOCK_SKEW_FAIL = dt.timedelta(seconds=120)


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


class Status(enum.Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    #: Checked nothing, because it cannot be checked from here.
    UNVERIFIABLE = "unverifiable"
    INFO = "info"

    @property
    def is_failure(self) -> bool:
        return self is Status.FAIL


@dataclass(frozen=True, slots=True)
class Result:
    name: str
    status: Status
    detail: str
    hint: str | None = None


@dataclass
class Report:
    connection: str | None
    results: list[Result] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(r.status.is_failure for r in self.results)

    @property
    def warned(self) -> bool:
        return any(r.status is Status.WARN for r in self.results)


def check_connection(connection: Connection, *, offline: bool = False) -> Report:
    """Run every check for one connection."""
    report = Report(connection=connection.identifier)
    report.results.extend(_config_checks(connection))
    if offline:
        report.results.append(
            Result(
                "network",
                Status.INFO,
                "Skipped every network check because --offline was given.",
            )
        )
        return report
    report.results.extend(_network_checks(connection))
    return report


def _config_checks(connection: Connection) -> Iterator[Result]:
    yield Result(
        "provider",
        Status.OK,
        f"Using the {connection.provider!r} quirks profile.",
        hint=(
            "The generic profile has no useful behaviour for groups or MFA. If "
            "this is a real provider, name it."
            if connection.provider == "generic"
            else None
        ),
    )

    if connection.client_secret:
        yield Result(
            "client authentication",
            Status.OK,
            f"Using {connection.auth_method.value}.",
        )
    else:
        yield Result(
            "client authentication",
            Status.WARN,
            "No client secret configured.",
            hint="Public clients rely entirely on PKCE. Confirm that is intended.",
        )

    if connection.grants_privileges:
        groups = connection.staff_groups + connection.superuser_groups
        yield Result(
            "group mapping",
            Status.UNVERIFIABLE,
            f"Configured to grant privileges from {_plural(len(groups), 'group name')}.",
            hint=(
                "Whether the provider actually emits a group claim, and in what "
                "format, cannot be established without a real login. Okta omits "
                "the claim unless configured; Entra sends object GUIDs rather "
                "than names; Google's ID token has no group claim at all. Sign "
                "in once and read the audit record before relying on this."
            ),
        )
    else:
        yield Result(
            "group mapping",
            Status.INFO,
            "No staff_groups or superuser_groups configured; no flags will be set.",
        )

    if connection.require_mfa:
        yield Result(
            "MFA requirement",
            Status.UNVERIFIABLE,
            "Logins will be refused unless the assertion shows a second factor.",
            hint=(
                "amr is opt-in on Entra SAML, Google and Keycloak. If the "
                "provider does not emit it, every login fails closed. Verify "
                "with one sign-in before enabling this in production."
            ),
        )


def _network_checks(connection: Connection) -> Iterator[Result]:
    try:
        metadata = connection.metadata()
    except BastionError as exc:
        yield Result(
            "discovery",
            Status.FAIL,
            f"{type(exc).__name__}: {exc}",
            hint="Nothing downstream can be checked until discovery succeeds.",
        )
        return

    yield Result("discovery", Status.OK, f"Fetched and validated for {metadata.issuer}.")

    yield from _algorithm_check(metadata)
    yield from _pkce_check(metadata)
    yield from _key_check(connection)
    yield from _clock_check(connection, metadata)

    if metadata.supports_rp_initiated_logout:
        yield Result("logout", Status.OK, "Provider supports RP-initiated logout.")
    else:
        yield Result(
            "logout",
            Status.WARN,
            "Provider publishes no end_session_endpoint.",
            hint=(
                "Signing out can only clear the local session. The next visit "
                "to a protected page will sign the person straight back in. "
                "Google is the common case here."
            ),
        )


def _pkce_check(metadata: Any) -> Iterator[Result]:
    """Report what the provider says about PKCE, without pretending to know.

    Discovery refuses a provider that advertises a method set without S256,
    since that is a stated refusal and S256 is all this package sends. Silence
    is not a refusal, though: RFC 8414 makes the field optional and Microsoft
    omits it while supporting S256 perfectly well. Treating that as a failure
    stopped every Entra deployment at startup and pushed people towards
    require_s256=False, which is the wrong switch for a metadata gap.
    """
    advertised = set(metadata.code_challenge_methods_supported)

    if "S256" in advertised:
        yield Result("PKCE", Status.OK, "Provider advertises S256.")
        return

    if not advertised:
        yield Result(
            "PKCE",
            Status.UNVERIFIABLE,
            "Provider advertises no code_challenge_methods_supported.",
            hint=(
                "The field is optional under RFC 8414 and its absence says "
                "nothing; Microsoft omits it and accepts S256. This package "
                "sends S256 and never `plain`, so a provider that genuinely "
                "does not support it will reject the authorization request. "
                "One sign-in settles it."
            ),
        )
        return

    yield Result(
        "PKCE",
        Status.FAIL,
        f"Provider advertises only {', '.join(sorted(advertised))}.",
        hint=(
            "S256 is the only method this package sends, so authorization "
            "would be refused. If the metadata understates what the provider "
            "accepts, set require_s256=False on the connection and record why."
        ),
    )


def _algorithm_check(metadata: Any) -> Iterator[Result]:
    advertised = set(metadata.id_token_signing_alg_values_supported)
    if not advertised:
        yield Result(
            "signing algorithms",
            Status.WARN,
            "Provider advertises no id_token_signing_alg_values_supported.",
            hint="Cannot confirm compatibility until a token arrives.",
        )
        return

    usable = advertised & ALLOWED_ALGORITHMS
    if usable:
        yield Result(
            "signing algorithms",
            Status.OK,
            f"Compatible: {', '.join(sorted(usable))}.",
        )
        return

    yield Result(
        "signing algorithms",
        Status.FAIL,
        f"Provider offers only {', '.join(sorted(advertised))}.",
        hint=(
            "None of those are accepted. Symmetric algorithms are refused "
            "deliberately: signing an ID token with the client secret is the "
            "substrate of the algorithm-confusion class. Configure the provider "
            "to use RS256 or another asymmetric algorithm."
        ),
    )


def _key_check(connection: Connection) -> Iterator[Result]:
    try:
        store = connection.key_store()
        store.prime()
    except BastionError as exc:
        yield Result(
            "signing keys",
            Status.FAIL,
            f"{type(exc).__name__}: {exc}",
            hint="Every login will fail while the key set is unreachable.",
        )
        return

    kids = store.kids
    yield Result(
        "signing keys",
        Status.OK,
        f"{_plural(len(kids), 'usable key')} published.",
        hint=(
            "Only one key is published. During a rotation the provider should "
            "publish both for a window; a single key means a rotation will cause "
            "a brief outage."
            if len(kids) == 1
            else None
        ),
    )


def _clock_check(connection: Connection, metadata: Any) -> Iterator[Result]:
    reader = getattr(connection.transport, "server_time", None)
    if reader is None:
        yield Result(
            "clock skew",
            Status.INFO,
            "Transport does not expose the provider's clock; skipped.",
        )
        return

    provider_now = reader(metadata.issuer)
    if provider_now is None:
        yield Result(
            "clock skew",
            Status.INFO,
            "Provider sent no usable Date header; skipped.",
        )
        return

    skew = abs(dt.datetime.now(tz=dt.UTC) - provider_now)
    hint = (
        "Skew produces the least informative failure in the flow: a token that "
        "verifies perfectly and is then rejected as expired or not yet valid, "
        "on a system where every other check passes. Fix time sync rather than "
        "widening the tolerance."
    )
    if skew >= CLOCK_SKEW_FAIL:
        yield Result("clock skew", Status.FAIL, f"{skew.total_seconds():.0f}s.", hint=hint)
    elif skew >= CLOCK_SKEW_WARN:
        yield Result("clock skew", Status.WARN, f"{skew.total_seconds():.0f}s.", hint=hint)
    else:
        yield Result("clock skew", Status.OK, f"{skew.total_seconds():.0f}s.")


def check_project() -> Report:
    """Checks that are about the project rather than one connection."""
    report = Report(connection=None)
    report.results.extend(_project_checks())
    return report


def _project_checks() -> Iterator[Result]:
    from django.conf import settings
    from django.urls import NoReverseMatch, reverse

    try:
        path = reverse("bastion:callback")
    except NoReverseMatch:
        yield Result(
            "urls",
            Status.FAIL,
            "bastion.urls is not included in the project URLconf.",
            hint='Add path("sso/", include("bastion.urls")) to urlpatterns.',
        )
    else:
        yield Result(
            "urls",
            Status.UNVERIFIABLE,
            f"Callback path is {path}",
            hint=(
                "Whether the absolute form of this is registered at the provider "
                "cannot be checked from here. It must match exactly, including "
                "scheme, host, port and trailing slash. Behind a proxy it also "
                "depends on SECURE_PROXY_SSL_HEADER being correct."
            ),
        )

    engine = getattr(settings, "SESSION_ENGINE", "")
    if engine.endswith("signed_cookies"):
        yield Result(
            "session engine",
            Status.WARN,
            "signed_cookies stores no server-side session state.",
            hint=(
                "Deprovisioning still works, because it rotates the session auth "
                "hash, but individual sessions cannot be enumerated or revoked."
            ),
        )
    else:
        yield Result("session engine", Status.OK, f"{engine or 'default'} supports revocation.")

    backends = list(getattr(settings, "AUTHENTICATION_BACKENDS", []))
    if not any(b.startswith("bastion.") for b in backends):
        yield Result(
            "auth backend",
            Status.FAIL,
            "No bastion backend is in AUTHENTICATION_BACKENDS.",
            hint='Add "bastion.backends.SSOBackend".',
        )
    else:
        yield Result("auth backend", Status.OK, "SSO backend is installed.")

    yield from _break_glass_checks()


def _break_glass_checks() -> Iterator[Result]:
    from bastion.breakglass.models import BreakGlassAccount

    config = get_setting("BREAK_GLASS")
    if not config.get("ENABLED"):
        yield Result(
            "break-glass",
            Status.WARN,
            "Disabled.",
            hint=(
                "An identity provider outage will lock everyone out, including "
                "whoever would fix it. Enable it, or document the out-of-band "
                "route you will use instead."
            ),
        )
        return

    if not config.get("ALERT_SINKS"):
        yield Result(
            "break-glass alerting",
            Status.FAIL,
            "Enabled with no ALERT_SINKS.",
            hint="Emergency access nobody is told about is a backdoor with paperwork.",
        )
    else:
        yield Result(
            "break-glass alerting",
            Status.UNVERIFIABLE,
            f"{len(config['ALERT_SINKS'])} sink(s) configured.",
            hint=(
                "Whether an alert actually arrives, through a channel that does "
                "not depend on the identity provider, is only established by "
                "running a drill. Use bastion_breakglass drill."
            ),
        )

    active = BreakGlassAccount.objects.active().count()
    if active == 0:
        yield Result(
            "break-glass accounts",
            Status.FAIL,
            "Enabled, but no active accounts exist.",
            hint="bastion_breakglass grant --user <name> --reason <why>",
        )
    elif active == 1:
        yield Result(
            "break-glass accounts",
            Status.WARN,
            "Only one active account.",
            hint="Two is the recommended minimum, so losing one is not losing all.",
        )
    else:
        yield Result("break-glass accounts", Status.OK, f"{active} active.")

    stale = BreakGlassAccount.objects.stale().count()
    if stale:
        yield Result(
            "break-glass validation",
            Status.WARN,
            f"{stale} account(s) not validated in 90 days.",
            hint="An emergency account nobody has tried is one nobody knows works.",
        )
