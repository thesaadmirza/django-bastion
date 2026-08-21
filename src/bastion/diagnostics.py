"""Pre-flight checks for a configured deployment.

Most SSO debugging is a configuration typo three layers down, surfaced as a
failed login with no useful detail. This module walks the whole path before
anyone tries to use it.

It is deliberately honest about its limits. Some things an operator would like
verified cannot be without a real person completing a real login: whether the
group claim is actually emitted, and whether MFA will be asserted. Those are
reported as "cannot verify" rather than quietly omitted, because a green run
that silently skipped the interesting question is worse than no run at all.

Whether the redirect URI is registered was on that list for a long time, and
should not have been. One authorization request answers it, without a client
secret and without issuing a token, because the flow is abandoned before the
code is exchanged. ``--check-registration`` does exactly that: off by default
only because it is the one check here that shows up in the provider's logs.
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


def check_connection(
    connection: Connection,
    *,
    offline: bool = False,
    registration_url: str | None = None,
) -> Report:
    """Run every check for one connection.

    ``registration_url`` opts into one extra request, to the provider's
    authorization endpoint, asking whether that exact callback URL is
    registered. Off unless asked for: it is the only check here that makes this
    process visible in the provider's logs.
    """
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
    report.results.extend(_network_checks(connection, registration_url=registration_url))
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
    elif connection.require_privileged_user and not connection.persist_refused_identities:
        yield Result(
            "group mapping",
            Status.WARN,
            "No staff_groups or superuser_groups, but this connection requires a "
            "privileged user and does not persist refused identities.",
            hint=(
                "Nothing can grant a flag from the claims, and no row survives a "
                "refusal to grant one on afterwards, so every first sign-in is "
                "refused and there is no way out of it through this connection. "
                "Configure the group lists, or set persist_refused_identities "
                "back to True and grant the first account in the admin."
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


def _network_checks(
    connection: Connection, *, registration_url: str | None = None
) -> Iterator[Result]:
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

    if registration_url is not None:
        yield _registration_check(connection, metadata, registration_url)

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


def _registration_check(connection: Connection, metadata: Any, callback_url: str) -> Result:
    """Ask the provider about the callback URL, rather than guessing.

    This was reported as unverifiable for a long time, and it is not: one
    authorization request answers it, needs no client secret, and issues no
    token because the flow is abandoned where it starts. The reason it stayed
    unverifiable is that a deployment had to guess whether a console edit had
    propagated, or landed on a different client, from a login that just failed.
    """
    from bastion.protocols.oidc.registration import Registration, probe_registration

    probe = probe_registration(
        authorization_endpoint=metadata.authorization_endpoint,
        client_id=connection.client_id,
        redirect_uri=callback_url,
    )

    status, hint = {
        Registration.REGISTERED: (
            Status.OK,
            None,
        ),
        Registration.NOT_REGISTERED: (
            Status.FAIL,
            "Register this exact string at the provider, trailing slash "
            "included. If you believe you already have, check that the edit "
            "was saved on this client id and not another, and that it has "
            "propagated -- some providers take a minute.",
        ),
        Registration.CLIENT_REJECTED: (
            Status.FAIL,
            "Fix the client id first. Nothing can be established about the "
            "redirect URI while the application itself is refused.",
        ),
        Registration.INCONCLUSIVE: (
            Status.UNVERIFIABLE,
            "Reported as unknown rather than passed. Nothing here treats the "
            "absence of a recognised error as success, because at least one "
            "provider answers a bad client id with HTTP 200 and an HTML page "
            "carrying no error parameter at all.",
        ),
    }[probe.verdict]

    return Result(
        "redirect uri",
        status,
        f"{probe.detail} Asked about {callback_url}",
        hint=hint,
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


#: Where the scheme in the callback URL came from, and what it depends on.
#: Printing the URL without this would trade one silent assumption for another.
_SCHEME_CAVEAT = {
    "proxy-header": (
        "Assumes your proxy actually sets {header}: {value}, which is what "
        "SECURE_PROXY_SSL_HEADER tells Django to read the scheme from. If the "
        "proxy does not set it, Django builds this as http:// instead and the "
        "provider rejects the sign-in with redirect_uri_mismatch."
    ),
    "ssl-redirect": (
        "Assumes TLS terminates in this process, since SECURE_SSL_REDIRECT is "
        "on and SECURE_PROXY_SSL_HEADER is not set. If TLS terminates at a "
        "proxy instead, Django sees every request as insecure: it redirects to "
        "https, the proxy forwards as http again, and the browser loops. Set "
        "SECURE_PROXY_SSL_HEADER."
    ),
    "plain": (
        "This is http://, not https://, and most providers refuse to register "
        "or redirect to a plain-http URI outside localhost. Nothing in settings "
        "says otherwise: SECURE_PROXY_SSL_HEADER is unset, so if TLS terminates "
        "at a load balancer Django believes every request is insecure and builds "
        "exactly this. That is the whole of the redirect_uri_mismatch class of "
        "failure, and it looks identical to a typo at the provider."
    ),
}


def _callback_url_result(path: str, base_url: str | None) -> Result:
    """The absolute callback URL, or the closest thing that can be derived.

    The path alone was what this reported, with the caveats in prose
    underneath, and prose is easy to read past when the line above it looks
    correct. A deployment behind a TLS-terminating load balancer without
    ``SECURE_PROXY_SSL_HEADER`` builds ``http://`` redirect URIs while the
    ``https://`` one is registered at the provider, and every sign-in fails
    with ``redirect_uri_mismatch`` -- with nothing in the output pointing at
    it, because the path was right.

    The scheme is knowable at check time. So it is shown, along with what its
    value depends on, and a plain-http result warns rather than passing.
    """
    if base_url:
        url = _url_from_base(path, base_url)
        secure = url.startswith("https://")
        return Result(
            "urls",
            Status.UNVERIFIABLE if secure else Status.WARN,
            f"Callback URL is {url}",
            hint=(
                "Register this exact string at the provider: scheme, host, port "
                "and trailing slash all have to match. It was assembled from "
                "--base-url, so it is what you say the deployment is reached "
                "on rather than what this process can prove."
            )
            if secure
            else _SCHEME_CAVEAT["plain"],
        )

    host, extra_hosts = _deployment_host()
    if host is None:
        return Result(
            "urls",
            Status.UNVERIFIABLE,
            f"Callback path is {path}",
            hint=(
                "The absolute URL cannot be assembled here: ALLOWED_HOSTS names "
                "no concrete host. Re-run with --base-url https://your.host to "
                "see the exact string the provider has to have registered, "
                "including the scheme, which is where this usually goes wrong."
            ),
        )

    scheme, origin = _inferred_scheme()
    url = f"{scheme}://{host}{path}"
    detail = f"Callback URL is {url}"
    if extra_hosts:
        detail += f" (first of {extra_hosts + 1} entries in ALLOWED_HOSTS)"

    return Result(
        "urls",
        Status.WARN if scheme == "http" else Status.UNVERIFIABLE,
        detail,
        hint=_SCHEME_CAVEAT[origin].format(**_proxy_header_parts())
        + " Whether it is registered at the provider still cannot be checked "
        "from here, and it must match exactly, trailing slash included.",
    )


def _url_from_base(path: str, base_url: str) -> str:
    """Join a stated base URL to the callback path. Scheme defaults to https."""
    from urllib.parse import urlsplit, urlunsplit

    split = urlsplit(base_url)
    return urlunsplit((split.scheme or "https", split.netloc or split.path, path, "", ""))


def resolve_callback_url(path: str, base_url: str | None) -> str | None:
    """The absolute callback URL, or ``None`` when no host is knowable.

    Shared with the registration probe, which asks the provider about this
    exact string. Two ways of assembling it would eventually disagree, and the
    one that got it wrong would be the one reporting success.
    """
    if base_url:
        return _url_from_base(path, base_url)

    host, _ = _deployment_host()
    if host is None:
        return None
    scheme, _ = _inferred_scheme()
    return f"{scheme}://{host}{path}"


def _deployment_host() -> tuple[str | None, int]:
    """The host to build the callback URL on, and how many others there were.

    ``ALLOWED_HOSTS`` is the only place a Django project states the names it
    answers to. Wildcards are skipped because they name nothing; a leading dot
    is a subdomain pattern, and the bare domain it also matches is the sensible
    thing to show. ``DEBUG`` with an empty list is Django's localhost default.
    """
    from django.conf import settings

    hosts = [str(h) for h in getattr(settings, "ALLOWED_HOSTS", [])]
    usable = [h.lstrip(".") for h in hosts if h and h != "*"]
    if usable:
        return usable[0], len(usable) - 1
    if not hosts and getattr(settings, "DEBUG", False):
        return "localhost:8000", 0
    return None, 0


def _proxy_header_parts() -> dict[str, str]:
    """``SECURE_PROXY_SSL_HEADER`` as a proxy is configured with it.

    The setting holds the WSGI ``META`` key, ``HTTP_X_FORWARDED_PROTO``. The
    person who has to check the proxy is looking for ``X-Forwarded-Proto``, so
    that is what gets printed.
    """
    from django.conf import settings

    configured = list(getattr(settings, "SECURE_PROXY_SSL_HEADER", None) or ())
    header = str(configured[0]) if configured else ""
    value = str(configured[1]) if len(configured) > 1 else ""
    wire = header.removeprefix("HTTP_").replace("_", "-").title()
    return {"header": wire or "the configured header", "value": value or "the configured value"}


def _inferred_scheme() -> tuple[str, str]:
    """What scheme ``request.build_absolute_uri`` would produce, and why.

    Django decides this per request from ``wsgi.url_scheme`` or from
    ``SECURE_PROXY_SSL_HEADER``, so no answer here is certain. Every branch
    returns the assumption it made along with the scheme, and the caller prints
    it: an unqualified guess about the scheme is what this check exists to stop
    producing.
    """
    from django.conf import settings

    if getattr(settings, "SECURE_PROXY_SSL_HEADER", None):
        return "https", "proxy-header"
    if getattr(settings, "SECURE_SSL_REDIRECT", False):
        return "https", "ssl-redirect"
    return "http", "plain"


def check_project(*, base_url: str | None = None) -> Report:
    """Checks that are about the project rather than one connection.

    ``base_url`` is the scheme and host the deployment is actually reached on,
    when the operator knows it. Without one the callback URL is assembled from
    settings and labelled with the assumptions that went into it.
    """
    report = Report(connection=None)
    report.results.extend(_project_checks(base_url=base_url))
    return report


def _project_checks(*, base_url: str | None = None) -> Iterator[Result]:
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
        yield _callback_url_result(path, base_url)

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

    if not config.get("ALLOWED_NETWORKS"):
        yield Result(
            "break-glass network",
            Status.WARN,
            "ALLOWED_NETWORKS is empty, so the emergency login answers anywhere.",
            hint=(
                "The same finding as bastion.W032 at startup. Restricting it is "
                "a real trade -- an allowlist your office is in is one the hotel "
                "you are in at 3am is not -- so this warns rather than fails."
            ),
        )
    else:
        yield Result(
            "break-glass network",
            Status.OK,
            f"{_plural(len(config['ALLOWED_NETWORKS']), 'network')} allowed.",
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
