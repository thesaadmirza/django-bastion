"""Ask the provider whether a redirect URI is registered.

``redirect_uri_mismatch`` is the most common way an OIDC integration fails and
the hardest to see from inside the application: the settings are right, the URL
is right, and the provider still refuses. Nothing local can tell you whether a
console edit propagated, or landed on a different client.

One authorization request settles it. No client secret is involved, and the
flow is abandoned where it starts -- no code is exchanged, so no token is ever
issued and nothing is stored. The ``state``, ``nonce`` and PKCE verifier are
generated for this request and thrown away, so no transaction record exists and
there is nothing for a later callback to replay.

The classifier is separate from the request on purpose. Every provider says
this differently and some say it badly, so the rules below are the part worth
testing, and they are testable without a network.
"""

from __future__ import annotations

import base64
import binascii
import enum
import hashlib
import http.client
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from bastion.protocols.oidc.transport import require_https

#: Enough of the provider's page to classify it. An authorization endpoint that
#: answers with megabytes is not one whose answer improves after the first few
#: kilobytes, and this runs against a host we only half-trust.
MAX_BODY = 256 * 1024

#: Query parameters whose value is an encoded error rather than a readable one.
#:
#: Google redirects to /signin/oauth/error with the OAuth error base64ed into
#: `authError`, so `invalid_client` appears nowhere in the response as text and
#: a plain substring search sees a redirect with nothing in it.
_ENCODED_PARAMS = ("autherror",)

#: Markers that a sign-in form was served. Deliberately short: a false positive
#: here reports a broken deployment as healthy, which is worse than a shrug.
_SIGN_IN_MARKERS = ('name="loginfmt"', "convergedsignin", 'name="password"', 'id="password"')


class Registration(enum.Enum):
    """What the provider's answer establishes."""

    REGISTERED = "registered"
    NOT_REGISTERED = "not_registered"
    #: The URI could not be judged because the client id was refused first.
    CLIENT_REJECTED = "client_rejected"
    #: The provider answered something this cannot read. Not a pass.
    INCONCLUSIVE = "inconclusive"


#: What the providers say, by code where they publish one and by phrase where
#: they only write prose.
#:
#: Phrases as well as codes because a code list is never finished: this was
#: written against AADSTS700016 and 90002, and the first run against a live
#: endpoint met 700038. "not a valid application identifier" covers the ones
#: Microsoft has not minted yet.
_RULES: tuple[tuple[str, Registration], ...] = (
    # The redirect URI itself, which is the question being asked.
    (r"redirect_uri_mismatch|invalid_redirect_uri|aadsts50011", Registration.NOT_REGISTERED),
    (r"(reply|redirect) url .{0,60}(does not match|not registered)", Registration.NOT_REGISTERED),
    (r"redirect_uri .{0,40}(does not match|is not valid)", Registration.NOT_REGISTERED),
    # The client, refused before the URI could be considered.
    (r"unauthorized_client|invalid_client", Registration.CLIENT_REJECTED),
    (r"aadsts(700016|700038|7000112|90002)", Registration.CLIENT_REJECTED),
    (r"not a valid (application|client) identifier", Registration.CLIENT_REJECTED),
    (r"(application|client) .{0,60}was not found", Registration.CLIENT_REJECTED),
)


@dataclass(frozen=True, slots=True)
class Probe:
    verdict: Registration
    detail: str


def build_authorize_url(
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scopes: tuple[str, ...] = ("openid",),
) -> str:
    """An authorization request that is never completed.

    Carries a real PKCE challenge because some providers reject a request
    without one, and a real ``state`` because some reject that too. Both are
    discarded when this returns: the point is the provider's answer to the
    ``redirect_uri``, not a login.
    """
    require_https(authorization_endpoint, what="authorization_endpoint")
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    query = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": secrets.token_urlsafe(16),
            "nonce": secrets.token_urlsafe(16),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    separator = "&" if "?" in authorization_endpoint else "?"
    return f"{authorization_endpoint}{separator}{query}"


def classify(*, status: int, location: str | None, body: str, redirect_uri: str) -> Probe:
    """Read the provider's answer. Pure, and the part that carries the rules.

    Order matters. A redirect back to our own URI is checked first because it
    is the only positive proof available: RFC 6749 section 4.1.2.1 requires an
    authorization server **not** to redirect to a URI it has not registered, so
    arriving there settles the question even when the redirect carries an
    error. ``redirect_uri_mismatch`` is never delivered that way -- it cannot
    be, since delivering it would mean using the URI under suspicion.

    Everything after that is negative evidence or a shrug. Nothing here reports
    success on the absence of an error: Entra answers a bad client id with HTTP
    200 and an HTML page containing no OAuth error parameter, so "no error
    seen" reported a broken deployment as healthy.
    """
    if location and _same_endpoint(location, redirect_uri):
        return Probe(
            Registration.REGISTERED,
            "The provider redirected to this exact URI, which it will not do "
            "for one it has not registered.",
        )

    haystack = f"{location or ''}\n{_decoded_errors(location)}\n{body}".lower()

    for pattern, outcome in _RULES:
        match = re.search(pattern, haystack)
        if not match:
            continue
        said = match.group(0)
        if outcome is Registration.NOT_REGISTERED:
            return Probe(outcome, f"The provider answered with {said!r}.")
        return Probe(
            outcome,
            f"The provider answered with {said!r}, so the client id was "
            "refused before the redirect URI could be judged.",
        )

    if any(marker in haystack for marker in _SIGN_IN_MARKERS):
        return Probe(
            Registration.REGISTERED,
            "The provider served its sign-in page, which it does only after "
            "accepting the client id and the redirect URI.",
        )

    return Probe(
        Registration.INCONCLUSIVE,
        f"The provider answered {status} with no sign-in form and no error this recognises.",
    )


def _decoded_errors(location: str | None) -> str:
    """Readable text out of any base64-encoded error parameter in a redirect.

    Only the parameter names in ``_ENCODED_PARAMS`` are decoded. Sniffing every
    parameter for something base64-shaped would eventually decode an opaque
    token into bytes that happen to contain one of the phrases above, and a
    false match here reports a working deployment as broken.
    """
    if not location:
        return ""

    found = []
    query = urllib.parse.urlsplit(location).query
    for name, values in urllib.parse.parse_qs(query).items():
        if name.lower() not in _ENCODED_PARAMS:
            continue
        for value in values:
            padded = value + "=" * (-len(value) % 4)
            try:
                decoded = base64.urlsafe_b64decode(padded)
            except (ValueError, binascii.Error):
                # Not base64 after all. Nothing to log and nothing to report:
                # this only ever adds to the haystack, so a parameter that does
                # not decode simply contributes nothing.
                decoded = b""
            found.append(decoded.decode("utf-8", "replace"))
    return "\n".join(found)


def _same_endpoint(location: str, redirect_uri: str) -> bool:
    """Whether a Location header points at our callback.

    Compared by scheme, host and path rather than by prefix. A prefix test
    treats ``https://example.com.attacker.test/sso/callback/`` as a match for
    ``https://example.com/sso/callback/``, and this function's answer is the
    one thing that reports success.
    """
    ours = urllib.parse.urlsplit(redirect_uri)
    theirs = urllib.parse.urlsplit(urllib.parse.urljoin(redirect_uri, location))
    return (
        ours.scheme.lower() == theirs.scheme.lower()
        and ours.netloc.lower() == theirs.netloc.lower()
        and ours.path == theirs.path
    )


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Read the redirect instead of following it.

    Following would send this at whatever the provider names, which on a
    misconfigured client is an arbitrary host, and would lose the Location
    header that carries the answer.
    """

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def probe_registration(
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    timeout: float = 15.0,
    opener: Any = None,
) -> Probe:
    """Issue the request and classify the answer."""
    url = build_authorize_url(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
    )
    # S310 wants the scheme audited. build_authorize_url ran require_https on
    # the endpoint above, so file: and friends never reach here.
    request = urllib.request.Request(  # noqa: S310
        url,
        headers={"Accept": "text/html,application/json", "User-Agent": "django-bastion doctor"},
        method="GET",
    )
    opener = opener or urllib.request.build_opener(_NoRedirects)

    try:
        with opener.open(request, timeout=timeout) as response:
            return classify(
                status=response.status,
                location=response.headers.get("Location"),
                body=_read_capped(response),
                redirect_uri=redirect_uri,
            )
    except urllib.error.HTTPError as exc:
        # A suppressed redirect arrives here, and so does a 4xx. Both carry the
        # answer.
        with exc:
            return classify(
                status=exc.code,
                location=exc.headers.get("Location"),
                body=_read_capped(exc),
                redirect_uri=redirect_uri,
            )
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        return Probe(
            Registration.INCONCLUSIVE,
            f"The authorization endpoint could not be reached: {exc}",
        )


def _read_capped(response: Any) -> str:
    body: bytes = response.read(MAX_BODY)
    return body.decode("utf-8", "replace")
