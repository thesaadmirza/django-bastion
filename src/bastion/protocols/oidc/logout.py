"""Logout token validation, for OIDC Back-Channel Logout 1.0.

Kept apart from ``validation.py`` on purpose. A logout token is not an ID token
with a different payload: four of its rules exist only here, and two of them
invert what the ID token path does.

``events`` is required and must carry the back-channel logout member. ``nonce``
is *forbidden* rather than optional, because a logout token arriving with one is
an ID token being replayed at this endpoint by someone hoping the two paths
share a validator. ``sub`` alone is not enough to identify what to end, and
neither is ``sid``, but one of them must be there. And ``jti`` is required,
because single use is the only thing standing between a captured logout token
and an attacker who can end a person's session whenever they like.

Sharing a validator between the two token types is how one of those rules ends
up skipped for the path nobody was thinking about, so they do not share one.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from bastion.exceptions import (
    AudienceMismatch,
    ClaimValidationError,
    IssuerMismatch,
    TokenExpired,
)
from bastion.protocols.oidc.jose import VerifiedToken
from bastion.protocols.oidc.validation import MAX_CLOCK_SKEW, _audiences, _timestamp

#: The member name that has to be present in ``events``. Spelled out rather
#: than pattern-matched: the specification names exactly this string, and a
#: prefix match would accept a neighbouring event type as a logout.
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

#: How old a logout token may be and still be acted on.
#:
#: The specification does not set one. It is needed anyway, for a reason that is
#: really about storage: single use is enforced by remembering every ``jti``,
#: and a table that has to remember them forever is a table that grows forever.
#: Bounding the age bounds how long a ``jti`` has to be remembered, which is
#: what makes the replay defence affordable to keep.
MAX_AGE = dt.timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class LogoutRequest:
    """What a valid logout token is asking for.

    ``sid`` ends one session and ``subject`` alone ends every session that
    identity holds. Both may be present, and then ``sid`` is the narrower
    reading and the one to honour.
    """

    issuer: str
    subject: str | None
    sid: str | None
    jti: str
    expires_at: dt.datetime

    @property
    def ends_every_session(self) -> bool:
        """Whether this ends everything for the subject rather than one session.

        Spelled as a property so the caller reads the intent rather than
        rediscovering the precedence rule at each call site.
        """
        return self.sid is None


def validate_logout_token(
    token: VerifiedToken,
    *,
    issuer: str,
    client_id: str,
    now: dt.datetime,
    clock_skew: dt.timedelta = dt.timedelta(seconds=60),
) -> LogoutRequest:
    """Validate a signature-verified logout token.

    The signature is somebody else's job and must already have been done:
    ``verify_compact`` against the same JWKS the ID tokens are checked with.
    This decides whether the contents are acceptable, and returns what to end.

    Everything raises. Nothing here returns a value a caller could forget to
    check, because the caller is about to destroy sessions on the strength of
    it.
    """
    if clock_skew < dt.timedelta(0):
        raise ClaimValidationError("clock_skew cannot be negative")
    if clock_skew > MAX_CLOCK_SKEW:
        raise ClaimValidationError(
            f"clock_skew of {clock_skew} exceeds the {MAX_CLOCK_SKEW} ceiling"
        )

    claims: Mapping[str, Any] = token.claims

    # Exact match, as everywhere else. A trailing slash is a different issuer.
    if claims.get("iss") != issuer:
        raise IssuerMismatch("logout token issuer does not match the connection")

    if client_id not in _audiences(claims):
        raise AudienceMismatch("logout token was not issued for this client")

    _reject_a_replayed_id_token(claims)
    _require_the_logout_event(claims)

    subject = claims.get("sub")
    if subject is not None and not isinstance(subject, str):
        raise ClaimValidationError("sub is not a string")
    sid = claims.get("sid")
    if sid is not None and not isinstance(sid, str):
        raise ClaimValidationError("sid is not a string")
    if not subject and not sid:
        raise ClaimValidationError("logout token carries neither sub nor sid")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        # Without it there is nothing to remember, so the same token could be
        # presented forever. Refusing is the only way to keep single use real.
        raise ClaimValidationError("jti is required so the token can be used once")

    issued_at = _timestamp(claims, "iat")
    if issued_at is None:
        raise ClaimValidationError("iat is required")
    if issued_at > now + clock_skew:
        raise ClaimValidationError("iat is in the future")
    if now - issued_at > MAX_AGE + clock_skew:
        raise TokenExpired(f"logout token is older than {MAX_AGE}")

    # ``exp`` is optional here, unlike on an ID token. Honoured when sent, and
    # never used to extend the window: whichever of the two expires first wins,
    # so a provider cannot ask us to remember a jti for longer than MAX_AGE.
    expires_at = issued_at + MAX_AGE
    stated = _timestamp(claims, "exp")
    if stated is not None:
        if now - clock_skew >= stated:
            raise TokenExpired("logout token has expired")
        expires_at = min(expires_at, stated)

    return LogoutRequest(
        issuer=issuer,
        subject=subject or None,
        sid=sid or None,
        jti=jti,
        expires_at=expires_at,
    )


def _reject_a_replayed_id_token(claims: Mapping[str, Any]) -> None:
    """Refuse a token carrying ``nonce``.

    Back-Channel Logout 1.0 section 2.4 makes this a MUST, and the reason is
    concrete rather than tidy: ``nonce`` is an ID token claim, so a token
    carrying one is an ID token. Accepting it would let anyone holding a
    captured ID token end the session it belongs to by posting it here.
    """
    if "nonce" in claims:
        raise ClaimValidationError("logout token carries a nonce, so it is an ID token")


def _require_the_logout_event(claims: Mapping[str, Any]) -> None:
    """Refuse anything that does not declare itself a back-channel logout.

    The ``events`` claim is what separates a logout token from every other
    security event token a provider might send to a URL it has on file. The
    specification pins the shape exactly: an object, containing this member,
    whose own value is an empty object.
    """
    events = claims.get("events")
    if not isinstance(events, dict):
        raise ClaimValidationError("events is missing or is not an object")
    if BACKCHANNEL_LOGOUT_EVENT not in events:
        raise ClaimValidationError("events does not declare a back-channel logout")
    if not isinstance(events[BACKCHANNEL_LOGOUT_EVENT], dict):
        # The specification says the member's value is a JSON object. Anything
        # else means the sender is describing something we do not understand,
        # and guessing what it meant is not a thing to do before ending
        # somebody's session.
        raise ClaimValidationError("the back-channel logout event is not an object")
