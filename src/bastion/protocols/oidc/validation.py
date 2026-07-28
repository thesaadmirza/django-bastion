"""ID token claim validation.

Kept separate from signature verification on purpose. "Was this signed by a key
we trust" and "are its contents acceptable" are different questions, and
tangling them is how an ``iss`` check ends up skipped on one code path but not
another.

Everything here raises. Nothing returns a boolean that a caller could forget to
check.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from bastion.exceptions import (
    AccessTokenHashMismatch,
    AudienceMismatch,
    ClaimValidationError,
    ConfigurationError,
    IssuerMismatch,
    NonceMismatch,
    SubjectMismatch,
    TokenExpired,
    TokenNotYetValid,
)
from bastion.protocols.oidc.jose import VerifiedToken

#: Hard ceiling on clock skew tolerance. Configurable downward, never upward:
#: a deployment that needs more than two minutes has an NTP problem, and
#: widening the window to paper over it widens the replay window too.
MAX_CLOCK_SKEW = dt.timedelta(seconds=120)


@dataclass(frozen=True)
class ValidationPolicy:
    """Knobs, with defaults set to the strict end of every choice."""

    clock_skew: dt.timedelta = dt.timedelta(seconds=60)

    #: OIDC Core says a client SHOULD verify ``azp`` when the audience is
    #: multi-valued. We default to MUST.
    #:
    #: This is stricter than the specification, deliberately. It is the
    #: correct default -- a token minted for
    #: another client that happens to list us as a secondary audience should
    #: not authenticate anyone here -- but a conformant provider that emits a
    #: multi-valued ``aud`` without ``azp`` will be rejected, so the escape
    #: hatch exists and is per-connection.
    require_azp_when_multiple_audiences: bool = True

    #: Reject a token whose ``iat`` is further in the future than skew allows.
    #: A provider clock running fast is a real operational condition; a token
    #: issued an hour from now is not.
    reject_future_iat: bool = True

    def __post_init__(self) -> None:
        if self.clock_skew < dt.timedelta(0):
            raise ConfigurationError("clock_skew cannot be negative")
        if self.clock_skew > MAX_CLOCK_SKEW:
            raise ConfigurationError(
                f"clock_skew of {self.clock_skew} exceeds the {MAX_CLOCK_SKEW} ceiling. "
                "Widening this widens the replay window; fix time sync instead."
            )


def _timestamp(claims: Mapping[str, Any], name: str) -> dt.datetime | None:
    value = claims.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ClaimValidationError(f"{name} is not a numeric timestamp")
    try:
        return dt.datetime.fromtimestamp(value, tz=dt.UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ClaimValidationError(f"{name} is out of range") from exc


def _audiences(claims: Mapping[str, Any]) -> tuple[str, ...]:
    aud = claims.get("aud")
    if isinstance(aud, str):
        return (aud,)
    if isinstance(aud, Sequence) and all(isinstance(a, str) for a in aud):
        return tuple(aud)
    raise AudienceMismatch("aud is missing or not a string or list of strings")


def validate_id_token(
    token: VerifiedToken,
    *,
    issuer: str,
    client_id: str,
    now: dt.datetime,
    nonce: str | None = None,
    access_token: str | None = None,
    max_age: dt.timedelta | None = None,
    policy: ValidationPolicy | None = None,
) -> Mapping[str, Any]:
    """Validate a signature-verified ID token and return its claims.

    ``nonce`` is the value bound to this browser transaction, read from the
    server-side transaction record. Passing ``None`` skips the check and should
    only happen for flows that genuinely have no nonce.
    """
    policy = policy or ValidationPolicy()
    claims = token.claims
    skew = policy.clock_skew

    # Exact string match. A trailing slash is a different issuer.
    if claims.get("iss") != issuer:
        raise IssuerMismatch("issuer does not match the configured provider")

    audiences = _audiences(claims)
    if client_id not in audiences:
        raise AudienceMismatch("token was not issued for this client")

    if len(audiences) > 1:
        azp = claims.get("azp")
        if policy.require_azp_when_multiple_audiences and azp != client_id:
            raise AudienceMismatch("token has multiple audiences and azp does not name this client")
        if azp is not None and azp != client_id:
            raise AudienceMismatch("azp names a different client")

    expires_at = _timestamp(claims, "exp")
    if expires_at is None:
        raise ClaimValidationError("exp is required")
    if now - skew >= expires_at:
        raise TokenExpired("token has expired")

    not_before = _timestamp(claims, "nbf")
    if not_before is not None and now + skew < not_before:
        raise TokenNotYetValid("token is not yet valid")

    issued_at = _timestamp(claims, "iat")
    if issued_at is None:
        raise ClaimValidationError("iat is required")
    if policy.reject_future_iat and issued_at > now + skew:
        raise ClaimValidationError("iat is in the future")

    if nonce is not None and claims.get("nonce") != nonce:
        # Not a timing-sensitive comparison: the nonce is bound to a
        # server-side record the attacker cannot enumerate against.
        raise NonceMismatch("nonce does not match this transaction")

    if max_age is not None:
        authenticated_at = _timestamp(claims, "auth_time")
        if authenticated_at is None:
            raise ClaimValidationError("max_age was requested but auth_time is absent")
        if now - authenticated_at > max_age + skew:
            raise ClaimValidationError("authentication is older than the requested max_age")

    if access_token is not None:
        _validate_at_hash(claims, access_token, str(token.header.get("alg")))

    return claims


def _validate_at_hash(claims: Mapping[str, Any], access_token: str, alg: str) -> None:
    """Check ``at_hash`` against the access token.

    Computed here from the algorithm we already pinned, rather than asking a
    library. The failure mode being guarded is a helper that cannot compute the
    hash for an unrecognised algorithm and reports success anyway, which is
    authlib CVE-2026-28498.
    """
    import hashlib

    expected = claims.get("at_hash")
    if expected is None:
        # Absent is permitted for the code flow; the access token reached us
        # over TLS from the token endpoint rather than through the browser.
        return

    digests = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}
    digest = digests.get(alg[-3:])
    if digest is None:
        # Cannot compute, therefore cannot confirm, therefore reject. This is
        # the branch that must never return quietly.
        raise AccessTokenHashMismatch(f"cannot compute at_hash for algorithm {alg}")

    import base64

    raw = digest(access_token.encode()).digest()
    computed = base64.urlsafe_b64encode(raw[: len(raw) // 2]).rstrip(b"=").decode()
    if computed != expected:
        raise AccessTokenHashMismatch("at_hash does not match the access token")


def validate_userinfo(
    userinfo: Mapping[str, Any], id_token_claims: Mapping[str, Any]
) -> Mapping[str, Any]:
    """Confirm a UserInfo response belongs to the same subject.

    OIDC Core 5.3.2 makes this a MUST, and the consequence of skipping it is
    that an attacker who can influence the UserInfo response substitutes a
    different person's profile onto an authenticated session.
    """
    if userinfo.get("sub") != id_token_claims.get("sub"):
        raise SubjectMismatch("UserInfo sub does not match the ID token")
    return userinfo
