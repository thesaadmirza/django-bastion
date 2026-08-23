"""Logout token validation.

The rules that only exist here get the most attention: the forbidden ``nonce``,
the required ``events`` member, the requirement that something be named, and
the ``jti`` that makes single use possible at all.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from bastion.exceptions import (
    AudienceMismatch,
    ClaimValidationError,
    IssuerMismatch,
    TokenExpired,
)
from bastion.protocols.oidc.jose import VerifiedToken
from bastion.protocols.oidc.logout import (
    BACKCHANNEL_LOGOUT_EVENT,
    MAX_AGE,
    validate_logout_token,
)
from bastion.protocols.oidc.validation import MAX_CLOCK_SKEW

ISSUER = "https://idp.example.test"
CLIENT_ID = "bastion-test-client"
NOW = dt.datetime(2026, 8, 23, 12, 0, tzinfo=dt.UTC)


def claims(**overrides: Any) -> dict[str, Any]:
    """A logout token the specification would call valid."""
    base: dict[str, Any] = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": int(NOW.timestamp()),
        "jti": "token-1",
        "sub": "subject-1",
        "sid": "session-1",
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not _ABSENT}


_ABSENT = object()


def token(**overrides: Any) -> VerifiedToken:
    return VerifiedToken(header={"alg": "RS256", "typ": "JWT"}, claims=claims(**overrides))


def validate(tok: VerifiedToken, **kwargs: Any) -> Any:
    params: dict[str, Any] = {"issuer": ISSUER, "client_id": CLIENT_ID, "now": NOW}
    params.update(kwargs)
    return validate_logout_token(tok, **params)


class TestTheHappyPath:
    def test_a_well_formed_token_is_accepted(self) -> None:
        result = validate(token())
        assert result.sid == "session-1"
        assert result.subject == "subject-1"
        assert result.jti == "token-1"

    def test_sid_wins_over_subject(self) -> None:
        """Both may be present. The narrower reading is the one to honour."""
        assert validate(token()).ends_every_session is False

    def test_subject_alone_ends_everything(self) -> None:
        assert validate(token(sid=_ABSENT)).ends_every_session is True

    def test_sid_alone_is_enough(self) -> None:
        result = validate(token(sub=_ABSENT))
        assert result.subject is None
        assert result.sid == "session-1"

    def test_an_empty_sid_is_treated_as_absent(self) -> None:
        """A provider sending "" has named nothing, and the falsy-but-present
        case is exactly where a truthiness check would quietly end every
        session instead of one."""
        assert validate(token(sid="")).ends_every_session is True


class TestTheRulesThatOnlyExistHere:
    def test_a_nonce_is_refused(self) -> None:
        """A logout token carrying a nonce is an ID token. Accepting it would
        let anyone holding a captured ID token end that session."""
        with pytest.raises(ClaimValidationError, match="nonce"):
            validate(token(nonce="n-1"))

    def test_missing_events_is_refused(self) -> None:
        with pytest.raises(ClaimValidationError, match="events"):
            validate(token(events=_ABSENT))

    def test_events_that_is_not_an_object_is_refused(self) -> None:
        with pytest.raises(ClaimValidationError, match="events"):
            validate(token(events="logout"))

    def test_events_without_the_logout_member_is_refused(self) -> None:
        """Some other security event token, sent to a URL the provider has on
        file. Not ours to act on."""
        with pytest.raises(ClaimValidationError, match="back-channel logout"):
            validate(token(events={"http://schemas.openid.net/event/other": {}}))

    def test_a_logout_member_that_is_not_an_object_is_refused(self) -> None:
        with pytest.raises(ClaimValidationError, match="not an object"):
            validate(token(events={BACKCHANNEL_LOGOUT_EVENT: "yes"}))

    def test_neither_sub_nor_sid_is_refused(self) -> None:
        with pytest.raises(ClaimValidationError, match="neither sub nor sid"):
            validate(token(sub=_ABSENT, sid=_ABSENT))

    @pytest.mark.parametrize("value", [123, {"a": 1}, []])
    def test_a_non_string_sub_is_refused(self, value: Any) -> None:
        with pytest.raises(ClaimValidationError, match="sub"):
            validate(token(sub=value))

    @pytest.mark.parametrize("value", [123, {"a": 1}, []])
    def test_a_non_string_sid_is_refused(self, value: Any) -> None:
        with pytest.raises(ClaimValidationError, match="sid"):
            validate(token(sid=value))

    def test_a_missing_jti_is_refused(self) -> None:
        """Without it there is nothing to remember, so the token could be
        presented forever."""
        with pytest.raises(ClaimValidationError, match="jti"):
            validate(token(jti=_ABSENT))

    @pytest.mark.parametrize("value", ["", 7])
    def test_an_unusable_jti_is_refused(self, value: Any) -> None:
        with pytest.raises(ClaimValidationError, match="jti"):
            validate(token(jti=value))


class TestTheRulesSharedWithIdTokens:
    def test_a_different_issuer_is_refused(self) -> None:
        with pytest.raises(IssuerMismatch):
            validate(token(iss="https://elsewhere.test"))

    def test_a_trailing_slash_is_a_different_issuer(self) -> None:
        with pytest.raises(IssuerMismatch):
            validate(token(iss=ISSUER + "/"))

    def test_another_clients_token_is_refused(self) -> None:
        with pytest.raises(AudienceMismatch):
            validate(token(aud="someone-else"))

    def test_a_list_audience_containing_us_is_accepted(self) -> None:
        assert validate(token(aud=["someone-else", CLIENT_ID])).jti == "token-1"

    def test_a_missing_audience_is_refused(self) -> None:
        with pytest.raises(AudienceMismatch):
            validate(token(aud=_ABSENT))


class TestFreshness:
    def test_a_missing_iat_is_refused(self) -> None:
        with pytest.raises(ClaimValidationError, match="iat"):
            validate(token(iat=_ABSENT))

    def test_a_non_numeric_iat_is_refused(self) -> None:
        with pytest.raises(ClaimValidationError, match="iat"):
            validate(token(iat="soon"))

    def test_an_iat_in_the_future_is_refused(self) -> None:
        future = NOW + dt.timedelta(minutes=10)
        with pytest.raises(ClaimValidationError, match="future"):
            validate(token(iat=int(future.timestamp())))

    def test_an_iat_inside_the_skew_is_tolerated(self) -> None:
        """A provider clock running slightly fast is an operational fact."""
        near = NOW + dt.timedelta(seconds=30)
        assert validate(token(iat=int(near.timestamp()))).jti == "token-1"

    def test_a_token_older_than_the_window_is_refused(self) -> None:
        old = NOW - MAX_AGE - dt.timedelta(minutes=5)
        with pytest.raises(TokenExpired, match="older than"):
            validate(token(iat=int(old.timestamp())))

    def test_the_age_limit_is_the_window_plus_the_skew(self) -> None:
        """Pinning where the line actually falls, because it is not MAX_AGE.

        The skew allowance applies here as it does everywhere else, so a token
        is refused at MAX_AGE + skew rather than at MAX_AGE. Worth an assertion:
        the first version of this test sat exactly on the boundary and passed
        for the wrong reason.
        """
        skew = dt.timedelta(seconds=60)
        inside = NOW - MAX_AGE - skew + dt.timedelta(seconds=1)
        assert validate(token(iat=int(inside.timestamp())), clock_skew=skew).jti == "token-1"

        outside = NOW - MAX_AGE - skew - dt.timedelta(seconds=1)
        with pytest.raises(TokenExpired, match="older than"):
            validate(token(iat=int(outside.timestamp())), clock_skew=skew)

    def test_a_stated_exp_is_honoured(self) -> None:
        expired = NOW - dt.timedelta(seconds=90)
        with pytest.raises(TokenExpired, match="expired"):
            validate(token(exp=int(expired.timestamp())))

    def test_exp_never_extends_the_window(self) -> None:
        """A provider asking us to remember a jti for a year does not get to.

        The expiry that comes back is what bounds the replay table, so the
        shorter of the two has to win or the table grows without limit.
        """
        far = NOW + dt.timedelta(days=365)
        result = validate(token(exp=int(far.timestamp())))
        assert result.expires_at <= NOW + MAX_AGE

    def test_exp_shortens_the_window_when_it_is_sooner(self) -> None:
        soon = NOW + dt.timedelta(seconds=30)
        result = validate(token(exp=int(soon.timestamp())))
        assert result.expires_at == soon


class TestClockSkewBounds:
    def test_a_negative_skew_is_refused(self) -> None:
        with pytest.raises(ClaimValidationError, match="negative"):
            validate(token(), clock_skew=dt.timedelta(seconds=-1))

    def test_a_skew_above_the_ceiling_is_refused(self) -> None:
        """Widening this widens the window a captured token stays usable in."""
        with pytest.raises(ClaimValidationError, match="ceiling"):
            validate(token(), clock_skew=MAX_CLOCK_SKEW + dt.timedelta(seconds=1))

    def test_the_ceiling_itself_is_allowed(self) -> None:
        assert validate(token(), clock_skew=MAX_CLOCK_SKEW).jti == "token-1"
