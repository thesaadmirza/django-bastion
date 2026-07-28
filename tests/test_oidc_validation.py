"""Claim validation."""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

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
from bastion.protocols.oidc.validation import (
    MAX_CLOCK_SKEW,
    ValidationPolicy,
    validate_id_token,
    validate_userinfo,
)
from tests.idp.provider import DEFAULT_NOW, FakeIdP

ISSUER = "https://idp.example.test"
CLIENT_ID = "bastion-test-client"


def token_for(claims: dict[str, Any], alg: str = "RS256") -> VerifiedToken:
    return VerifiedToken(header={"alg": alg, "typ": "JWT"}, claims=claims)


@pytest.fixture
def claims(idp: FakeIdP) -> dict[str, Any]:
    return dict(idp.base_claims())


def validate(claims: dict[str, Any], **kwargs: Any) -> Any:
    kwargs.setdefault("issuer", ISSUER)
    kwargs.setdefault("client_id", CLIENT_ID)
    kwargs.setdefault("now", DEFAULT_NOW)
    kwargs.setdefault("nonce", "test-nonce")
    return validate_id_token(token_for(claims), **kwargs)


class TestControlCase:
    def test_a_good_token_validates(self, claims: dict[str, Any]) -> None:
        assert validate(claims)["sub"] == "user-0001"


class TestIssuer:
    def test_mismatch_is_rejected(self, claims: dict[str, Any]) -> None:
        claims["iss"] = "https://evil.example.test"
        with pytest.raises(IssuerMismatch):
            validate(claims)

    def test_trailing_slash_is_a_different_issuer(self, claims: dict[str, Any]) -> None:
        """Exact string match. Normalising here would mean accepting a token
        from an issuer we did not configure."""
        claims["iss"] = ISSUER + "/"
        with pytest.raises(IssuerMismatch):
            validate(claims)

    def test_missing_issuer_is_rejected(self, claims: dict[str, Any]) -> None:
        del claims["iss"]
        with pytest.raises(IssuerMismatch):
            validate(claims)


class TestAudience:
    def test_wrong_audience_is_rejected(self, claims: dict[str, Any]) -> None:
        claims["aud"] = "some-other-client"
        with pytest.raises(AudienceMismatch):
            validate(claims)

    def test_list_containing_us_is_accepted_with_azp(self, claims: dict[str, Any]) -> None:
        claims["aud"] = [CLIENT_ID, "another-client"]
        claims["azp"] = CLIENT_ID
        assert validate(claims)

    def test_multiple_audiences_without_azp_is_rejected(self, claims: dict[str, Any]) -> None:
        """Stricter than OIDC Core, which says SHOULD. A token minted for
        another client that lists us as a secondary audience must not
        authenticate anyone here."""
        claims["aud"] = [CLIENT_ID, "another-client"]
        with pytest.raises(AudienceMismatch):
            validate(claims)

    def test_the_strictness_can_be_relaxed_per_connection(self, claims: dict[str, Any]) -> None:
        """The escape hatch for a conformant provider that omits azp."""
        claims["aud"] = [CLIENT_ID, "another-client"]
        policy = ValidationPolicy(require_azp_when_multiple_audiences=False)
        assert validate(claims, policy=policy)

    def test_azp_naming_someone_else_is_rejected_even_when_relaxed(
        self, claims: dict[str, Any]
    ) -> None:
        claims["aud"] = [CLIENT_ID, "another-client"]
        claims["azp"] = "another-client"
        policy = ValidationPolicy(require_azp_when_multiple_audiences=False)
        with pytest.raises(AudienceMismatch):
            validate(claims, policy=policy)

    def test_malformed_audience_is_rejected(self, claims: dict[str, Any]) -> None:
        claims["aud"] = {"not": "a string or list"}
        with pytest.raises(AudienceMismatch):
            validate(claims)


class TestTimeWindow:
    def test_expired_token_is_rejected(self, claims: dict[str, Any]) -> None:
        with pytest.raises(TokenExpired):
            validate(claims, now=DEFAULT_NOW + dt.timedelta(seconds=400))

    def test_skew_permits_a_just_expired_token(self, claims: dict[str, Any]) -> None:
        # exp is now + 300; at now + 330 it is 30s expired, inside the 60s skew.
        assert validate(claims, now=DEFAULT_NOW + dt.timedelta(seconds=330))

    def test_missing_exp_is_rejected(self, claims: dict[str, Any]) -> None:
        del claims["exp"]
        with pytest.raises(ClaimValidationError):
            validate(claims)

    def test_not_yet_valid_is_rejected(self, claims: dict[str, Any]) -> None:
        claims["nbf"] = int((DEFAULT_NOW + dt.timedelta(hours=1)).timestamp())
        with pytest.raises(TokenNotYetValid):
            validate(claims)

    def test_future_iat_is_rejected(self, claims: dict[str, Any]) -> None:
        claims["iat"] = int((DEFAULT_NOW + dt.timedelta(hours=1)).timestamp())
        with pytest.raises(ClaimValidationError):
            validate(claims)

    def test_missing_iat_is_rejected(self, claims: dict[str, Any]) -> None:
        del claims["iat"]
        with pytest.raises(ClaimValidationError):
            validate(claims)

    def test_non_numeric_timestamp_is_rejected(self, claims: dict[str, Any]) -> None:
        claims["exp"] = "soon"
        with pytest.raises(ClaimValidationError):
            validate(claims)

    def test_boolean_timestamp_is_rejected(self, claims: dict[str, Any]) -> None:
        """bool is an int in Python, so this needs an explicit guard."""
        claims["exp"] = True
        with pytest.raises(ClaimValidationError):
            validate(claims)


class TestSkewPolicy:
    def test_skew_above_the_ceiling_is_a_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError):
            ValidationPolicy(clock_skew=MAX_CLOCK_SKEW + dt.timedelta(seconds=1))

    def test_negative_skew_is_a_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError):
            ValidationPolicy(clock_skew=dt.timedelta(seconds=-1))

    def test_the_ceiling_itself_is_allowed(self) -> None:
        assert ValidationPolicy(clock_skew=MAX_CLOCK_SKEW)


class TestNonce:
    def test_mismatch_is_rejected(self, claims: dict[str, Any]) -> None:
        with pytest.raises(NonceMismatch):
            validate(claims, nonce="a-different-transaction")

    def test_missing_nonce_when_one_was_expected_is_rejected(self, claims: dict[str, Any]) -> None:
        del claims["nonce"]
        with pytest.raises(NonceMismatch):
            validate(claims)

    def test_check_is_skipped_when_no_nonce_was_bound(self, claims: dict[str, Any]) -> None:
        assert validate(claims, nonce=None)


class TestMaxAge:
    def test_stale_authentication_is_rejected(self, claims: dict[str, Any]) -> None:
        with pytest.raises(ClaimValidationError):
            validate(
                claims,
                now=DEFAULT_NOW + dt.timedelta(seconds=200),
                max_age=dt.timedelta(seconds=60),
            )

    def test_fresh_authentication_passes(self, claims: dict[str, Any]) -> None:
        assert validate(claims, max_age=dt.timedelta(seconds=60))

    def test_missing_auth_time_when_max_age_requested_is_rejected(
        self, claims: dict[str, Any]
    ) -> None:
        del claims["auth_time"]
        with pytest.raises(ClaimValidationError):
            validate(claims, max_age=dt.timedelta(seconds=60))


class TestAccessTokenHash:
    def test_matching_hash_passes(self, idp: FakeIdP, claims: dict[str, Any]) -> None:
        access_token = idp.access_token()
        claims["at_hash"] = idp.at_hash(access_token)
        assert validate(claims, access_token=access_token)

    def test_mismatched_hash_is_rejected(self, idp: FakeIdP, claims: dict[str, Any]) -> None:
        claims["at_hash"] = idp.at_hash("a-different-token")
        with pytest.raises(AccessTokenHashMismatch):
            validate(claims, access_token=idp.access_token())

    def test_absent_hash_is_permitted_for_the_code_flow(
        self, idp: FakeIdP, claims: dict[str, Any]
    ) -> None:
        assert validate(claims, access_token=idp.access_token())

    def test_uncomputable_hash_fails_closed(self, claims: dict[str, Any]) -> None:
        """authlib CVE-2026-28498: the helper could not compute the hash for an
        unrecognised algorithm and reported success. Cannot compute means
        cannot confirm means reject."""
        claims["at_hash"] = "anything"
        token = token_for(claims, alg="Weird")
        with pytest.raises(AccessTokenHashMismatch):
            validate_id_token(
                token,
                issuer=ISSUER,
                client_id=CLIENT_ID,
                now=DEFAULT_NOW,
                nonce="test-nonce",
                access_token="at",
            )


class TestUserInfo:
    def test_matching_subject_passes(self) -> None:
        assert validate_userinfo({"sub": "alice"}, {"sub": "alice"})

    def test_different_subject_is_rejected(self) -> None:
        """OIDC Core 5.3.2 is a MUST. Skipping it lets an attacker who can
        influence the UserInfo response graft another person's profile onto an
        authenticated session."""
        with pytest.raises(SubjectMismatch):
            validate_userinfo({"sub": "mallory"}, {"sub": "alice"})

    def test_absent_subject_is_rejected(self) -> None:
        with pytest.raises(SubjectMismatch):
            validate_userinfo({"name": "no sub here"}, {"sub": "alice"})
