"""Provider quirks and normalisation into IdentityClaims."""

from __future__ import annotations

from typing import Any

import pytest

from bastion.claims import GroupFormat, Verified
from bastion.exceptions import ClaimValidationError
from bastion.protocols.oidc.quirks import (
    REGISTRY,
    EntraQuirks,
    GenericQuirks,
    GoogleQuirks,
    KeycloakQuirks,
    OktaQuirks,
    to_identity_claims,
)
from tests.idp.provider import FakeIdP


def normalise(claims: dict[str, Any], quirks: Any, issuer: str = "https://idp.example.test") -> Any:
    return to_identity_claims(claims, quirks=quirks, issuer=issuer)


class TestSubjectResolution:
    def test_generic_uses_sub(self, idp: FakeIdP) -> None:
        identity = normalise(dict(idp.base_claims()), GenericQuirks())
        assert identity.subject == "user-0001"
        assert identity.subject_source == "sub"

    def test_entra_uses_oid_not_sub(self, entra_idp: FakeIdP) -> None:
        """The single most consequential vendor quirk in the package.

        Entra's sub is pairwise per application registration, so an account
        keyed on it breaks silently the moment a deployment adds a second
        client id.
        """
        claims = dict(entra_idp.base_claims(subject="alice"))
        identity = normalise(claims, EntraQuirks())
        assert identity.subject == "oid-alice"
        assert identity.subject_source == "oid"
        assert identity.subject != claims["sub"]

    def test_entra_without_oid_is_rejected(self) -> None:
        with pytest.raises(ClaimValidationError, match="pairwise"):
            normalise({"sub": "pairwise-value"}, EntraQuirks())

    def test_missing_sub_is_rejected(self) -> None:
        with pytest.raises(ClaimValidationError):
            normalise({"email": "a@b.test"}, GenericQuirks())

    def test_subject_source_is_recorded_on_the_identity(self, entra_idp: FakeIdP) -> None:
        """Recorded so a configuration change is detectable rather than
        silently re-linking accounts."""
        identity = normalise(dict(entra_idp.base_claims()), EntraQuirks())
        assert identity.subject_source == "oid"


class TestTenantPinning:
    def test_entra_tid_mismatch_is_rejected(self, entra_idp: FakeIdP) -> None:
        quirks = EntraQuirks(expected_tenant="some-other-tenant")
        with pytest.raises(ClaimValidationError, match="tid"):
            normalise(dict(entra_idp.base_claims()), quirks)

    def test_entra_tid_match_passes(self, entra_idp: FakeIdP) -> None:
        quirks = EntraQuirks(expected_tenant="tenant-0001")
        assert normalise(dict(entra_idp.base_claims()), quirks)

    def test_google_hd_mismatch_is_rejected(self, google_idp: FakeIdP) -> None:
        """hd is the only tenant boundary Google offers. Without this check any
        personal Google account satisfies a Workspace login."""
        quirks = GoogleQuirks(hosted_domain="corp.example")
        with pytest.raises(ClaimValidationError, match="hd"):
            normalise(dict(google_idp.base_claims()), quirks)

    def test_google_hd_match_passes(self, google_idp: FakeIdP) -> None:
        quirks = GoogleQuirks(hosted_domain="example.test")
        assert normalise(dict(google_idp.base_claims()), quirks)

    def test_unpinned_providers_skip_the_check(self, google_idp: FakeIdP) -> None:
        assert normalise(dict(google_idp.base_claims()), GoogleQuirks())


class TestGroups:
    def test_entra_groups_are_opaque_ids(self, entra_idp: FakeIdP) -> None:
        claims = dict(entra_idp.with_groups(["eng-admins"]))
        identity = normalise(claims, EntraQuirks())
        assert identity.group_value_format is GroupFormat.OPAQUE_ID
        assert identity.groups_complete is True

    def test_entra_overage_marks_the_list_incomplete(self, entra_idp: FakeIdP) -> None:
        """The pointer to Graph is not an empty group list. Treating it as one
        would strip every group-derived permission."""
        claims = dict(entra_idp.with_group_overage())
        identity = normalise(claims, EntraQuirks())
        assert identity.groups == ()
        assert identity.groups_complete is False

    def test_overage_blocks_privilege_escalation(self, entra_idp: FakeIdP) -> None:
        identity = normalise(dict(entra_idp.with_group_overage()), EntraQuirks())
        assert identity.may_escalate_privileges() is False

    def test_a_complete_list_permits_escalation(self, entra_idp: FakeIdP) -> None:
        identity = normalise(dict(entra_idp.with_groups(["eng-admins"])), EntraQuirks())
        assert identity.may_escalate_privileges() is True

    def test_okta_groups_are_display_names(self, okta_idp: FakeIdP) -> None:
        identity = normalise(dict(okta_idp.with_groups(["eng-admins"])), OktaQuirks())
        assert identity.groups == ("eng-admins",)
        assert identity.group_value_format is GroupFormat.DISPLAY_NAME

    def test_keycloak_rooted_paths_are_detected(self, keycloak_idp: FakeIdP) -> None:
        identity = normalise(dict(keycloak_idp.with_groups(["eng"])), KeycloakQuirks())
        assert identity.groups == ("/eng",)
        assert identity.group_value_format is GroupFormat.FULL_PATH

    def test_keycloak_unrooted_names_are_detected(self) -> None:
        """The mapper's path toggle changes the shape; a rule written against
        one silently fails against the other, so the format travels along."""
        identity = normalise({"sub": "x", "groups": ["eng"]}, KeycloakQuirks())
        assert identity.group_value_format is GroupFormat.DISPLAY_NAME

    def test_google_reports_groups_as_unknown_not_empty(self, google_idp: FakeIdP) -> None:
        """Google's ID token structurally has no group claim. Reporting an
        empty but complete list would assert non-membership on evidence that
        does not exist."""
        identity = normalise(dict(google_idp.base_claims()), GoogleQuirks())
        assert identity.groups == ()
        assert identity.groups_complete is False
        assert identity.may_escalate_privileges() is False

    def test_a_scalar_group_claim_is_tolerated(self) -> None:
        identity = normalise({"sub": "x", "groups": "solo"}, GenericQuirks())
        assert identity.groups == ("solo",)

    def test_a_malformed_group_claim_yields_nothing(self) -> None:
        identity = normalise({"sub": "x", "groups": [1, 2, 3]}, GenericQuirks())
        assert identity.groups == ()


class TestEmailVerified:
    def test_google_reports_verified(self, google_idp: FakeIdP) -> None:
        identity = normalise(dict(google_idp.base_claims()), GoogleQuirks())
        assert identity.email_verified is Verified.YES

    def test_entra_reports_unknown(self, entra_idp: FakeIdP) -> None:
        """Entra emits no email_verified at all. Defaulting to False would
        break every Entra login; defaulting to True would be a hole."""
        identity = normalise(dict(entra_idp.base_claims()), EntraQuirks())
        assert identity.email_verified is Verified.UNKNOWN

    def test_entra_honours_xms_edov_when_present(self, entra_idp: FakeIdP) -> None:
        claims = dict(entra_idp.base_claims())
        claims["xms_edov"] = True
        assert normalise(claims, EntraQuirks()).email_verified is Verified.YES

    def test_explicit_false_is_distinct_from_unknown(self) -> None:
        identity = normalise({"sub": "x", "email_verified": False}, GenericQuirks())
        assert identity.email_verified is Verified.NO

    def test_unknown_is_falsey_so_callers_fail_closed(self) -> None:
        identity = normalise({"sub": "x"}, GenericQuirks())
        assert not identity.email_verified


class TestMfa:
    def test_entra_multipleauthn_counts(self, entra_idp: FakeIdP) -> None:
        claims = dict(entra_idp.base_claims())
        claims["amr"] = ["pwd", "multipleauthn"]
        assert normalise(claims, EntraQuirks()).mfa_satisfied is True

    def test_okta_mfa_counts(self, okta_idp: FakeIdP) -> None:
        claims = dict(okta_idp.base_claims())
        claims["amr"] = ["pwd", "mfa"]
        assert normalise(claims, OktaQuirks()).mfa_satisfied is True

    def test_password_alone_does_not(self) -> None:
        identity = normalise({"sub": "x", "amr": ["pwd"]}, GenericQuirks())
        assert identity.mfa_satisfied is False

    def test_absent_amr_does_not(self) -> None:
        """amr is opt-in on Entra SAML, Google and Keycloak, so absence is
        common and must not be read as success."""
        assert normalise({"sub": "x"}, GenericQuirks()).mfa_satisfied is False

    def test_vendor_specific_values_are_not_shared(self) -> None:
        """multipleauthn is an Entra value. A generic provider emitting it
        proves nothing, so the sets are per-provider rather than a union."""
        identity = normalise({"sub": "x", "amr": ["multipleauthn"]}, GenericQuirks())
        assert identity.mfa_satisfied is False


class TestNormalisation:
    def test_raw_claims_are_preserved(self, idp: FakeIdP) -> None:
        claims = dict(idp.base_claims())
        identity = normalise(claims, GenericQuirks())
        assert identity.raw["iss"] == claims["iss"]

    def test_identity_key_never_uses_email(self, idp: FakeIdP) -> None:
        identity = normalise(dict(idp.base_claims()), GenericQuirks())
        assert identity.identity_key == (identity.issuer, "user-0001")

    def test_display_name_falls_back_to_preferred_username(self) -> None:
        identity = normalise({"sub": "x", "preferred_username": "alice"}, GenericQuirks())
        assert identity.display_name == "alice"

    def test_timestamps_are_timezone_aware(self, idp: FakeIdP) -> None:
        identity = normalise(dict(idp.base_claims()), GenericQuirks())
        assert identity.expires_at is not None
        assert identity.expires_at.tzinfo is not None


class TestRegistry:
    @pytest.mark.parametrize("identifier", ["generic", "entra", "okta", "google", "keycloak"])
    def test_every_provider_is_registered_under_its_identifier(self, identifier: str) -> None:
        assert REGISTRY[identifier].identifier == identifier
