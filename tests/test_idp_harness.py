"""Tests for the synthetic IdP itself.

The corpus is only useful if it really contains what it claims to. A test that
asserts we reject `alg: none` proves nothing if the fixture quietly minted a
correctly-signed RS256 token instead. So the harness is verified before any
adapter exists to consume it.

Every test here is deliberately about *token structure*, not about our
verification logic, which does not exist yet.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from bastion.testing.keys import SigningKey
from bastion.testing.provider import FakeIdP
from tests.idp import tokens


def verify_rs256(token: str, key: SigningKey) -> bool:
    """Independent verifier, so harness tests do not depend on our own code."""
    header_b64, payload_b64, signature_b64 = token.split(".")
    padded = signature_b64 + "=" * (-len(signature_b64) % 4)
    signature = base64.urlsafe_b64decode(padded)
    try:
        key.public.verify(
            signature,
            f"{header_b64}.{payload_b64}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


class TestKeys:
    def test_thumbprint_is_stable(self, signing_key: SigningKey) -> None:
        assert signing_key.kid == signing_key.thumbprint()

    def test_thumbprint_matches_rfc7638_construction(self, signing_key: SigningKey) -> None:
        jwk = signing_key.public_jwk(include_meta=False)
        required = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
        canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        assert signing_key.kid == expected

    def test_distinct_keys_have_distinct_kids(
        self, signing_key: SigningKey, attacker_key: SigningKey
    ) -> None:
        assert signing_key.kid != attacker_key.kid

    def test_jwk_has_no_private_material(self, signing_key: SigningKey) -> None:
        assert set(signing_key.public_jwk()) == {"kty", "n", "e", "kid", "alg", "use"}

    def test_ec_key_signs_and_verifies(self, ec_key: SigningKey) -> None:
        token = tokens.sign({"alg": "ES256", "typ": "JWT"}, {"sub": "x"}, ec_key)
        # Raw r||s is 2 * 32 bytes for P-256; DER would be longer and variable.
        signature_b64 = token.split(".")[2]
        padded = signature_b64 + "=" * (-len(signature_b64) % 4)
        assert len(base64.urlsafe_b64decode(padded)) == 64


class TestValidToken:
    def test_control_case_verifies(self, idp: FakeIdP, signing_key: SigningKey) -> None:
        assert verify_rs256(idp.id_token(), signing_key)

    def test_claims_round_trip(self, idp: FakeIdP) -> None:
        claims = tokens.decode_segment(idp.id_token(subject="alice"), 1)
        assert claims["sub"] == "alice"
        assert claims["iss"] == idp.issuer
        assert claims["aud"] == idp.client_id
        assert claims["exp"] > claims["iat"]

    def test_header_carries_kid(self, idp: FakeIdP, signing_key: SigningKey) -> None:
        header = tokens.decode_segment(idp.id_token(), 0)
        assert header == {"alg": "RS256", "typ": "JWT", "kid": signing_key.kid}

    def test_at_hash_is_the_left_half(self, idp: FakeIdP) -> None:
        access_token = idp.access_token()
        digest = hashlib.sha256(access_token.encode()).digest()
        assert idp.at_hash(access_token) == tokens.b64u(digest[:16])


class TestAttackShapes:
    def test_alg_none_has_empty_signature(self, idp: FakeIdP) -> None:
        token = tokens.alg_none(idp.base_claims())
        header = tokens.decode_segment(token, 0)
        assert header["alg"] == "none"
        assert token.endswith(".")

    def test_hmac_confusion_uses_public_key_as_secret(
        self, idp: FakeIdP, signing_key: SigningKey
    ) -> None:
        claims = idp.base_claims()
        token = tokens.hmac_with_public_key(claims, signing_key)
        header_b64, payload_b64, signature_b64 = token.split(".")

        assert tokens.decode_segment(token, 0)["alg"] == "HS256"
        expected = hmac.new(
            signing_key.public_pem(),
            f"{header_b64}.{payload_b64}".encode(),
            hashlib.sha256,
        ).digest()
        assert signature_b64 == tokens.b64u(expected)

        # And it must NOT verify as a real RS256 signature.
        assert not verify_rs256(token, signing_key)

    def test_embedded_jwk_is_self_consistent(
        self, idp: FakeIdP, attacker_key: SigningKey, signing_key: SigningKey
    ) -> None:
        token = tokens.embedded_jwk(idp.base_claims(), attacker_key)
        header = tokens.decode_segment(token, 0)

        assert header["jwk"]["kty"] == "RSA"
        # Verifies against the embedded key: that is what makes it dangerous.
        assert verify_rs256(token, attacker_key)
        # And not against the key the RP should be using.
        assert not verify_rs256(token, signing_key)

    def test_jku_points_at_attacker_url(self, idp: FakeIdP, attacker_key: SigningKey) -> None:
        token = tokens.remote_key_url(
            idp.base_claims(), attacker_key, "https://attacker.test/jwks.json"
        )
        assert tokens.decode_segment(token, 0)["jku"] == "https://attacker.test/jwks.json"

    def test_unknown_crit_is_present_and_signed(
        self, idp: FakeIdP, signing_key: SigningKey
    ) -> None:
        token = tokens.unknown_crit(idp.base_claims(), signing_key)
        header = tokens.decode_segment(token, 0)
        assert header["crit"] == ["urn:example:not-a-real-extension"]
        # Correctly signed, so only the crit check can reject it.
        assert verify_rs256(token, signing_key)

    def test_tampered_payload_breaks_the_signature(
        self, idp: FakeIdP, signing_key: SigningKey
    ) -> None:
        original = idp.id_token(subject="alice")
        forged = tokens.tampered_payload(original, {"sub": "admin", "iss": idp.issuer})
        assert tokens.decode_segment(forged, 1)["sub"] == "admin"
        assert not verify_rs256(forged, signing_key)

    def test_stripped_signature_keeps_the_claims(self, idp: FakeIdP) -> None:
        token = tokens.stripped_signature(idp.id_token(subject="alice"))
        assert tokens.decode_segment(token, 1)["sub"] == "alice"
        assert token.split(".")[2] == ""


class TestKeyRotation:
    def test_rotation_publishes_both_keys(self, idp: FakeIdP) -> None:
        original = idp.active_key
        new = idp.rotate_key()
        published = {k["kid"] for k in idp.jwks()["keys"]}
        assert published == {original.kid, new.kid}

    def test_tokens_signed_by_the_retired_key_still_parse(
        self, idp: FakeIdP, signing_key: SigningKey
    ) -> None:
        idp.rotate_key()
        token = idp.id_token(key=signing_key)
        assert tokens.decode_segment(token, 0)["kid"] == signing_key.kid
        assert verify_rs256(token, signing_key)

    def test_hard_rotation_drops_the_old_key(self, idp: FakeIdP) -> None:
        original = idp.active_key
        idp.rotate_key(retire_old=True)
        assert original.kid not in {k["kid"] for k in idp.jwks()["keys"]}


class TestVendorShapes:
    def test_entra_sub_is_pairwise_and_oid_is_stable(self, entra_idp: FakeIdP) -> None:
        first = tokens.decode_segment(entra_idp.id_token(subject="alice"), 1)
        second = tokens.decode_segment(entra_idp.id_token(subject="alice"), 1)

        assert first["oid"] == second["oid"] == "oid-alice"
        assert first["tid"] == "tenant-0001"
        # The trap: sub differs per application registration, so keying on it
        # breaks the moment a deployment adds a second client id.
        assert first["sub"] != second["sub"]

    def test_entra_emits_no_email_verified(self, entra_idp: FakeIdP) -> None:
        assert "email_verified" not in entra_idp.base_claims()

    def test_entra_groups_are_guids(self, entra_idp: FakeIdP) -> None:
        claims = entra_idp.with_groups(["eng-admins", "all-staff"])
        assert all(g.startswith("00000000-0000-0000-0000-") for g in claims["groups"])
        assert "eng-admins" not in claims["groups"]

    def test_entra_overage_replaces_groups_with_a_graph_pointer(self, entra_idp: FakeIdP) -> None:
        claims = entra_idp.with_group_overage()
        assert "groups" not in claims
        assert claims["_claim_names"] == {"groups": "src1"}
        assert "getMemberObjects" in claims["_claim_sources"]["src1"]["endpoint"]
        assert claims["hasgroups"] is True

    def test_okta_groups_are_names(self, okta_idp: FakeIdP) -> None:
        claims = okta_idp.with_groups(["eng-admins"])
        assert claims["groups"] == ["eng-admins"]

    def test_keycloak_groups_carry_a_leading_path(self, keycloak_idp: FakeIdP) -> None:
        claims = keycloak_idp.with_groups(["eng-admins"])
        assert claims["groups"] == ["/eng-admins"]

    def test_google_has_no_group_claim_at_all(self, google_idp: FakeIdP) -> None:
        claims = google_idp.with_groups(["eng-admins"])
        assert "groups" not in claims

    def test_google_publishes_no_end_session_endpoint(self, google_idp: FakeIdP) -> None:
        # RP-initiated logout is therefore impossible against Google.
        assert "end_session_endpoint" not in google_idp.discovery_document()

    def test_google_pins_the_tenant_with_hd(self, google_idp: FakeIdP) -> None:
        assert google_idp.base_claims()["hd"] == "example.test"

    @pytest.mark.parametrize("attribute", ["issuer", "jwks_uri", "token_endpoint"])
    def test_every_vendor_publishes_the_core_endpoints(
        self, any_vendor: FakeIdP, attribute: str
    ) -> None:
        assert any_vendor.discovery_document()[attribute]

    def test_every_vendor_signs_verifiably(
        self, any_vendor: FakeIdP, signing_key: SigningKey
    ) -> None:
        assert verify_rs256(any_vendor.id_token(), signing_key)


class TestDiscovery:
    def test_jwks_uri_matches_the_issuer(self, idp: FakeIdP) -> None:
        doc = idp.discovery_document()
        assert doc["jwks_uri"].startswith(doc["issuer"])

    def test_s256_is_advertised(self, idp: FakeIdP) -> None:
        # We refuse providers that do not offer S256 (invariant 8).
        assert "S256" in idp.discovery_document()["code_challenge_methods_supported"]

    def test_rfc9207_iss_parameter_is_advertised(self, idp: FakeIdP) -> None:
        assert idp.discovery_document()["authorization_response_iss_parameter_supported"]
