"""Defensive branches in the security core.

The core carries a 100% gate rather than the repository's 95%, and this file is
what makes that honest. Everything here is a path that only runs when something
has already gone wrong — a malformed key, an unsupported curve, a sink that
throws. Those are the branches least likely to be exercised by accident and
most likely to matter when they run.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from bastion.audit.events import Event
from bastion.audit.models import AuditActor, AuditEvent, verify_chain
from bastion.audit.recorder import emit, get_sinks, reset_sinks
from bastion.claims import GroupFormat, IdentityClaims, Verified
from bastion.exceptions import (
    DiscoveryError,
    KeyNotFound,
    MalformedToken,
    SignatureVerificationFailed,
)
from bastion.protocols.oidc.jose import verify_compact
from bastion.protocols.oidc.jwks import JWKSStore, jwk_to_public_key
from bastion.testing.keys import SigningKey, generate_key
from tests.idp import tokens


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# --------------------------------------------------------------------------- #
# IdentityClaims validation
# --------------------------------------------------------------------------- #


class TestClaimsValidation:
    """The constructor refuses an identity that cannot be keyed on."""

    def test_a_missing_issuer_is_refused(self) -> None:
        with pytest.raises(ValueError, match="issuer"):
            IdentityClaims(issuer="", subject="s", subject_source="sub")

    def test_a_missing_subject_is_refused(self) -> None:
        with pytest.raises(ValueError, match="subject is required"):
            IdentityClaims(issuer="https://i.test", subject="", subject_source="sub")

    def test_a_missing_subject_source_is_refused(self) -> None:
        """Recording which claim the subject came from is what makes a
        configuration change detectable rather than silently re-linking."""
        with pytest.raises(ValueError, match="subject_source"):
            IdentityClaims(issuer="https://i.test", subject="s", subject_source="")

    def test_the_verified_enum_is_falsey_when_unknown(self) -> None:
        assert not Verified.UNKNOWN
        assert not Verified.NO
        assert Verified.YES

    def test_group_format_travels_with_the_values(self) -> None:
        claims = IdentityClaims(
            issuer="https://i.test",
            subject="s",
            subject_source="sub",
            groups=("/eng",),
            group_value_format=GroupFormat.FULL_PATH,
        )
        assert claims.group_value_format is GroupFormat.FULL_PATH


# --------------------------------------------------------------------------- #
# JOSE defensive branches
# --------------------------------------------------------------------------- #


class TestSignatureAlgorithmBranches:
    def test_eddsa_verifies(self) -> None:
        private = ed25519.Ed25519PrivateKey.generate()
        header = {"alg": "EdDSA", "typ": "JWT"}
        payload = {"sub": "alice"}
        signing_input = tokens.signing_input(header, payload)
        token = tokens.compact(header, payload, private.sign(signing_input))

        result = verify_compact(
            token,
            key_resolver=lambda *, kid, alg: private.public_key(),
            allowed_algorithms=frozenset({"EdDSA"}),
        )
        assert result.claims["sub"] == "alice"

    def test_an_eddsa_header_with_an_rsa_key_fails_closed(self, signing_key: SigningKey) -> None:
        private = ed25519.Ed25519PrivateKey.generate()
        header = {"alg": "EdDSA", "typ": "JWT"}
        payload = {"sub": "alice"}
        token = tokens.compact(header, payload, private.sign(tokens.signing_input(header, payload)))
        with pytest.raises(SignatureVerificationFailed, match="key does not match"):
            verify_compact(
                token,
                key_resolver=lambda *, kid, alg: signing_key.public,
                allowed_algorithms=frozenset({"EdDSA"}),
            )

    def test_an_ecdsa_header_with_an_rsa_key_fails_closed(
        self, ec_key: SigningKey, signing_key: SigningKey
    ) -> None:
        header = {"alg": "ES256", "typ": "JWT"}
        payload = {"sub": "alice"}
        token = tokens.sign(header, payload, ec_key)
        with pytest.raises(SignatureVerificationFailed, match="key does not match"):
            verify_compact(token, key_resolver=lambda *, kid, alg: signing_key.public)

    def test_a_malformed_ecdsa_signature_is_refused(self, ec_key: SigningKey) -> None:
        """An odd-length r||s cannot be split, and guessing would be worse than
        refusing."""
        header = {"alg": "ES256", "typ": "JWT"}
        payload = {"sub": "alice"}
        token = tokens.compact(header, payload, b"\x01\x02\x03")
        with pytest.raises(SignatureVerificationFailed, match="malformed ECDSA"):
            verify_compact(token, key_resolver=lambda *, kid, alg: ec_key.public)

    def test_an_rsa_header_with_an_ec_key_fails_closed(
        self, signing_key: SigningKey, ec_key: SigningKey
    ) -> None:
        token = tokens.sign({"alg": "RS256", "typ": "JWT"}, {"sub": "a"}, signing_key)
        with pytest.raises(SignatureVerificationFailed, match="key does not match"):
            verify_compact(token, key_resolver=lambda *, kid, alg: ec_key.public)

    def test_a_pss_signature_verifies(self) -> None:
        key = generate_key("PS256")
        token = tokens.sign({"alg": "PS256", "typ": "JWT"}, {"sub": "a"}, key)
        result = verify_compact(
            token,
            key_resolver=lambda *, kid, alg: key.public,
            allowed_algorithms=frozenset({"PS256"}),
        )
        assert result.claims["sub"] == "a"

    def test_an_undecodable_signature_segment_is_malformed(self, signing_key: SigningKey) -> None:
        header_b64 = tokens.b64u_json({"alg": "RS256"})
        payload_b64 = tokens.b64u_json({"sub": "a"})
        with pytest.raises(MalformedToken):
            verify_compact(
                f"{header_b64}.{payload_b64}.!!!not-base64!!!",
                key_resolver=lambda *, kid, alg: signing_key.public,
            )


# --------------------------------------------------------------------------- #
# JWK parsing
# --------------------------------------------------------------------------- #


class TestJwkParsing:
    def test_an_ec_jwk_round_trips(self, ec_key: SigningKey) -> None:
        key = jwk_to_public_key(ec_key.public_jwk())
        assert key.curve.name == "secp256r1"

    def test_an_okp_jwk_round_trips(self) -> None:
        private = ed25519.Ed25519PrivateKey.generate()
        raw = private.public_key().public_bytes_raw()
        key = jwk_to_public_key({"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)})
        assert isinstance(key, ed25519.Ed25519PublicKey)

    def test_an_unsupported_curve_is_refused(self) -> None:
        with pytest.raises(DiscoveryError, match="unsupported curve"):
            jwk_to_public_key({"kty": "EC", "crv": "P-192", "x": "AA", "y": "AA"})

    def test_an_unsupported_okp_curve_is_refused(self) -> None:
        with pytest.raises(DiscoveryError, match="unsupported OKP curve"):
            jwk_to_public_key({"kty": "OKP", "crv": "X25519", "x": "AA"})

    def test_an_unsupported_key_type_is_refused(self) -> None:
        with pytest.raises(DiscoveryError, match="unsupported key type"):
            jwk_to_public_key({"kty": "oct", "k": "AA"})

    def test_a_missing_member_is_reported_by_name(self) -> None:
        with pytest.raises(DiscoveryError, match="'n'"):
            jwk_to_public_key({"kty": "RSA", "e": "AQAB"})

    def test_invalid_base64_is_refused(self) -> None:
        """A single character cannot be a base64url group. Stray non-alphabet
        bytes are silently discarded by binascii, so an undecodable *length* is
        what actually reaches the decoder's error path."""
        with pytest.raises(DiscoveryError, match="base64url"):
            jwk_to_public_key({"kty": "RSA", "n": "A", "e": "AQAB"})

    def test_invalid_key_material_is_refused(self) -> None:
        with pytest.raises(DiscoveryError, match="invalid key material"):
            jwk_to_public_key({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"})


class TestJwksStoreBranches:
    def test_a_key_without_a_kid_is_skipped(self, signing_key: SigningKey) -> None:
        def fetcher(_: str) -> dict[str, Any]:
            jwk = dict(signing_key.public_jwk())
            jwk.pop("kid")
            return {"keys": [jwk, signing_key.public_jwk()]}

        store = JWKSStore(uri="https://idp.test/jwks", fetcher=fetcher)
        assert store.resolve(kid=signing_key.kid, alg="RS256") is not None
        assert len(store.kids) == 1

    def test_a_non_mapping_entry_is_skipped(self, signing_key: SigningKey) -> None:
        def fetcher(_: str) -> dict[str, Any]:
            return {"keys": ["not-a-jwk", signing_key.public_jwk()]}

        store = JWKSStore(uri="https://idp.test/jwks", fetcher=fetcher)
        assert store.resolve(kid=signing_key.kid, alg="RS256") is not None

    def test_a_non_list_keys_member_is_refused(self) -> None:
        store = JWKSStore(uri="https://idp.test/jwks", fetcher=lambda _: {"keys": "nope"})
        with pytest.raises(DiscoveryError):
            store.resolve(kid="x", alg="RS256")

    def test_an_unknown_kid_with_no_keys_at_all(self) -> None:
        store = JWKSStore(uri="https://idp.test/jwks", fetcher=lambda _: {})
        with pytest.raises(DiscoveryError):
            store.resolve(kid="x", alg="RS256")

    def test_resolving_without_a_kid_when_none_match_the_algorithm(
        self, signing_key: SigningKey
    ) -> None:
        store = JWKSStore(
            uri="https://idp.test/jwks",
            fetcher=lambda _: {"keys": [signing_key.public_jwk()]},
        )
        with pytest.raises(KeyNotFound):
            store.resolve(kid=None, alg="EdDSA")


# --------------------------------------------------------------------------- #
# Audit recorder failure paths
# --------------------------------------------------------------------------- #


@pytest.mark.django_db
class TestRecorderFailurePaths:
    def test_an_unloadable_sink_is_logged_and_skipped(self, settings, caplog) -> None:
        settings.BASTION = {"AUDIT": {"SINKS": ["nowhere.does.this.Exist"]}}
        reset_sinks()
        assert get_sinks() == []
        assert "Could not load audit sink" in caplog.text

    def test_a_pseudonym_failure_does_not_break_the_emit(self, monkeypatch, caplog) -> None:
        """Losing the actor is bad; failing the login because the audit table
        is unhappy is worse."""

        def explode(cls, user):
            raise RuntimeError("database is unhappy")

        monkeypatch.setattr(AuditActor, "for_user", classmethod(explode))
        from django.contrib.auth import get_user_model

        user = get_user_model().objects.create_user(username="alice")
        emit(Event.LOGIN_SUCCEEDED, actor=user)

        assert AuditEvent.objects.get().actor_pseudonym == ""
        assert "Could not resolve an audit pseudonym" in caplog.text

    def test_an_event_with_a_sessionless_request_is_fine(self, rf) -> None:
        request = rf.get("/")
        emit(Event.LOGIN_SUCCEEDED, request=request)
        assert AuditEvent.objects.get().session_id == ""

    def test_verification_of_an_empty_chain_passes(self) -> None:
        ok, problems = verify_chain("never-written-to")
        assert ok and problems == []

    def test_a_string_event_type_is_accepted(self) -> None:
        """The API takes an Event or a plain string, so downstream packages can
        emit their own types into the same chain."""
        emit("myapp.custom.thing")
        assert AuditEvent.objects.get().event_type == "myapp.custom.thing"


# --------------------------------------------------------------------------- #
# Break-glass network parsing
# --------------------------------------------------------------------------- #


@pytest.mark.django_db
class TestNetworkParsing:
    @pytest.fixture(autouse=True)
    def _enabled(self, settings):
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["bastion.breakglass.service.log_only_sink"],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }

    def test_a_request_without_an_address_is_refused(self) -> None:
        from bastion.breakglass.service import BreakGlassDenied, authenticate_break_glass

        with pytest.raises(BreakGlassDenied) as caught:
            authenticate_break_glass(username="x", password="y", request=None)
        assert caught.value.reason == "network"

    def test_an_unparseable_address_is_refused(self, rf) -> None:
        from bastion.breakglass.service import BreakGlassDenied, authenticate_break_glass

        request = rf.post("/", REMOTE_ADDR="not-an-address")
        with pytest.raises(BreakGlassDenied) as caught:
            authenticate_break_glass(username="x", password="y", request=request)
        assert caught.value.reason == "network"

    def test_an_unparseable_address_still_leaves_a_record(self, rf) -> None:
        """It is stored with no address rather than not stored at all.

        ``source_ip`` is ``inet`` on PostgreSQL and Django adapts the value
        through ``ipaddress.ip_address`` for writes *and* lookups, so a value
        that is not an address raises on the way to the driver. On the write
        path the recorder's "a sink must never fail a login" catch swallows
        that, and the entire record disappears -- silently, and only on one
        backend. Normalising it to NULL at the single place the address is
        resolved keeps the evidence and keeps every lookup that compares
        against it working.
        """
        from bastion.audit.models import AuditEvent
        from bastion.breakglass.service import BreakGlassDenied, authenticate_break_glass

        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(
                username="x", password="y", request=rf.post("/", REMOTE_ADDR="not-an-address")
            )

        record = AuditEvent.objects.get(reason="network")
        assert record.source_ip is None
