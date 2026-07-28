"""The adversarial corpus, pointed at the verifier.

Each test names the CVE class it is a regression for. Several assert not just
that a token was rejected but *why*, and one asserts the order in which checks
ran, because rejecting a hostile token after it has already influenced key
selection is a weaker property than rejecting it before.
"""

from __future__ import annotations

from typing import Any

import pytest

from bastion.exceptions import (
    AlgorithmNotAllowed,
    KeyNotFound,
    MalformedToken,
    SignatureVerificationFailed,
    TokenTooLarge,
    UnsupportedCriticalHeader,
    UntrustedKeyMaterial,
)
from bastion.protocols.oidc import parse_header, verify_compact
from tests.idp import tokens
from tests.idp.keys import SigningKey
from tests.idp.provider import FakeIdP


class RecordingResolver:
    """A resolver that remembers whether it was consulted.

    Lets a test assert that a policy failure short-circuited before key
    selection, rather than merely that the token was rejected somewhere.
    """

    def __init__(self, key: Any) -> None:
        self.key = key
        self.calls: list[tuple[str | None, str]] = []

    def __call__(self, *, kid: str | None, alg: str) -> Any:
        self.calls.append((kid, alg))
        if self.key is None:
            raise KeyNotFound("no key")
        return self.key


@pytest.fixture
def resolver(signing_key: SigningKey) -> RecordingResolver:
    return RecordingResolver(signing_key.public)


class TestControlCase:
    def test_valid_token_verifies(self, idp: FakeIdP, resolver: RecordingResolver) -> None:
        result = verify_compact(idp.id_token(subject="alice"), key_resolver=resolver)
        assert result.claims["sub"] == "alice"
        assert result.header["alg"] == "RS256"

    def test_resolver_receives_the_kid_and_algorithm(
        self, idp: FakeIdP, resolver: RecordingResolver, signing_key: SigningKey
    ) -> None:
        verify_compact(idp.id_token(), key_resolver=resolver)
        assert resolver.calls == [(signing_key.kid, "RS256")]

    def test_elliptic_curve_tokens_verify(self, ec_key: SigningKey) -> None:
        idp = FakeIdP(keys=[ec_key])
        result = verify_compact(
            idp.id_token(subject="bob"), key_resolver=RecordingResolver(ec_key.public)
        )
        assert result.claims["sub"] == "bob"


class TestAlgorithmPolicy:
    def test_alg_none_is_rejected(self, idp: FakeIdP, resolver: RecordingResolver) -> None:
        """authlib CVE-2026-28802. OIDC Core permits this in one narrow case;
        we refuse it anyway and say so in the docs."""
        token = tokens.alg_none(idp.base_claims())
        with pytest.raises(AlgorithmNotAllowed):
            verify_compact(token, key_resolver=resolver)

    def test_alg_none_never_reaches_key_selection(
        self, idp: FakeIdP, resolver: RecordingResolver
    ) -> None:
        with pytest.raises(AlgorithmNotAllowed):
            verify_compact(tokens.alg_none(idp.base_claims()), key_resolver=resolver)
        assert resolver.calls == []

    def test_hmac_signed_with_the_public_key_is_rejected(
        self, idp: FakeIdP, signing_key: SigningKey, resolver: RecordingResolver
    ) -> None:
        """The algorithm-confusion classic. PyJWT has shipped this four times
        (CVE-2017-11424, CVE-2022-29217, CVE-2026-48526, CVE-2026-48523).

        Note what makes the allowlist the right shape: HS256 is refused because
        it is absent, not because anything special-cases it.
        """
        token = tokens.hmac_with_public_key(idp.base_claims(), signing_key)
        with pytest.raises(AlgorithmNotAllowed):
            verify_compact(token, key_resolver=resolver)
        assert resolver.calls == []

    def test_missing_algorithm_is_malformed(self, resolver: RecordingResolver) -> None:
        token = tokens.compact({"typ": "JWT"}, {"sub": "x"}, b"sig")
        with pytest.raises(MalformedToken):
            verify_compact(token, key_resolver=resolver)

    def test_caller_may_narrow_the_allowlist(
        self, idp: FakeIdP, resolver: RecordingResolver
    ) -> None:
        with pytest.raises(AlgorithmNotAllowed):
            verify_compact(
                idp.id_token(), key_resolver=resolver, allowed_algorithms=frozenset({"ES256"})
            )


class TestKeyMaterialInTheHeader:
    def test_embedded_jwk_is_rejected(
        self, idp: FakeIdP, attacker_key: SigningKey, resolver: RecordingResolver
    ) -> None:
        """authlib CVE-2026-27962, critical.

        The signature is genuinely valid against the embedded key. Only
        refusing to read key material from the message stops it.
        """
        token = tokens.embedded_jwk(idp.base_claims(), attacker_key)
        with pytest.raises(UntrustedKeyMaterial):
            verify_compact(token, key_resolver=resolver)
        assert resolver.calls == []

    def test_jku_is_rejected(
        self, idp: FakeIdP, attacker_key: SigningKey, resolver: RecordingResolver
    ) -> None:
        token = tokens.remote_key_url(
            idp.base_claims(), attacker_key, "https://attacker.test/jwks.json"
        )
        with pytest.raises(UntrustedKeyMaterial):
            verify_compact(token, key_resolver=resolver)

    @pytest.mark.parametrize("param", ["jwk", "jku", "x5u", "x5c"])
    def test_every_key_bearing_header_is_refused(
        self, idp: FakeIdP, signing_key: SigningKey, resolver: RecordingResolver, param: str
    ) -> None:
        header = {"alg": "RS256", "typ": "JWT", "kid": signing_key.kid, param: "anything"}
        token = tokens.sign(header, idp.base_claims(), signing_key)
        with pytest.raises(UntrustedKeyMaterial):
            verify_compact(token, key_resolver=resolver)


class TestCriticalHeaders:
    def test_unknown_crit_is_rejected(
        self, idp: FakeIdP, signing_key: SigningKey, resolver: RecordingResolver
    ) -> None:
        """authlib CVE-2025-59420. The token is correctly signed, so only the
        crit check can reject it."""
        token = tokens.unknown_crit(idp.base_claims(), signing_key)
        with pytest.raises(UnsupportedCriticalHeader):
            verify_compact(token, key_resolver=resolver)

    def test_malformed_crit_is_rejected(
        self, idp: FakeIdP, signing_key: SigningKey, resolver: RecordingResolver
    ) -> None:
        header = {"alg": "RS256", "kid": signing_key.kid, "crit": "not-a-list"}
        token = tokens.sign(header, idp.base_claims(), signing_key)
        with pytest.raises(MalformedToken):
            verify_compact(token, key_resolver=resolver)


class TestSignature:
    def test_tampered_payload_is_rejected(self, idp: FakeIdP, resolver: RecordingResolver) -> None:
        original = idp.id_token(subject="alice")
        forged = tokens.tampered_payload(original, {"sub": "admin"})
        with pytest.raises(SignatureVerificationFailed):
            verify_compact(forged, key_resolver=resolver)

    def test_stripped_signature_is_rejected(
        self, idp: FakeIdP, resolver: RecordingResolver
    ) -> None:
        token = tokens.stripped_signature(idp.id_token())
        with pytest.raises(SignatureVerificationFailed):
            verify_compact(token, key_resolver=resolver)

    def test_signature_from_the_wrong_key_is_rejected(
        self, attacker_key: SigningKey, resolver: RecordingResolver
    ) -> None:
        hostile = FakeIdP(keys=[attacker_key])
        with pytest.raises(SignatureVerificationFailed):
            verify_compact(hostile.id_token(), key_resolver=resolver)

    def test_key_of_the_wrong_type_is_rejected(self, idp: FakeIdP, ec_key: SigningKey) -> None:
        """An RS256 header with an EC key resolved must fail closed rather than
        raising something uncaught out of the primitive."""
        with pytest.raises(SignatureVerificationFailed):
            verify_compact(idp.id_token(), key_resolver=RecordingResolver(ec_key.public))


class TestMalformedInput:
    @pytest.mark.parametrize(
        "token",
        ["", "onlyonepart", "two.parts", "a.b.c.d", "a.b.c.d.e"],
        ids=["empty", "one", "two", "four", "five-jwe"],
    )
    def test_wrong_segment_count_is_rejected(self, token: str, resolver: RecordingResolver) -> None:
        with pytest.raises(MalformedToken):
            verify_compact(token, key_resolver=resolver)

    def test_oversized_token_is_rejected_before_parsing(self, resolver: RecordingResolver) -> None:
        with pytest.raises(TokenTooLarge):
            verify_compact("a" * (16 * 1024 + 1), key_resolver=resolver)

    def test_non_json_header_is_rejected(self, resolver: RecordingResolver) -> None:
        with pytest.raises(MalformedToken):
            verify_compact("bm90LWpzb24.e30.c2ln", key_resolver=resolver)

    def test_header_that_is_not_an_object_is_rejected(self, resolver: RecordingResolver) -> None:
        token = f"{tokens.b64u_json(['a', 'list'])}.{tokens.b64u_json({})}.c2ln"
        with pytest.raises(MalformedToken):
            verify_compact(token, key_resolver=resolver)

    def test_non_string_kid_is_rejected(
        self, idp: FakeIdP, signing_key: SigningKey, resolver: RecordingResolver
    ) -> None:
        token = tokens.sign({"alg": "RS256", "kid": 1234}, idp.base_claims(), signing_key)
        with pytest.raises(MalformedToken):
            verify_compact(token, key_resolver=resolver)


class TestResolverContract:
    def test_key_not_found_propagates(self, idp: FakeIdP) -> None:
        with pytest.raises(KeyNotFound):
            verify_compact(idp.id_token(), key_resolver=RecordingResolver(None))

    def test_a_resolver_returning_none_still_fails_closed(self, idp: FakeIdP) -> None:
        """Defence in depth. The contract says raise, but a third-party
        resolver that returns None must not be read as "no signature
        required" -- which is how this class of bug has always looked."""

        def bad_resolver(*, kid: str | None, alg: str) -> Any:
            return None

        with pytest.raises(KeyNotFound):
            verify_compact(idp.id_token(), key_resolver=bad_resolver)


class TestParseHeader:
    def test_reads_the_header_without_a_key(self, idp: FakeIdP, signing_key: SigningKey) -> None:
        header = parse_header(idp.id_token())
        assert header["kid"] == signing_key.kid

    def test_still_enforces_the_size_cap(self) -> None:
        with pytest.raises(TokenTooLarge):
            parse_header("a" * (16 * 1024 + 1))
