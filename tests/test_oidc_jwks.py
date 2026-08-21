"""JWKS caching, rotation, and the rate limit that stops kid-driven
amplification."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from bastion.exceptions import DiscoveryError, InsecureEndpoint, KeyNotFound
from bastion.protocols.oidc import JWKSStore
from bastion.testing.keys import SigningKey
from bastion.testing.provider import FakeIdP

JWKS_URI = "https://idp.example.test/.well-known/jwks.json"


class CountingFetcher:
    """Serves the IdP's current JWKS and counts requests."""

    def __init__(self, idp: FakeIdP) -> None:
        self.idp = idp
        self.calls = 0

    def __call__(self, uri: str) -> Mapping[str, Any]:
        self.calls += 1
        return self.idp.jwks()


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def fetcher(idp: FakeIdP) -> CountingFetcher:
    return CountingFetcher(idp)


@pytest.fixture
def store(fetcher: CountingFetcher, clock: FakeClock) -> JWKSStore:
    return JWKSStore(uri=JWKS_URI, fetcher=fetcher, clock=clock)


class TestEndpointScheme:
    @pytest.mark.parametrize(
        "uri",
        [
            "http://idp.example.test/jwks.json",
            "file:///etc/passwd",
            "ftp://idp.example.test/jwks.json",
            "/local/path/jwks.json",
        ],
    )
    def test_non_https_uris_are_refused_at_construction(self, uri: str) -> None:
        """PyJWT CVE-2026-48522: an unrestricted scheme here is an SSRF
        primitive and a local-file read, driven by configuration."""
        with pytest.raises(InsecureEndpoint):
            JWKSStore(uri=uri, fetcher=lambda _: {"keys": []})


class TestResolution:
    def test_first_resolve_fetches_once(
        self, store: JWKSStore, fetcher: CountingFetcher, signing_key: SigningKey
    ) -> None:
        key = store.resolve(kid=signing_key.kid, alg="RS256")
        assert key is not None
        assert fetcher.calls == 1

    def test_second_resolve_is_served_from_cache(
        self, store: JWKSStore, fetcher: CountingFetcher, signing_key: SigningKey
    ) -> None:
        store.resolve(kid=signing_key.kid, alg="RS256")
        store.resolve(kid=signing_key.kid, alg="RS256")
        assert fetcher.calls == 1

    def test_absent_kid_resolves_when_exactly_one_key_is_published(self, store: JWKSStore) -> None:
        assert store.resolve(kid=None, alg="RS256") is not None

    def test_absent_kid_is_ambiguous_with_several_keys(
        self, store: JWKSStore, idp: FakeIdP, clock: FakeClock
    ) -> None:
        """Guessing among published keys is how the wrong one gets picked
        during a rotation."""
        idp.rotate_key()
        clock.advance(120)
        with pytest.raises(KeyNotFound):
            store.resolve(kid=None, alg="RS256")

    def test_wrong_algorithm_family_for_a_known_kid_is_a_miss(
        self, store: JWKSStore, signing_key: SigningKey
    ) -> None:
        with pytest.raises(KeyNotFound):
            store.resolve(kid=signing_key.kid, alg="ES256")


class TestRateLimiting:
    def test_unknown_kid_triggers_exactly_one_refetch(
        self, store: JWKSStore, fetcher: CountingFetcher
    ) -> None:
        with pytest.raises(KeyNotFound):
            store.resolve(kid="unknown-1", alg="RS256")
        assert fetcher.calls == 1

    def test_further_unknown_kids_inside_the_window_do_not_fetch(
        self, store: JWKSStore, fetcher: CountingFetcher
    ) -> None:
        """PyJWT CVE-2026-48524. Without this, one attacker-controlled request
        becomes one outbound request to the provider, indefinitely."""
        for i in range(50):
            with pytest.raises(KeyNotFound):
                store.resolve(kid=f"unknown-{i}", alg="RS256")
        assert fetcher.calls == 1

    def test_refetch_resumes_after_the_interval(
        self, store: JWKSStore, fetcher: CountingFetcher, clock: FakeClock
    ) -> None:
        with pytest.raises(KeyNotFound):
            store.resolve(kid="unknown", alg="RS256")
        clock.advance(61)
        with pytest.raises(KeyNotFound):
            store.resolve(kid="unknown", alg="RS256")
        assert fetcher.calls == 2

    def test_window_budget_caps_slow_drip_amplification(
        self, store: JWKSStore, fetcher: CountingFetcher, clock: FakeClock
    ) -> None:
        """Spacing requests past min_refetch_interval must not buy unlimited
        fetches either."""
        for i in range(20):
            clock.advance(61)
            with pytest.raises(KeyNotFound):
                store.resolve(kid=f"unknown-{i}", alg="RS256")
        assert fetcher.calls == store.max_fetches_per_window

    def test_budget_refills_after_the_window(
        self, store: JWKSStore, fetcher: CountingFetcher, clock: FakeClock
    ) -> None:
        for i in range(10):
            clock.advance(61)
            with pytest.raises(KeyNotFound):
                store.resolve(kid=f"unknown-{i}", alg="RS256")
        before = fetcher.calls
        clock.advance(3601)
        with pytest.raises(KeyNotFound):
            store.resolve(kid="unknown-later", alg="RS256")
        assert fetcher.calls == before + 1


class TestRotation:
    def test_a_newly_published_key_is_picked_up(
        self, store: JWKSStore, idp: FakeIdP, clock: FakeClock, signing_key: SigningKey
    ) -> None:
        store.resolve(kid=signing_key.kid, alg="RS256")
        new = idp.rotate_key()
        clock.advance(61)
        assert store.resolve(kid=new.kid, alg="RS256") is not None

    def test_both_keys_resolve_during_the_overlap(
        self, store: JWKSStore, idp: FakeIdP, clock: FakeClock, signing_key: SigningKey
    ) -> None:
        new = idp.rotate_key()
        clock.advance(61)
        assert store.resolve(kid=new.kid, alg="RS256") is not None
        assert store.resolve(kid=signing_key.kid, alg="RS256") is not None

    def test_a_withdrawn_key_stops_resolving(
        self, store: JWKSStore, idp: FakeIdP, clock: FakeClock, signing_key: SigningKey
    ) -> None:
        """The cache is replaced wholesale, not merged. A key the provider has
        retired must stop being accepted here too."""
        store.resolve(kid=signing_key.kid, alg="RS256")
        idp.rotate_key(retire_old=True)
        clock.advance(61)
        store.resolve(kid=idp.active_key.kid, alg="RS256")

        clock.advance(61)
        with pytest.raises(KeyNotFound):
            store.resolve(kid=signing_key.kid, alg="RS256")


class TestMalformedDocuments:
    def test_empty_document_raises(self) -> None:
        store = JWKSStore(uri=JWKS_URI, fetcher=lambda _: {"keys": []})
        with pytest.raises(DiscoveryError):
            store.resolve(kid="anything", alg="RS256")

    def test_unusable_key_is_skipped_but_others_survive(
        self, idp: FakeIdP, signing_key: SigningKey
    ) -> None:
        """A provider mid-rotation can publish something we cannot parse.
        Refusing every login over it would be worse than ignoring it."""

        def fetcher(_: str) -> dict[str, Any]:
            document = dict(idp.jwks())
            keys = [dict(k) for k in document["keys"]]
            keys.insert(0, {"kty": "RSA", "kid": "broken", "n": "!!!", "e": "AQAB"})
            keys.insert(0, {"kty": "UNKNOWN", "kid": "alien"})
            return {"keys": keys}

        store = JWKSStore(uri=JWKS_URI, fetcher=fetcher)
        assert store.resolve(kid=signing_key.kid, alg="RS256") is not None
        assert "broken" not in store.kids

    def test_document_of_only_unusable_keys_raises(self) -> None:
        store = JWKSStore(
            uri=JWKS_URI,
            fetcher=lambda _: {"keys": [{"kty": "UNKNOWN", "kid": "alien"}]},
        )
        with pytest.raises(DiscoveryError):
            store.resolve(kid="alien", alg="RS256")

    def test_encryption_keys_are_ignored(self, idp: FakeIdP, signing_key: SigningKey) -> None:
        def fetcher(_: str) -> dict[str, Any]:
            keys = [dict(k) for k in idp.jwks()["keys"]]
            keys[0]["use"] = "enc"
            return {"keys": keys}

        store = JWKSStore(uri=JWKS_URI, fetcher=fetcher)
        with pytest.raises(DiscoveryError):
            store.resolve(kid=signing_key.kid, alg="RS256")


class TestPrime:
    def test_prime_fetches_eagerly(self, store: JWKSStore, fetcher: CountingFetcher) -> None:
        store.prime()
        assert fetcher.calls == 1
        assert store.kids

    def test_prime_surfaces_a_broken_endpoint(self) -> None:
        def fetcher(_: str) -> dict[str, Any]:
            raise DiscoveryError("connection refused")

        with pytest.raises(DiscoveryError):
            JWKSStore(uri=JWKS_URI, fetcher=fetcher).prime()
