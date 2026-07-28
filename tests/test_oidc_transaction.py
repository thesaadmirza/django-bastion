"""Transaction records, PKCE, and the authorization request."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest
from django.core.cache import cache

from bastion.exceptions import (
    ConfigurationError,
    TransactionExpired,
    TransactionNotFound,
    TransactionReplayed,
)
from bastion.protocols.oidc.transaction import (
    MAX_TTL,
    CacheTransactionStore,
    MemoryTransactionStore,
    Transaction,
    build_authorization_url,
    code_challenge_for,
    generate_code_verifier,
    start_transaction,
    verify_callback_issuer,
)

NOW = dt.datetime(2026, 7, 28, 12, 0, 0, tzinfo=dt.UTC)
AUTHORIZE = "https://idp.example.test/authorize"


class FrozenClock:
    def __init__(self, now: dt.datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += dt.timedelta(**kwargs)


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def store(clock: FrozenClock) -> MemoryTransactionStore:
    return MemoryTransactionStore(clock=clock)


class TestPKCE:
    def test_verifier_meets_the_rfc_length_floor(self) -> None:
        # RFC 7636 permits 43-128 characters; 32 random bytes gives exactly 43.
        assert len(generate_code_verifier()) == 43

    def test_verifier_is_unpadded_base64url(self) -> None:
        verifier = generate_code_verifier()
        assert "=" not in verifier
        assert "+" not in verifier and "/" not in verifier

    def test_verifiers_are_unique(self) -> None:
        assert len({generate_code_verifier() for _ in range(100)}) == 100

    def test_challenge_is_the_s256_digest(self) -> None:
        verifier = generate_code_verifier()
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        assert code_challenge_for(verifier) == expected

    def test_challenge_differs_from_the_verifier(self) -> None:
        """If they matched, PKCE would prove nothing."""
        verifier = generate_code_verifier()
        assert code_challenge_for(verifier) != verifier


class TestStartTransaction:
    def test_state_and_nonce_are_distinct_and_random(
        self, store: MemoryTransactionStore, clock: FrozenClock
    ) -> None:
        first = start_transaction(connection="corp", store=store, now=clock())
        second = start_transaction(connection="corp", store=store, now=clock())
        assert first.state != first.nonce
        assert first.state != second.state
        assert first.nonce != second.nonce

    def test_entropy_is_at_least_128_bits(self, store: MemoryTransactionStore) -> None:
        transaction = start_transaction(connection="corp", store=store, now=NOW)
        raw = base64.urlsafe_b64decode(transaction.state + "==")
        assert len(raw) * 8 >= 128

    def test_pkce_is_generated_unconditionally(self, store: MemoryTransactionStore) -> None:
        """Including for confidential clients. RFC 9700 recommends it
        regardless of client type, and it is what actually stops code
        injection."""
        transaction = start_transaction(connection="corp", store=store, now=NOW)
        assert transaction.code_verifier
        assert transaction.code_challenge != transaction.code_verifier

    def test_the_record_is_persisted(self, store: MemoryTransactionStore) -> None:
        transaction = start_transaction(connection="corp", store=store, now=NOW)
        assert store.consume(transaction.state).state == transaction.state

    def test_ttl_above_the_ceiling_is_rejected(self, store: MemoryTransactionStore) -> None:
        with pytest.raises(ConfigurationError):
            start_transaction(connection="corp", store=store, ttl=MAX_TTL + dt.timedelta(seconds=1))

    def test_non_positive_ttl_is_rejected(self, store: MemoryTransactionStore) -> None:
        with pytest.raises(ConfigurationError):
            start_transaction(connection="corp", store=store, ttl=dt.timedelta(0))

    def test_the_connection_travels_with_the_record(self, store: MemoryTransactionStore) -> None:
        """This is what lets one shared callback URL route to N tenants
        without putting the tenant in a query parameter the provider would
        reject."""
        transaction = start_transaction(connection="tenant-b", store=store, now=NOW)
        assert store.consume(transaction.state).connection == "tenant-b"

    def test_the_return_url_stays_server_side(self, store: MemoryTransactionStore) -> None:
        transaction = start_transaction(
            connection="corp", store=store, redirect_to="/admin/auth/user/", now=NOW
        )
        assert transaction.redirect_to == "/admin/auth/user/"
        url = build_authorization_url(
            transaction,
            authorization_endpoint=AUTHORIZE,
            client_id="cid",
            redirect_uri="https://app.test/callback",
        )
        assert "/admin/auth/user/" not in url


class TestConsumption:
    def test_unknown_state_is_rejected(self, store: MemoryTransactionStore) -> None:
        with pytest.raises(TransactionNotFound):
            store.consume("never-issued")

    def test_a_transaction_is_single_use(self, store: MemoryTransactionStore) -> None:
        transaction = start_transaction(connection="corp", store=store, now=NOW)
        store.consume(transaction.state)
        with pytest.raises(TransactionNotFound):
            store.consume(transaction.state)

    def test_an_expired_transaction_is_rejected(
        self, store: MemoryTransactionStore, clock: FrozenClock
    ) -> None:
        transaction = start_transaction(
            connection="corp", store=store, ttl=dt.timedelta(minutes=5), now=clock()
        )
        clock.advance(minutes=6)
        with pytest.raises(TransactionExpired):
            store.consume(transaction.state)

    def test_an_expired_transaction_is_still_removed(
        self, store: MemoryTransactionStore, clock: FrozenClock
    ) -> None:
        """Expiry must not leave the record available for a later attempt."""
        transaction = start_transaction(
            connection="corp", store=store, ttl=dt.timedelta(minutes=5), now=clock()
        )
        clock.advance(minutes=6)
        with pytest.raises(TransactionExpired):
            store.consume(transaction.state)
        with pytest.raises(TransactionNotFound):
            store.consume(transaction.state)


class TestCacheStore:
    @pytest.fixture(autouse=True)
    def _clear(self) -> None:
        cache.clear()

    @pytest.fixture
    def cache_store(self, clock: FrozenClock) -> CacheTransactionStore:
        return CacheTransactionStore(clock=clock)

    def test_round_trip(self, cache_store: CacheTransactionStore, clock: FrozenClock) -> None:
        transaction = start_transaction(connection="corp", store=cache_store, now=clock())
        restored = cache_store.consume(transaction.state)
        assert restored.code_verifier == transaction.code_verifier
        assert restored.connection == "corp"

    def test_single_use(self, cache_store: CacheTransactionStore, clock: FrozenClock) -> None:
        transaction = start_transaction(connection="corp", store=cache_store, now=clock())
        cache_store.consume(transaction.state)
        with pytest.raises(TransactionNotFound):
            cache_store.consume(transaction.state)

    def test_the_state_is_not_a_cache_key(
        self, cache_store: CacheTransactionStore, clock: FrozenClock
    ) -> None:
        """Hashed, so a state value never appears in a keyspace dump."""
        transaction = start_transaction(connection="corp", store=cache_store, now=clock())
        assert cache.get(f"bastion:txn:{transaction.state}") is None
        assert cache_store.consume(transaction.state)

    def test_concurrent_consumers_produce_one_winner(
        self, cache_store: CacheTransactionStore, clock: FrozenClock
    ) -> None:
        """The delete is the gate, not the fetch.

        Simulated rather than threaded: both callers read the record, then both
        try to delete. Exactly one delete can succeed.
        """
        transaction = start_transaction(connection="corp", store=cache_store, now=clock())
        key = cache_store._key(transaction.state)

        first = cache.get(key)
        second = cache.get(key)
        assert first is not None and second is not None

        assert cache.delete(key) is True
        assert cache.delete(key) is False

        with pytest.raises(TransactionNotFound):
            cache_store.consume(transaction.state)

    def test_replay_is_reported_when_the_record_vanishes_mid_consume(
        self, cache_store: CacheTransactionStore, clock: FrozenClock, monkeypatch
    ) -> None:
        transaction = start_transaction(connection="corp", store=cache_store, now=clock())
        real_cache = cache_store._cache()

        class RacingCache:
            def get(self, key: str) -> object:
                return real_cache.get(key)

            def delete(self, key: str) -> bool:
                return False  # someone else got there first

        monkeypatch.setattr(cache_store, "_cache", lambda: RacingCache())
        with pytest.raises(TransactionReplayed):
            cache_store.consume(transaction.state)


class TestAuthorizationUrl:
    @pytest.fixture
    def transaction(self, store: MemoryTransactionStore) -> Transaction:
        return start_transaction(connection="corp", store=store, now=NOW)

    def url_params(self, transaction: Transaction, **kwargs: object) -> dict[str, list[str]]:
        kwargs.setdefault("authorization_endpoint", AUTHORIZE)
        kwargs.setdefault("client_id", "cid")
        kwargs.setdefault("redirect_uri", "https://app.test/callback")
        url = build_authorization_url(transaction, **kwargs)  # type: ignore[arg-type]
        return parse_qs(urlparse(url).query)

    def test_carries_state_nonce_and_challenge(self, transaction: Transaction) -> None:
        params = self.url_params(transaction)
        assert params["state"] == [transaction.state]
        assert params["nonce"] == [transaction.nonce]
        assert params["code_challenge"] == [transaction.code_challenge]

    def test_challenge_method_is_always_s256(self, transaction: Transaction) -> None:
        assert self.url_params(transaction)["code_challenge_method"] == ["S256"]

    def test_the_verifier_never_leaves_the_server(self, transaction: Transaction) -> None:
        url = build_authorization_url(
            transaction,
            authorization_endpoint=AUTHORIZE,
            client_id="cid",
            redirect_uri="https://app.test/callback",
        )
        assert transaction.code_verifier not in url

    def test_optional_parameters_are_omitted_when_unset(self, transaction: Transaction) -> None:
        params = self.url_params(transaction)
        assert "prompt" not in params
        assert "max_age" not in params
        assert "acr_values" not in params

    def test_step_up_parameters_are_included(self, transaction: Transaction) -> None:
        params = self.url_params(
            transaction, prompt="login", max_age=0, acr_values=("urn:okta:loa:2fa:any",)
        )
        assert params["prompt"] == ["login"]
        assert params["max_age"] == ["0"]
        assert params["acr_values"] == ["urn:okta:loa:2fa:any"]

    def test_extra_params_cannot_override_security_parameters(
        self, transaction: Transaction
    ) -> None:
        """A provider-specific hint is welcome. A caller-supplied
        code_challenge is not."""
        with pytest.raises(ConfigurationError):
            self.url_params(transaction, extra_params={"code_challenge": "attacker"})

    def test_extra_params_are_appended(self, transaction: Transaction) -> None:
        params = self.url_params(transaction, extra_params={"kc_idp_hint": "corp"})
        assert params["kc_idp_hint"] == ["corp"]

    def test_an_endpoint_with_a_query_string_is_handled(self, transaction: Transaction) -> None:
        url = build_authorization_url(
            transaction,
            authorization_endpoint="https://idp.test/authorize?tenant=a",
            client_id="cid",
            redirect_uri="https://app.test/callback",
        )
        params = parse_qs(urlparse(url).query)
        assert params["tenant"] == ["a"]
        assert params["state"] == [transaction.state]


class TestCallbackIssuer:
    def test_matching_issuer_passes(self) -> None:
        verify_callback_issuer("https://idp.example.test", expected="https://idp.example.test")

    def test_absent_issuer_is_tolerated(self) -> None:
        """RFC 9207 is not universally emitted yet."""
        verify_callback_issuer(None, expected="https://idp.example.test")

    def test_wrong_issuer_is_rejected(self) -> None:
        """The IdP mix-up defence: a callback from provider B arriving at the
        handler for provider A."""
        with pytest.raises(TransactionNotFound):
            verify_callback_issuer("https://attacker.test", expected="https://idp.example.test")
