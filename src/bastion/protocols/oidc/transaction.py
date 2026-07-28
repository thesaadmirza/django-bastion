"""The browser transaction record.

Everything the callback needs to trust what comes back lives here, on the
server, for at most a few minutes.

Three design points, each of which exists because the obvious alternative is
broken.

**Nothing sensitive rides in the URL.** ``state`` is an opaque random lookup
key, not an encoding of where to go next. The return URL, the connection
identifier and the PKCE verifier stay server-side. Packages that pack the
destination into ``state`` or ``RelayState`` and validate it on the way back
are one validation slip from an open redirect, and the same value is
attacker-visible throughout.

**The record is found by ``state``, not by a cookie.** For the OIDC code flow
with the default response mode the callback is a top-level GET, so a
``SameSite=Lax`` session cookie does arrive. For ``form_post`` -- and for the
SAML POST binding later -- it does not. Teams hit that, set
``SameSite=None`` globally, and re-open CSRF everywhere. Keying on ``state``
sidesteps the whole dilemma. The session key is recorded as a secondary
binding and checked when it is available.

**Consumption is atomic and single-use.** The delete is the gate, not the
fetch: whoever's delete returns true owns the transaction. Two concurrent
callbacks carrying the same code cannot both proceed.

PKCE is generated for every flow including confidential clients. RFC 9700
recommends it regardless of client type, and it is the control that actually
stops authorization code injection -- ``nonce`` does not, for public clients.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlencode

from bastion.exceptions import (
    ConfigurationError,
    TransactionExpired,
    TransactionNotFound,
    TransactionReplayed,
)

#: RFC 7636 allows 43-128 characters. 32 random bytes base64url-encodes to 43,
#: which is the floor, and the floor is 256 bits of entropy.
_VERIFIER_BYTES = 32

#: 128 bits, per OIDC Core's guidance on nonce entropy. Same for state.
_STATE_BYTES = 16

DEFAULT_TTL = dt.timedelta(minutes=10)

#: Beyond this a transaction is not a login in progress, it is a leak waiting
#: to be replayed.
MAX_TTL = dt.timedelta(minutes=30)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def generate_code_verifier() -> str:
    return _b64u(secrets.token_bytes(_VERIFIER_BYTES))


def code_challenge_for(verifier: str) -> str:
    """S256 only. ``plain`` is in the RFC and is not worth supporting."""
    return _b64u(hashlib.sha256(verifier.encode("ascii")).digest())


@dataclass(frozen=True, slots=True)
class Transaction:
    """One in-flight authorization request."""

    state: str
    nonce: str
    code_verifier: str
    connection: str
    created_at: dt.datetime
    expires_at: dt.datetime
    redirect_to: str | None = None
    session_key: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def is_expired(self, now: dt.datetime) -> bool:
        return now >= self.expires_at

    @property
    def code_challenge(self) -> str:
        return code_challenge_for(self.code_verifier)


class TransactionStore(Protocol):
    """Storage for in-flight transactions.

    ``consume`` must be atomic and single-use. A store that cannot guarantee
    that is not usable here.
    """

    def save(self, transaction: Transaction) -> None: ...

    def consume(self, state: str) -> Transaction: ...


@dataclass
class MemoryTransactionStore:
    """In-process store. Correct, and single-process only.

    Fine for tests and for a single-worker deployment. Anything with more than
    one process needs the cache-backed store, or a callback will land on a
    worker that has never heard of the transaction.
    """

    clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(tz=dt.UTC)
    _records: dict[str, Transaction] = field(default_factory=dict, repr=False)

    def save(self, transaction: Transaction) -> None:
        self._records[transaction.state] = transaction

    def consume(self, state: str) -> Transaction:
        transaction = self._records.pop(state, None)
        if transaction is None:
            raise TransactionNotFound("no transaction matches this state")
        if transaction.is_expired(self.clock()):
            raise TransactionExpired("transaction has expired")
        return transaction


@dataclass
class CacheTransactionStore:
    """Cache-backed store.

    Single-use is enforced by ``cache.delete``, which reports whether it
    actually removed anything. The fetch is not the gate; the delete is.
    Two callbacks racing with the same state both read the record, and exactly
    one of them succeeds at deleting it.

    Requires a backend where delete is atomic and reports truthfully. Redis and
    memcached qualify. ``LocMemCache`` does too, being lock-guarded, though it
    is per-process and therefore subject to the same caveat as the memory
    store above.
    """

    cache_alias: str = "default"
    key_prefix: str = "bastion:txn:"
    clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(tz=dt.UTC)

    def _cache(self) -> Any:
        from django.core.cache import caches

        return caches[self.cache_alias]

    def _key(self, state: str) -> str:
        # State is already a base64url random value, so it is a safe cache key
        # component. Hashed anyway so that a state value never appears in a
        # cache-server keyspace dump.
        digest = hashlib.sha256(state.encode()).hexdigest()
        return f"{self.key_prefix}{digest}"

    def save(self, transaction: Transaction) -> None:
        ttl = (transaction.expires_at - self.clock()).total_seconds()
        if ttl <= 0:
            raise ConfigurationError("transaction expires in the past")
        self._cache().set(self._key(transaction.state), transaction, timeout=int(ttl))

    def consume(self, state: str) -> Transaction:
        cache = self._cache()
        key = self._key(state)

        transaction: Transaction | None = cache.get(key)
        if transaction is None:
            raise TransactionNotFound("no transaction matches this state")

        if not cache.delete(key):
            # Someone else deleted it between our get and our delete. They own
            # the transaction; we do not.
            raise TransactionReplayed("transaction was already consumed")

        if transaction.is_expired(self.clock()):
            raise TransactionExpired("transaction has expired")
        return transaction


def start_transaction(
    *,
    connection: str,
    store: TransactionStore,
    redirect_to: str | None = None,
    session_key: str | None = None,
    ttl: dt.timedelta = DEFAULT_TTL,
    now: dt.datetime | None = None,
    extra: Mapping[str, Any] | None = None,
) -> Transaction:
    """Mint and persist a transaction."""
    if ttl <= dt.timedelta(0):
        raise ConfigurationError("transaction ttl must be positive")
    if ttl > MAX_TTL:
        raise ConfigurationError(
            f"transaction ttl of {ttl} exceeds the {MAX_TTL} ceiling. A login "
            "that takes longer than this is not in progress any more."
        )

    now = now or dt.datetime.now(tz=dt.UTC)
    transaction = Transaction(
        state=_b64u(secrets.token_bytes(_STATE_BYTES)),
        nonce=_b64u(secrets.token_bytes(_STATE_BYTES)),
        code_verifier=generate_code_verifier(),
        connection=connection,
        created_at=now,
        expires_at=now + ttl,
        redirect_to=redirect_to,
        session_key=session_key,
        extra=dict(extra or {}),
    )
    store.save(transaction)
    return transaction


def build_authorization_url(
    transaction: Transaction,
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scopes: tuple[str, ...] = ("openid", "email", "profile"),
    prompt: str | None = None,
    max_age: int | None = None,
    acr_values: tuple[str, ...] = (),
    extra_params: Mapping[str, str] | None = None,
) -> str:
    """Build the URL to send the browser to.

    ``code_challenge_method`` is always ``S256`` and there is no switch for it.
    """
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": transaction.state,
        "nonce": transaction.nonce,
        "code_challenge": transaction.code_challenge,
        "code_challenge_method": "S256",
    }
    if prompt:
        params["prompt"] = prompt
    if max_age is not None:
        params["max_age"] = str(max_age)
    if acr_values:
        params["acr_values"] = " ".join(acr_values)
    if extra_params:
        # Never allow an override of a security parameter. A provider-specific
        # hint is welcome; a caller-supplied code_challenge is not.
        reserved = params.keys() & extra_params.keys()
        if reserved:
            raise ConfigurationError(f"extra_params may not override {sorted(reserved)}")
        params.update(extra_params)

    separator = "&" if "?" in authorization_endpoint else "?"
    return f"{authorization_endpoint}{separator}{urlencode(params)}"


def verify_callback_issuer(returned_issuer: str | None, *, expected: str) -> None:
    """Check the RFC 9207 ``iss`` authorization response parameter.

    This is the IdP mix-up defence. A client configured with more than one
    provider, receiving a callback with no way to tell which one sent it, can
    be induced to send a victim's code to the attacker's token endpoint.

    Absent is tolerated because the parameter is not universally emitted;
    present and wrong never is. Providers that advertise support should be
    configured to require it.
    """
    if returned_issuer is None:
        return
    if returned_issuer != expected:
        raise TransactionNotFound("callback issuer does not match this connection")
