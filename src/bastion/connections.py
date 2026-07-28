"""Runtime connection objects.

A ``Connection`` is what a ``BASTION["CONNECTIONS"]`` entry becomes once it has
been validated: config plus the caches it owns. Everything expensive on it is
lazy, because a connection is constructed during startup checks and during
``manage.py`` runs where no network is available or wanted.

Connections are cached per identifier and rebuilt when settings change, so the
discovery document and key set are shared across requests rather than refetched
per login.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from django.core.signals import setting_changed
from django.dispatch import receiver

from bastion.conf import get_setting
from bastion.exceptions import ConfigurationError
from bastion.protocols.oidc.client import ClientAuthMethod
from bastion.protocols.oidc.discovery import DiscoveryCache, ProviderMetadata
from bastion.protocols.oidc.jwks import JWKSStore
from bastion.protocols.oidc.quirks import REGISTRY, ProviderQuirks
from bastion.protocols.oidc.transaction import CacheTransactionStore, TransactionStore
from bastion.protocols.oidc.transport import Transport, UrllibTransport
from bastion.protocols.oidc.validation import ValidationPolicy

_REQUIRED = ("issuer", "client_id")


@dataclass
class Connection:
    """One configured identity provider."""

    identifier: str
    issuer: str
    client_id: str
    client_secret: str | None = None
    provider: str = "generic"
    scopes: tuple[str, ...] = ("openid", "email", "profile")
    auth_method: ClientAuthMethod = ClientAuthMethod.BASIC
    require_s256: bool = True
    require_mfa: bool = False

    # v0.1 mapping. The rule engine replaces this in v0.2; these two lists
    # cover the case the quickstart promises and nothing more.
    staff_groups: tuple[str, ...] = ()
    superuser_groups: tuple[str, ...] = ()

    # Whether an authenticated person with no matching group may sign in at
    # all. Off means authentication succeeds and authorisation does not, which
    # is the right default: the distinction is what makes the failure page able
    # to say something useful.
    require_group_match: bool = False

    validation: ValidationPolicy = field(default_factory=ValidationPolicy)
    transport: Transport = field(default_factory=UrllibTransport)
    transactions: TransactionStore = field(default_factory=CacheTransactionStore)
    quirks_kwargs: dict[str, Any] = field(default_factory=dict)

    _discovery: DiscoveryCache | None = field(default=None, repr=False)
    _keys: JWKSStore | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if self.provider not in REGISTRY:
            raise ConfigurationError(
                f"unknown provider {self.provider!r}. Known: {sorted(REGISTRY)}"
            )

    # ------------------------------------------------------------- resources --

    @property
    def quirks(self) -> ProviderQuirks:
        return REGISTRY[self.provider](**self.quirks_kwargs)

    @property
    def discovery(self) -> DiscoveryCache:
        with self._lock:
            if self._discovery is None:
                self._discovery = DiscoveryCache(
                    issuer=self.issuer,
                    transport=self.transport,
                    require_s256=self.require_s256,
                )
            return self._discovery

    def metadata(self) -> ProviderMetadata:
        return self.discovery.get()

    def key_store(self) -> JWKSStore:
        """Built from discovery, so a rotated ``jwks_uri`` is picked up.

        ``metadata()`` is resolved *before* taking the lock, deliberately. It
        reaches back into ``discovery``, which takes the same lock, and
        ``threading.Lock`` is not reentrant -- doing it the obvious way
        deadlocks on the first login and looks like a network hang.
        """
        uri = self.metadata().jwks_uri
        with self._lock:
            if self._keys is None or self._keys.uri != uri:
                self._keys = JWKSStore(uri=uri, fetcher=self.transport.get_json)
            return self._keys

    # ----------------------------------------------------------------- policy --

    def flags_for(self, groups: tuple[str, ...]) -> dict[str, bool]:
        """The v0.1 mapping: two lists, two flags.

        ``is_staff`` is promote-only and ``is_superuser`` is two-way, copied
        from mozilla-django-oidc-db. The asymmetry is deliberate: an identity
        provider hiccup should not lock every administrator out of the admin,
        but a revoked superuser must lose it immediately.
        """
        present = set(groups)
        flags: dict[str, bool] = {}
        if self.staff_groups and present & set(self.staff_groups):
            flags["is_staff"] = True
        if self.superuser_groups:
            flags["is_superuser"] = bool(present & set(self.superuser_groups))
        return flags

    @property
    def grants_privileges(self) -> bool:
        return bool(self.staff_groups or self.superuser_groups)


_cache: dict[str, Connection] = {}
_cache_lock = threading.Lock()


def build_connection(identifier: str, config: dict[str, Any]) -> Connection:
    """Turn one settings entry into a Connection, or explain why not."""
    unknown = set(config) - set(Connection.__dataclass_fields__)
    unknown -= {"discovery"}
    if unknown:
        raise ConfigurationError(f"connection {identifier!r} has unknown keys: {sorted(unknown)}")

    for name in _REQUIRED:
        if not config.get(name):
            raise ConfigurationError(f"connection {identifier!r} is missing {name!r}")

    kwargs = dict(config)
    kwargs.pop("discovery", None)
    for key in ("scopes", "staff_groups", "superuser_groups"):
        if key in kwargs:
            kwargs[key] = tuple(kwargs[key])
    if "auth_method" in kwargs:
        kwargs["auth_method"] = ClientAuthMethod(kwargs["auth_method"])

    return Connection(identifier=identifier, **kwargs)


def get_connection(identifier: str) -> Connection:
    """Return a configured connection, building and caching it on first use."""
    with _cache_lock:
        if identifier in _cache:
            return _cache[identifier]

    connections = get_setting("CONNECTIONS")
    if identifier not in connections:
        raise ConfigurationError(
            f"no connection named {identifier!r}. Configured: {sorted(connections) or 'none'}"
        )

    connection = build_connection(identifier, dict(connections[identifier]))
    with _cache_lock:
        _cache[identifier] = connection
    return connection


def all_connections() -> dict[str, Connection]:
    return {name: get_connection(name) for name in get_setting("CONNECTIONS")}


@receiver(setting_changed)
def _reset(*, setting: str, **kwargs: Any) -> None:
    if setting == "BASTION":
        with _cache_lock:
            _cache.clear()
