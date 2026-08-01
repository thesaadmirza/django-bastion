"""Settings resolution.

Two rules govern everything in this module, and both come from watching other
packages get it wrong:

1. One namespaced ``BASTION`` dict. django-allauth ships roughly 134 flat
   top-level setting names across six prefixes and three casing conventions;
   mozilla-django-oidc ships 39, including a near-duplicate pair and one
   setting that is documented but never read. Namespacing is not tidiness, it
   is the only way the config surface stays reviewable.

2. Settings hold code-level extension points and defaults. The database holds
   per-connection instance config. No key may be set in both places. allauth's
   three-way duality between ``APP``, ``APPS`` and the ``SocialApp`` model
   produces ``MultipleObjectsReturned`` from a getter, and its settings-derived
   model instances have ``pk = None``, which silently breaks foreign keys.

The ``dynamic_setting`` descriptor is taken, near-verbatim and with thanks,
from mozilla-django-oidc-db. It exists so that auth backends can resolve
configuration lazily. Django instantiates auth backends on *every* permission
check, so reading config in ``__init__`` is both a correctness blocker for
per-tenant configuration and a performance hazard.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from django.conf import settings
from django.core.signals import setting_changed
from django.dispatch import receiver
from django.utils.module_loading import import_string

T = TypeVar("T")

SETTING_NAME = "BASTION"

#: Code-level extension points and defaults only. Anything describing a
#: *specific* identity provider belongs in the database.
DEFAULTS: dict[str, Any] = {
    # The auth backend is the customisation seam for now. The ordered pipeline
    # and the separate resolver/provisioner/reconciler protocols arrive with
    # the rule engine; declaring their settings
    # before they exist would mean shipping a config surface that does nothing,
    # which is worse than not having one.
    "BACKEND": "bastion.backends.SSOBackend",
    "SUCCESS_URL": "/",
    "IDENTITY": {
        # (issuer, subject). Never email. mozilla-django-oidc defaults to
        # email__iexact, Django's User.email has no unique constraint, and an
        # IdP admin who can change an address takes over an account. That is
        # allauth CVE-2025-65431, seen in the wild against Okta and NetIQ.
        "KEY": ("issuer", "subject"),
        "LINKING_POLICY": "subject_only",
        "REQUIRE_VERIFIED_EMAIL": True,
    },
    # v0.1 maps groups to flags per connection via staff_groups and
    # superuser_groups. The rule engine lands in v0.2 and takes this over.
    "MAPPING": {
        "STRICT": True,
        "MANAGED_GROUPS": "prefix:sso-",
    },
    "ADMIN": {
        "enabled": True,
        "connection": None,
        # Off, and the change from True is a fix rather than a relaxation. It
        # read as True and enforced nothing, so no deployment ever had admin MFA
        # from this key; it is now enforced, and defaulting it on would have
        # locked out every deployment whose provider does not emit `amr`, which
        # is opt-in on several of them. A control that depends on a claim the
        # provider may simply omit cannot fail closed by default without
        # bricking the admin it protects. Turn it on after one sign-in shows the
        # claim arriving -- `bastion_doctor` says the same about the per-
        # connection flag.
        "require_mfa": False,
        "reauth_max_age": 3600,
        "local_login": "breakglass_only",
    },
    "BREAK_GLASS": {
        # Off by default. An emergency route nobody decided to have is worse
        # than not having one.
        "ENABLED": False,
        #: CIDRs the emergency login answers from. Empty means anywhere, which
        #: the startup check warns about rather than silently accepting.
        "ALLOWED_NETWORKS": [],
        #: Callables taking (subject, detail), fired synchronously. A startup
        #: check refuses to run with break-glass on and this empty.
        "ALERT_SINKS": [],
        #: Credential failures from one address before that address is refused,
        #: counted over FAILURE_WINDOW_SECONDS. Per address and never per
        #: account: locking the account would let anyone who can reach the form
        #: disable the emergency route. 0 disables the throttle.
        "MAX_FAILURES_PER_IP": 5,
        "FAILURE_WINDOW_SECONDS": 900,
        "SUCCESS_URL": "/admin/",
    },
    "AUDIT": {
        "SINKS": ["bastion.audit.sinks.DatabaseSink"],
        # CNIL's logging recommendation is the only regulator text that puts a
        # number on this: six months to a year as standard, up to three years
        # where a documented internal-control need exists. PCI requires twelve
        # months with three immediately available; FedRAMP one year with ninety
        # days online. HIPAA sets nothing, contrary to widespread belief -- its
        # six-year rule covers required documentation, not application logs.
        #
        # Twelve months satisfies every regime that names a number. It is a
        # default, not a requirement, and the docs say so.
        "RETENTION_DAYS": 365,
    },
    "CONNECTIONS": {},
}

#: Settings whose values are dotted paths and should be imported on access.
IMPORT_STRINGS: frozenset[str] = frozenset()

_cache: dict[str, Any] = {}


def _user_settings() -> dict[str, Any]:
    return getattr(settings, SETTING_NAME, {}) or {}


def _merge(default: Any, override: Any) -> Any:
    """Shallow-merge one level into nested dicts.

    Deliberately shallow. Deep merging makes it impossible for a deployer to
    *remove* a default, and "why is this key still set" is a miserable thing to
    debug in an auth path.
    """
    if isinstance(default, dict) and isinstance(override, dict):
        merged = dict(default)
        merged.update(override)
        return merged
    return override


def get_setting(name: str, default: Any = ...) -> Any:
    """Resolve a single top-level key of the ``BASTION`` dict."""
    if name in _cache:
        return _cache[name]

    if name not in DEFAULTS and default is ...:
        raise AttributeError(f"Invalid {SETTING_NAME} setting: {name!r}")

    base = DEFAULTS.get(name, default)
    value = _merge(base, _user_settings()[name]) if name in _user_settings() else base

    if name in IMPORT_STRINGS and isinstance(value, str):
        value = import_string(value)

    _cache[name] = value
    return value


class dynamic_setting(Generic[T]):
    """A lazily resolved, read-only, typed settings attribute.

    The attribute name *is* the setting name::

        class SSOBackend(BaseBackend):
            PIPELINE = dynamic_setting[list[str]]()

    Read-only on purpose: a settings value that can be assigned at runtime is a
    settings value that will be assigned at runtime, in a request handler, by
    accident.
    """

    _NOT_SET = object()

    def __init__(self, default: Any = _NOT_SET) -> None:
        self.default = default
        self.name = ""

    def __set_name__(self, owner: type, name: str) -> None:
        self.name = name

    def __get__(self, obj: object, objtype: type | None = None) -> Any:
        if obj is None:
            return self
        if self.default is self._NOT_SET:
            return get_setting(self.name)
        return get_setting(self.name, self.default)

    def __set__(self, obj: object, value: Any) -> None:
        raise AttributeError(f"{self.name} is read-only")


@receiver(setting_changed)
def _reset_cache(*, setting: str, **kwargs: Any) -> None:
    """Make ``override_settings`` work in tests.

    Copied from DRF's APISettings pattern. Without this, a test that overrides
    BASTION sees the value cached by an earlier test, which produces the worst
    class of test failure: order-dependent and only in CI.
    """
    if setting == SETTING_NAME:
        _cache.clear()
        from bastion.audit.recorder import reset_sinks

        reset_sinks()
