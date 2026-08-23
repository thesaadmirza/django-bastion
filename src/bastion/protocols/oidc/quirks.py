"""Provider quirks.

This layer is mandatory, not optional, and that is the finding that reshaped
the design. There is no useful "generic OIDC" behaviour for subjects, groups or
MFA, because the providers do not agree on any of the three. A package that
ships one generic path and calls the rest configuration is quietly wrong on
every deployment that is not the one it was written against.

``GenericQuirks`` is configurable, which is not a retreat from that. The
difference is who supplies the answer. Nothing here inspects a token to work
out which claim looks like a group list; a deployment reads its provider's
documentation and writes the name down, and until it does the defaults stay
spec-shaped and wrong for most providers. Declared beats sniffed, because the
sniffing version grants staff from whichever claim resembled a group list, and
an attacker only has to influence one claim for that to be theirs.

Two ways to answer, then. A profile in ``REGISTRY`` for a provider whose quirks
this project has taken on and will maintain, and configuration for the far
larger number it has not. A provider whose only difference is where its groups
live does not need a profile; that is what ``groups_claim`` is for.

Each class here answers four questions about a token's claims:

- which claim is the stable subject, and what is it called
- what do the group values mean, and is the list complete
- did the provider actually say the address was verified
- did a second factor happen

A profile also carries a small amount of endpoint behaviour that no claim can
express -- currently ``sign_in_paths``, read only by ``bastion_doctor``. That
is a deliberate widening rather than drift: the fact has to be keyed per
provider, and this registry is the only per-provider keying in the package.
Anything added here that is not about claims should have the same defence.

Everything is sourced from vendor documentation, not from the specification.
"""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Any

from bastion.claims import GroupFormat, IdentityClaims, Verified
from bastion.exceptions import ClaimValidationError, ConfigurationError

GroupResult = tuple[tuple[str, ...], GroupFormat, bool]


def _claim_name(value: Any, setting: str) -> str:
    """A claim name has to be a non-empty string, and nothing else.

    Checked rather than trusted because these arrive from settings. An empty
    name reads every token as having no such claim, which for ``groups_claim``
    means everybody is in no groups and every group-derived privilege quietly
    disappears -- a failure that looks like a provider problem for as long as
    nobody thinks to check the setting.
    """
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{setting} must be a non-empty claim name, got {value!r}")
    return value


def _group_format(value: str | GroupFormat) -> GroupFormat:
    """Accept the enum or the string a settings file can hold."""
    if isinstance(value, GroupFormat):
        return value
    try:
        return GroupFormat(value)
    except ValueError:
        known = ", ".join(sorted(member.value for member in GroupFormat))
        raise ConfigurationError(f"groups_format {value!r} is not one of: {known}") from None


def _string_list(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and all(isinstance(v, str) for v in value):
        return tuple(value)
    return ()


class ProviderQuirks(ABC):
    """One per identity provider. Registered by identifier."""

    identifier: str = "generic"

    #: ``amr`` values this provider emits that constitute a second factor.
    mfa_methods: frozenset[str] = frozenset({"mfa", "otp", "hwk", "swk"})

    #: Claim carrying group membership.
    groups_claim: str = "groups"

    #: What the strings in that claim mean. A profile that knows says so; the
    #: default is honest rather than optimistic, because a mapping rule written
    #: against display names silently matches nothing on a provider emitting
    #: GUIDs and the failure looks like "that person is in no groups".
    groups_format: GroupFormat = GroupFormat.UNKNOWN

    #: Claim carrying the address, and the one carrying the provider's opinion
    #: of whether it is verified. Named rather than hardcoded because they move:
    #: an Auth0 tenant with a custom namespace puts both behind a URI prefix.
    email_claim: str = "email"
    email_verified_claim: str = "email_verified"

    #: Exact paths, on the authorization endpoint's own origin, that this
    #: provider redirects to once it has accepted a client id and redirect URI.
    #:
    #: Only for providers that answer a good authorization request with a 302
    #: rather than a served form: there is no form in a redirect, so the markers
    #: the classifier normally reads are absent and a correct deployment gets a
    #: shrug. Exact paths rather than a prefix or a "looks like sign-in" rule,
    #: because a provider's error page tends to live next door -- Google's is
    #: /signin/oauth/error, one segment away from the real thing -- and a false
    #: positive here reports a broken deployment as healthy.
    sign_in_paths: tuple[str, ...] = ()

    @abstractmethod
    def subject(self, claims: Mapping[str, Any]) -> tuple[str, str]:
        """Return ``(subject, subject_source)``."""

    def check(self, claims: Mapping[str, Any]) -> None:  # noqa: B027
        """Provider-specific validation beyond the standard claim checks.

        Not abstract, and the empty default is deliberate. Most providers have
        nothing extra to assert; the ones that do are tenant-pinning checks
        that only exist because the provider offers a tenant boundary at all
        (Entra's ``tid``, Google's ``hd``). Forcing every subclass to write
        ``pass`` would make the two that matter harder to spot.
        """

    def groups(self, claims: Mapping[str, Any]) -> GroupResult:
        return _string_list(claims.get(self.groups_claim)), self.groups_format, True

    def email(self, claims: Mapping[str, Any]) -> str | None:
        value = claims.get(self.email_claim)
        return value if isinstance(value, str) else None

    def email_verified(self, claims: Mapping[str, Any]) -> Verified:
        value = claims.get(self.email_verified_claim)
        if value is True:
            return Verified.YES
        if value is False:
            return Verified.NO
        # Some providers send the string rather than the boolean. Read those
        # two spellings and nothing else: anything further is guessing at what
        # a provider meant, on the claim that decides whether an address is
        # good enough to adopt an existing administrator's account.
        if isinstance(value, str) and value.lower() in {"true", "false"}:
            return Verified.YES if value.lower() == "true" else Verified.NO
        return Verified.UNKNOWN

    def mfa_satisfied(self, claims: Mapping[str, Any]) -> bool:
        return bool(set(_string_list(claims.get("amr"))) & self.mfa_methods)


class GenericQuirks(ProviderQuirks):
    """Spec defaults out of the box, and the profile you configure otherwise.

    Left alone this is still what the module docstring says it is: correct for
    very little, because no provider agrees on where the interesting claims
    live. Configured, it is how a provider nobody has written a class for gets
    used without writing one.

    That distinction is the whole design. The claim names are *declared* by the
    deployment, never sniffed from the token. Guessing which claim holds the
    groups by looking for one that resembles a group list is how a package
    ends up granting staff from an attacker-influenced claim, so the only
    supported answer is that somebody who read their provider's documentation
    writes the name down.

    Configured through ``quirks_kwargs`` on the connection::

        "corp": {
            "provider": "generic",
            "issuer": "https://example.auth0.com/",
            "client_id": env("CLIENT_ID"),
            "quirks_kwargs": {
                "groups_claim": "https://example.com/groups",
                "groups_format": "display_name",
                "expected_claims": {"org_id": "org_abc123"},
            },
        }

    ``expected_claims`` is the generic form of the tenant pin that ``entra``
    and ``google`` hardcode. Without one, a multi-tenant provider will happily
    authenticate somebody from a tenant you have never heard of, and every
    check downstream will agree that their token was perfectly valid.
    """

    identifier = "generic"

    def __init__(
        self,
        *,
        subject_claim: str = "sub",
        groups_claim: str = "groups",
        groups_format: str | GroupFormat = GroupFormat.UNKNOWN,
        email_claim: str = "email",
        email_verified_claim: str = "email_verified",
        mfa_methods: Sequence[str] | None = None,
        expected_claims: Mapping[str, Any] | None = None,
    ) -> None:
        self.subject_claim = _claim_name(subject_claim, "subject_claim")
        self.groups_claim = _claim_name(groups_claim, "groups_claim")
        self.groups_format = _group_format(groups_format)
        self.email_claim = _claim_name(email_claim, "email_claim")
        self.email_verified_claim = _claim_name(email_verified_claim, "email_verified_claim")
        if mfa_methods is not None:
            if not mfa_methods:
                raise ConfigurationError(
                    "mfa_methods is empty, which would mean no assertion ever "
                    "satisfies require_mfa. Leave it unset for the defaults."
                )
            self.mfa_methods = frozenset(mfa_methods)
        self.expected_claims = dict(expected_claims or {})

    def subject(self, claims: Mapping[str, Any]) -> tuple[str, str]:
        subject = claims.get(self.subject_claim)
        if not isinstance(subject, str) or not subject:
            raise ClaimValidationError(
                f"{self.subject_claim!r} is missing or is not a string, so this "
                "token carries no stable identifier to key an account on."
            )
        return subject, self.subject_claim

    def check(self, claims: Mapping[str, Any]) -> None:
        """Pin whatever claims the deployment says identify its tenant.

        Compared exactly, and against a value from configuration rather than
        anything in the token. A provider that serves more than one
        organisation issues perfectly valid tokens for all of them, so without
        this every other check passes and the wrong tenant gets in.
        """
        for name, expected in self.expected_claims.items():
            if claims.get(name) != expected:
                raise ClaimValidationError(
                    f"claim {name!r} does not match the value this connection pins"
                )


class EntraQuirks(ProviderQuirks):
    """Microsoft Entra ID.

    The subject is ``oid``, not ``sub``. Entra's ``sub`` is **pairwise per
    application registration**, so two of your own apps see different values
    for the same person and any account keyed on it breaks the moment a second
    client id is added. ``oid`` is stable within the tenant.

    Groups arrive as object GUIDs unless the tenant opts into names, and above
    200 in a JWT (150 in SAML) Entra replaces them with a pointer to Microsoft
    Graph. That pointer is why ``groups_complete`` exists.

    Entra emits no ``email_verified`` at all. The nearest analogue is
    ``xms_edov``, which is opt-in and has different preconditions.
    """

    identifier = "entra"
    mfa_methods = frozenset({"mfa", "multipleauthn", "hwk", "swk", "fido", "wia"})

    def __init__(self, *, expected_tenant: str | None = None) -> None:
        self.expected_tenant = expected_tenant

    def subject(self, claims: Mapping[str, Any]) -> tuple[str, str]:
        oid = claims.get("oid")
        if not isinstance(oid, str) or not oid:
            raise ClaimValidationError(
                "oid is missing. Entra's sub is pairwise per application and "
                "cannot be used as a stable identifier; enable the oid claim."
            )
        return oid, "oid"

    def check(self, claims: Mapping[str, Any]) -> None:
        """Compare ``tid`` against the configured tenant.

        Every configurable Entra issuer already names its tenant in the URL --
        the multi-tenant endpoints declare a templated issuer and are refused
        during discovery -- so this is a second opinion taken from the token
        rather than from the address it was fetched over, and it fires if the
        two ever disagree.
        """
        if self.expected_tenant is None:
            return
        if claims.get("tid") != self.expected_tenant:
            raise ClaimValidationError("tid does not match the expected tenant")

    def groups(self, claims: Mapping[str, Any]) -> GroupResult:
        if "_claim_names" in claims or claims.get("hasgroups"):
            # Overage. The groups are not here; resolving them needs a Graph
            # call with admin-consented GroupMember.Read.All. Until that
            # happens the list is not merely empty, it is unknown, and the
            # difference decides whether privileges may be granted.
            return (), GroupFormat.OPAQUE_ID, False
        values = _string_list(claims.get(self.groups_claim))
        return values, GroupFormat.OPAQUE_ID, True

    def email_verified(self, claims: Mapping[str, Any]) -> Verified:
        edov = claims.get("xms_edov")
        if edov is True:
            return Verified.YES
        if edov is False:
            return Verified.NO
        return Verified.UNKNOWN


class OktaQuirks(ProviderQuirks):
    """Okta.

    The ``groups`` claim is **not emitted by default**, so a fresh integration
    looks like a user with no groups rather than an error. Above 100 groups
    Okta errors on the filter instead of sending an overage claim, which means
    a truncated list never reaches us -- but it also means we cannot detect the
    condition from the token alone.
    """

    identifier = "okta"
    mfa_methods = frozenset({"mfa", "otp", "hwk", "swk", "sms", "kba"})

    def subject(self, claims: Mapping[str, Any]) -> tuple[str, str]:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise ClaimValidationError("sub is missing")
        return subject, "sub"

    def groups(self, claims: Mapping[str, Any]) -> GroupResult:
        return _string_list(claims.get(self.groups_claim)), GroupFormat.DISPLAY_NAME, True


class GoogleQuirks(ProviderQuirks):
    """Google Workspace.

    Google's OIDC ID token has **no group claim at all** -- the live discovery
    document's ``claims_supported`` does not list one. Group membership
    requires an out-of-band Admin SDK Directory API call.

    So groups are reported as empty *and incomplete*. That is not pedantry:
    marking them complete would assert this person is a member of nothing,
    which would let a mapping rule strip permissions on evidence that does not
    exist. Marking them incomplete means a Google OIDC login can authenticate
    but cannot by itself justify granting staff.
    """

    identifier = "google"

    #: Versioned, and Google has moved it before -- ``/signin/v2/identifier``
    #: preceded this one. When it moves again the verdict falls back to
    #: inconclusive, which is the direction a stale entry should fail in.
    sign_in_paths = ("/v3/signin/identifier",)

    def __init__(self, *, hosted_domain: str | None = None) -> None:
        self.hosted_domain = hosted_domain

    def subject(self, claims: Mapping[str, Any]) -> tuple[str, str]:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise ClaimValidationError("sub is missing")
        return subject, "sub"

    def check(self, claims: Mapping[str, Any]) -> None:
        """Pin the Workspace domain.

        ``hd`` is the only tenant boundary Google offers. Omitting this check
        on a Workspace integration means any Google account, personal ones
        included, satisfies the login.
        """
        if self.hosted_domain is None:
            return
        if claims.get("hd") != self.hosted_domain:
            raise ClaimValidationError("hd does not match the expected Workspace domain")

    def groups(self, claims: Mapping[str, Any]) -> GroupResult:
        return (), GroupFormat.UNKNOWN, False


class KeycloakQuirks(ProviderQuirks):
    """Keycloak.

    The group mapper's "full group path" toggle decides whether values arrive
    as ``/eng/backend`` or ``backend``. A rule written against one silently
    fails against the other, which is why the format travels with the values.
    """

    identifier = "keycloak"

    def subject(self, claims: Mapping[str, Any]) -> tuple[str, str]:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise ClaimValidationError("sub is missing")
        return subject, "sub"

    def groups(self, claims: Mapping[str, Any]) -> GroupResult:
        values = _string_list(claims.get(self.groups_claim))
        rooted = all(v.startswith("/") for v in values) if values else False
        fmt = GroupFormat.FULL_PATH if rooted else GroupFormat.DISPLAY_NAME
        return values, fmt, True


REGISTRY: dict[str, type[ProviderQuirks]] = {
    "generic": GenericQuirks,
    "entra": EntraQuirks,
    "okta": OktaQuirks,
    "google": GoogleQuirks,
    "keycloak": KeycloakQuirks,
}


def resolve(provider: str) -> type[ProviderQuirks]:
    """A registry name, or an import path to a class of your own.

    Two ways in rather than one, because a name in this registry is a promise
    this project maintains and an import path is not. A provider with a quirk
    that cannot be expressed as a claim name -- a subject that has to be
    assembled from two claims, a group list that arrives base64-encoded --
    needs real code, and needing real code should not mean forking the package
    or monkey-patching this dict at import time.

    The path is refused unless it names a ``ProviderQuirks`` subclass, so a
    typo pointing at something unrelated fails at startup with a message
    saying so, rather than at the first login with an AttributeError.
    """
    if provider in REGISTRY:
        return REGISTRY[provider]
    if "." not in provider:
        raise ConfigurationError(
            f"unknown provider {provider!r}. Known: {sorted(REGISTRY)}. "
            "An import path to a ProviderQuirks subclass is also accepted."
        )

    from django.utils.module_loading import import_string

    try:
        loaded = import_string(provider)
    except ImportError as exc:
        raise ConfigurationError(f"could not import provider {provider!r}: {exc}") from exc

    if not (isinstance(loaded, type) and issubclass(loaded, ProviderQuirks)):
        raise ConfigurationError(
            f"provider {provider!r} is not a ProviderQuirks subclass. "
            "Subclass bastion.protocols.oidc.quirks.ProviderQuirks."
        )
    return loaded


def to_identity_claims(
    claims: Mapping[str, Any], *, quirks: ProviderQuirks, issuer: str
) -> IdentityClaims:
    """Turn validated OIDC claims into the protocol-agnostic identity."""
    quirks.check(claims)

    subject, source = quirks.subject(claims)
    groups, group_format, complete = quirks.groups(claims)

    def moment(name: str) -> dt.datetime | None:
        value = claims.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return dt.datetime.fromtimestamp(value, tz=dt.UTC)

    email = quirks.email(claims)
    name = claims.get("name") or claims.get("preferred_username")

    return IdentityClaims(
        issuer=issuer,
        subject=subject,
        subject_source=source,
        email=email,
        email_verified=quirks.email_verified(claims),
        display_name=name if isinstance(name, str) else None,
        groups=groups,
        group_value_format=group_format,
        groups_complete=complete,
        mfa_satisfied=quirks.mfa_satisfied(claims),
        authn_time=moment("auth_time"),
        expires_at=moment("exp"),
        raw=dict(claims),
    )
