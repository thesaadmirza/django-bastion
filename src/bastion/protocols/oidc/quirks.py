"""Provider quirks.

This layer is mandatory, not optional, and that is the finding that reshaped
the design. There is no useful "generic OIDC" behaviour for subjects, groups or
MFA, because the providers do not agree on any of the three. A package that
ships one generic path and calls the rest configuration is quietly wrong on
every deployment that is not the one it was written against.

Each class here answers four questions:

- which claim is the stable subject, and what is it called
- what do the group values mean, and is the list complete
- did the provider actually say the address was verified
- did a second factor happen

Everything is sourced from vendor documentation, not from the specification.
"""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Any

from bastion.claims import GroupFormat, IdentityClaims, Verified
from bastion.exceptions import ClaimValidationError

GroupResult = tuple[tuple[str, ...], GroupFormat, bool]


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
        return _string_list(claims.get(self.groups_claim)), GroupFormat.UNKNOWN, True

    def email_verified(self, claims: Mapping[str, Any]) -> Verified:
        value = claims.get("email_verified")
        if value is True:
            return Verified.YES
        if value is False:
            return Verified.NO
        return Verified.UNKNOWN

    def mfa_satisfied(self, claims: Mapping[str, Any]) -> bool:
        return bool(set(_string_list(claims.get("amr"))) & self.mfa_methods)


class GenericQuirks(ProviderQuirks):
    """Spec-conformant defaults. Correct for very little in practice."""

    identifier = "generic"

    def subject(self, claims: Mapping[str, Any]) -> tuple[str, str]:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise ClaimValidationError("sub is missing")
        return subject, "sub"


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

    email = claims.get("email")
    name = claims.get("name") or claims.get("preferred_username")

    return IdentityClaims(
        issuer=issuer,
        subject=subject,
        subject_source=source,
        email=email if isinstance(email, str) else None,
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
