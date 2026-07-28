"""The normalised identity a protocol backend produces.

This is the seam that lets one mapping engine serve OIDC, SAML, LDAP and
proxy-header auth. It is also the place where an earlier, more optimistic
design was wrong, so the shape here is deliberately more awkward than
``dict[str, Any]`` would be.

Three fields exist purely because vendor behaviour forced them:

``subject_source``
    There is no single claim that means "the user". Entra's ``sub`` is pairwise
    per application, so two of your own apps see different values for the same
    person; the tenant-stable identifier is ``oid``. AD FS needs ``objectGUID``
    because ``upn`` is mutable. Ping lets the deployment remap ``sub`` to
    anything. Recording which claim we used means a configuration change is
    detectable instead of silently re-linking accounts to the wrong humans.

``email_verified`` as a tri-state
    Google emits it meaningfully. **Entra does not emit it at all.** Defaulting
    to False breaks every Entra login; defaulting to True is a security hole.
    So it is True, False, or Unknown, and the linking policy decides what
    Unknown means.

``group_value_format`` and ``groups_complete``
    A list of strings is not enough information to make an authorisation
    decision with. The same list can hold GUIDs (Entra), display names (Okta),
    ``/full/paths`` (Keycloak), SIDs (AD FS), or nothing at all (Google OIDC
    has no group claim). It may also be silently truncated: Entra above 150,
    Okta above 100, Google SAML above 75.
"""

from __future__ import annotations

import datetime as dt
import enum
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


class Verified(enum.Enum):
    """Tri-state, because "the provider did not say" is not the same as "no"."""

    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"

    def __bool__(self) -> bool:
        # Deliberately explicit: UNKNOWN is falsey, so `if claims.email_verified`
        # fails closed. Anywhere the distinction matters, compare to the member.
        return self is Verified.YES


class GroupFormat(enum.Enum):
    """How to read the strings in ``IdentityClaims.groups``.

    A mapping rule is portable across protocols for a given provider, and only
    conditionally portable across providers: specifically, only across
    providers that share a format. A rule matching ``"eng-admins"`` will never
    match an Entra deployment emitting GUIDs, and the failure is silent.
    """

    OPAQUE_ID = "opaque_id"  # Entra object GUIDs
    DISPLAY_NAME = "display_name"  # Okta, Entra with the names opt-in
    FULL_PATH = "full_path"  # Keycloak, /parent/child
    QUALIFIED_NAME = "qualified"  # DOMAIN\name
    SID = "sid"  # AD FS
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class IdentityClaims:
    """What a protocol backend hands to the rest of the pipeline."""

    issuer: str
    subject: str
    subject_source: str

    email: str | None = None
    email_verified: Verified = Verified.UNKNOWN
    display_name: str | None = None

    groups: tuple[str, ...] = ()
    group_value_format: GroupFormat = GroupFormat.UNKNOWN
    groups_complete: bool = True

    mfa_satisfied: bool = False

    # Optional in practice as well as in theory. Several providers omit
    # auth_time unless the request carried max_age.
    authn_time: dt.datetime | None = None
    expires_at: dt.datetime | None = None

    raw: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.issuer:
            raise ValueError("issuer is required")
        if not self.subject:
            raise ValueError("subject is required")
        if not self.subject_source:
            raise ValueError(
                "subject_source is required: record which claim the subject "
                "came from, so a configuration change is detectable"
            )

    @property
    def identity_key(self) -> tuple[str, str]:
        """The tuple accounts are keyed on. Never email, ever."""
        return (self.issuer, self.subject)

    def may_escalate_privileges(self) -> bool:
        """Whether this identity can be granted staff or superuser.

        A truncated group list is not evidence of absence. Entra above its
        overage threshold sends a pointer to Microsoft Graph instead of the
        groups themselves; treating that as "member of nothing" would strip
        every group-derived permission, and treating it as sufficient grounds
        to grant would be worse. So login proceeds and escalation does not.

        Nothing else in the Django ecosystem draws this distinction.
        """
        return self.groups_complete
