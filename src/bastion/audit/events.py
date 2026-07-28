"""The event catalogue.

Publishing this list *is* the NIST AU-2(a)/(c)/(d) deliverable: identify what
the system is capable of logging, specify what it does log, and give a rationale
for why that selection is adequate for after-the-fact investigation. Customers
otherwise write it by hand from source, badly.

Names are dotted and stable. Renaming one is a breaking change for anyone whose
SIEM rules or compliance evidence reference it, so treat them as public API.
"""

from __future__ import annotations

import enum


class Event(enum.StrEnum):
    """Every event type this package emits."""

    # -- authentication ----------------------------------------------------
    LOGIN_SUCCEEDED = "auth.login.succeeded"
    LOGIN_FAILED = "auth.login.failed"
    #: Authenticated, then refused. Distinct from failure on purpose: an
    #: authorisation denial and an authentication failure are different
    #: detections under SOC 2 CC7.2, and collapsing them loses the signal that
    #: someone's credentials work but their access does not.
    LOGIN_DENIED = "auth.login.denied"
    LOGOUT = "auth.logout"
    SESSION_REVOKED = "auth.session.revoked"

    #: Signature, issuer, audience, nonce, replay or clock validation failed.
    #: High signal: this is what a token forgery attempt looks like.
    ASSERTION_REJECTED = "auth.assertion.rejected"

    #: A local password was used where SSO was expected. Rare by design, and
    #: therefore worth alerting on.
    PROTOCOL_FALLBACK = "auth.protocol.fallback"

    MFA_REQUIRED = "auth.mfa.required"
    MFA_SATISFIED = "auth.mfa.satisfied"
    MFA_MISSING = "auth.mfa.missing"

    # -- identity lifecycle ------------------------------------------------
    USER_PROVISIONED = "user.provisioned"
    USER_UPDATED = "user.updated"
    USER_DEACTIVATED = "user.deactivated"
    USER_REACTIVATED = "user.reactivated"

    #: Frequently missing from packages, and frequently the root cause when an
    #: account takeover is investigated afterwards.
    IDENTITY_LINKED = "user.identity_linked"
    IDENTITY_UNLINKED = "user.identity_unlinked"

    #: The provider asserted a subject under a different claim than the one the
    #: link was made with. Almost always a configuration change.
    IDENTITY_SOURCE_CONFLICT = "user.identity_source_conflict"

    # -- authorisation -----------------------------------------------------
    ROLE_GRANTED = "role.granted"
    ROLE_REVOKED = "role.revoked"
    MAPPING_EVALUATED = "mapping.evaluated"

    #: Group data arrived truncated, so privilege escalation was refused while
    #: the login itself proceeded.
    MAPPING_INCOMPLETE = "mapping.incomplete"

    #: A point-in-time snapshot of who holds what. This is what lets an auditor
    #: answer "who had admin on 14 March" without reconstructing state from a
    #: change stream.
    ENTITLEMENT_SNAPSHOT = "entitlement.snapshot"

    # -- configuration and trust anchors -----------------------------------
    CONNECTION_CHANGED = "idp.connection.changed"
    JWKS_REFRESHED = "idp.jwks.refreshed"
    METADATA_REFRESHED = "idp.metadata.refreshed"

    # -- the audit log's own operations ------------------------------------
    #: Who exported evidence, covering what range. Auditors like this;
    #: regulators like it more.
    AUDIT_EXPORTED = "audit.export.generated"
    AUDIT_VERIFIED = "audit.integrity.verified"
    AUDIT_VERIFICATION_FAILED = "audit.integrity.failed"
    #: Recorded so that a gap in the sequence has an explanation rather than
    #: looking like evidence destruction.
    AUDIT_PURGED = "audit.retention.purged"
    ACTOR_FORGOTTEN = "audit.actor.forgotten"


class Outcome(enum.StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    #: Authenticated but not permitted. Kept apart from FAILURE deliberately.
    DENIED = "denied"
    ERROR = "error"


class Severity(enum.StrEnum):
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    CRITICAL = "critical"


#: Events that should reach someone rather than only a table.
ALERTABLE: frozenset[Event] = frozenset(
    {
        Event.ASSERTION_REJECTED,
        Event.PROTOCOL_FALLBACK,
        Event.IDENTITY_SOURCE_CONFLICT,
        Event.AUDIT_VERIFICATION_FAILED,
    }
)
