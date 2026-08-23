"""Persistent identity.

One table for now. The link between a person at an identity provider and a
Django user is the thing mozilla-django-oidc does not model at all -- it stores
nothing, matches on email, and therefore cannot tell you which provider an
account came from, cannot support the same person arriving from two providers,
and orphans the account when an address changes.

Field widths are 255 rather than something more generous on purpose. A
composite index over two 255-character columns is 2040 bytes under utf8mb4,
which fits InnoDB's 3072-byte limit. Wider columns index fine on PostgreSQL and
fail on MySQL at migrate time, which is a poor way to find out.
"""

from __future__ import annotations

import datetime as dt

from django.conf import settings
from django.db import models
from django.utils import timezone

# Django's AppConfig imports only `<app>/models.py`, so models declared
# elsewhere in the package are never registered unless something pulls them in.
# Re-exported here rather than moved, because the audit tables belong with the
# rest of the audit code and splitting them for the sake of the loader would be
# the loader dictating the layout.
from bastion.audit.models import (  # noqa: F401  (import position is load-bearing)
    AuditActor,
    AuditChain,
    AuditEvent,
)
from bastion.breakglass.models import BreakGlassAccount  # noqa: F401


class FederatedIdentityQuerySet(models.QuerySet["FederatedIdentity"]):
    def for_claims(self, issuer: str, subject: str) -> FederatedIdentityQuerySet:
        return self.filter(issuer=issuer, subject=subject)


class FederatedIdentity(models.Model):
    """A person at a provider, linked to a local user.

    Keyed on ``(issuer, subject)``. Never on email: an address is mutable at
    the provider, and an administrator who can change one would otherwise be
    able to take over another account. That is django-allauth CVE-2025-65431,
    observed in the wild against Okta and NetIQ.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="federated_identities",
    )

    issuer = models.CharField(
        max_length=255,
        help_text="The provider's issuer identifier, exactly as it appears in the token.",
    )
    subject = models.CharField(
        max_length=255,
        help_text="The provider's stable identifier for this person.",
    )
    subject_source = models.CharField(
        max_length=64,
        help_text=(
            "Which claim the subject was read from. Recorded so that a "
            "configuration change is detectable rather than silently "
            "re-linking accounts: Entra's sub is pairwise per application "
            "while oid is stable, and swapping between them would otherwise "
            "look like a new person."
        ),
    )

    connection = models.CharField(
        max_length=100,
        db_index=True,
        help_text="Which configured connection this identity last arrived through.",
    )

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    last_seen_at = models.DateTimeField(default=timezone.now)

    objects = FederatedIdentityQuerySet.as_manager()

    class Meta:
        verbose_name = "federated identity"
        verbose_name_plural = "federated identities"
        constraints = [
            models.UniqueConstraint(
                fields=["issuer", "subject"],
                name="bastion_identity_unique_issuer_subject",
            )
        ]
        indexes = [models.Index(fields=["user", "connection"])]

    def __str__(self) -> str:
        return f"{self.subject} @ {self.issuer}"

    def subject_source_changed(self, source: str) -> bool:
        """Whether the claim we read the subject from has moved.

        A deployment that switches Entra from ``sub`` to ``oid`` produces the
        same human under a different identifier. Without noticing, the second
        login creates a duplicate account and the first one's permissions are
        stranded. Callers surface this rather than resolving it silently.
        """
        return self.subject_source != source


class FederatedSession(models.Model):
    """One Django session, and which provider session it came from.

    This exists because back-channel logout arrives naming a ``sid`` or a
    ``sub``, and Django's session table is keyed on neither. Without an index
    from one to the other, honouring a logout token would mean walking every
    session in the store and decoding it, which is only possible on some
    backends and is never cheap.

    Rows are the index, not the session. Deleting one revokes nothing on its
    own; the session store is the thing that has to be told, and
    ``bastion.sessions`` is what tells it.
    """

    identity = models.ForeignKey(
        FederatedIdentity,
        on_delete=models.CASCADE,
        related_name="sessions",
    )

    session_key = models.CharField(
        max_length=40,
        unique=True,
        help_text="The Django session this login established.",
    )

    sid = models.CharField(
        max_length=255,
        blank=True,
        db_index=True,
        help_text=(
            "The provider's session identifier, where it sends one. Blank is "
            "normal: sid is optional, and a provider that omits it can still "
            "end every session for a subject, just not one of them."
        ),
    )

    connection = models.CharField(max_length=100, db_index=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        verbose_name = "federated session"
        indexes = [models.Index(fields=["identity", "sid"])]

    def __str__(self) -> str:
        return f"{self.session_key[:8]}… ({self.sid or 'no sid'})"


class SeenLogoutToken(models.Model):
    """A logout token that has already been acted on.

    Single use, enforced by the unique constraint rather than by a read
    followed by a write. Two copies of the same token arriving at once is
    exactly the shape a replay takes, and a check-then-insert would let both
    through: whichever transaction inserts second gets the IntegrityError, and
    that is the signal.

    The cache would be the conventional place and is the wrong one, for the
    reason the break-glass throttle already documents. Django's default cache
    is per-process, so a deployment on four workers would get four independent
    memories of what it had seen and a token could be replayed once per worker.

    Rows are prunable because a logout token is only valid for
    ``logout.MAX_AGE``; anything older cannot be accepted whether or not it is
    remembered. ``purge_expired`` is what keeps the table bounded.
    """

    issuer = models.CharField(max_length=255)
    jti = models.CharField(max_length=255)
    expires_at = models.DateTimeField(
        db_index=True,
        help_text="After this the token is refused on age alone, so the row can go.",
    )
    seen_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        verbose_name = "seen logout token"
        constraints = [
            models.UniqueConstraint(
                fields=["issuer", "jti"],
                name="bastion_logout_token_unique_issuer_jti",
            )
        ]

    def __str__(self) -> str:
        return f"{self.jti} @ {self.issuer}"

    @classmethod
    def purge_expired(cls, *, now: dt.datetime | None = None) -> int:
        """Drop rows for tokens that age alone would now refuse."""
        cutoff = now or timezone.now()
        deleted, _ = cls.objects.filter(expires_at__lt=cutoff).delete()
        return int(deleted)
