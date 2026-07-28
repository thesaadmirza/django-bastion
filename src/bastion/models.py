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

from django.conf import settings
from django.db import models
from django.utils import timezone


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
