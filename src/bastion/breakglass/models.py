"""Break-glass account records."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.db import models
from django.utils import timezone


class BreakGlassAccountQuerySet(models.QuerySet["BreakGlassAccount"]):
    def active(self) -> BreakGlassAccountQuerySet:
        return self.filter(is_active=True)

    def stale(self, *, days: int = 90) -> BreakGlassAccountQuerySet:
        """Accounts not validated within the drill interval.

        Microsoft's guidance is 90 days, and on staff change. An emergency
        account nobody has tried is an emergency account nobody knows works.
        """
        cutoff = timezone.now() - timezone.timedelta(days=days)
        return self.active().filter(
            models.Q(last_validated_at__isnull=True) | models.Q(last_validated_at__lt=cutoff)
        )


class BreakGlassAccount(models.Model):
    """A local account that may bypass the identity provider.

    Marked by a record rather than by a magic username, so that the set is
    enumerable, auditable, and cannot be joined by accident.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="break_glass",
    )
    reason = models.TextField(
        help_text="Why this account exists. Required, and read during an incident."
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    is_active = models.BooleanField(default=True)

    last_used_at = models.DateTimeField(null=True, blank=True)
    #: Set by a successful drill. Distinct from last_used_at, because a use
    #: during a real incident does not tell you the account still works in
    #: normal conditions, and a drill does not tell you it was needed.
    last_validated_at = models.DateTimeField(null=True, blank=True)

    objects = BreakGlassAccountQuerySet.as_manager()

    class Meta:
        verbose_name = "break-glass account"

    def __str__(self) -> str:
        return f"break-glass: {self.user}"

    def delete(self, *args: Any, **kwargs: Any) -> None:
        """Refuse to remove the last active account.

        Deleting your way to zero is a thing people do while tidying up, and
        the consequence only appears during the outage that needed it.
        """
        if self.is_active and type(self).objects.active().exclude(pk=self.pk).count() == 0:
            raise LastBreakGlassAccount(
                "This is the only active break-glass account. Create another "
                "before removing it, or the next provider outage locks everyone "
                "out permanently."
            )
        super().delete(*args, **kwargs)


class LastBreakGlassAccount(Exception):
    """Raised when removing the final route back in."""
