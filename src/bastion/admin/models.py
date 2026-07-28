"""Admin registration for the identity table.

Read-only where it matters. ``issuer``, ``subject`` and ``subject_source`` are
the tuple an account is resolved by, so an editable field here would be an
account-takeover primitive with a nice form around it: change one row's subject
to another person's and the next login lands in the wrong account.
"""

from __future__ import annotations

from typing import Any

from django.contrib import admin
from django.http import HttpRequest

from bastion.models import FederatedIdentity


@admin.register(FederatedIdentity)
class FederatedIdentityAdmin(admin.ModelAdmin):
    list_display = ("subject", "issuer", "connection", "user", "last_seen_at")
    list_filter = ("connection", "subject_source")
    search_fields = ("subject", "issuer", "user__username", "user__email")
    ordering = ("-last_seen_at",)
    autocomplete_fields = ()
    readonly_fields = (
        "issuer",
        "subject",
        "subject_source",
        "connection",
        "created_at",
        "last_seen_at",
    )

    def has_add_permission(self, request: HttpRequest) -> bool:
        """Links are created by a completed login, never by hand.

        A hand-made row asserts that a person at a provider is a given local
        user, which is exactly the claim the whole verification chain exists to
        establish.
        """
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False
