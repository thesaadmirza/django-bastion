"""Admin registration for the identity table.

Read-only where it matters. ``issuer``, ``subject`` and ``subject_source`` are
the tuple an account is resolved by, so an editable field here would be an
account-takeover primitive with a nice form around it: change one row's subject
to another person's and the next login lands in the wrong account.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib import admin
from django.http import HttpRequest

from bastion.audit.models import AuditEvent
from bastion.models import FederatedIdentity

# django-stubs types ModelAdmin as generic, but the runtime class is not
# subscriptable: `ModelAdmin[Model]` raises TypeError on import. django-stubs-ext
# offers a monkeypatch for this, and requiring consumers to call it would be
# rude for a library, so the parameterisation is confined to type-checking.
if TYPE_CHECKING:
    _IdentityAdmin = admin.ModelAdmin[FederatedIdentity]
    _EventAdmin = admin.ModelAdmin[AuditEvent]
else:
    _IdentityAdmin = admin.ModelAdmin
    _EventAdmin = admin.ModelAdmin


@admin.register(FederatedIdentity)
class FederatedIdentityAdmin(_IdentityAdmin):
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


@admin.register(AuditEvent)
class AuditEventAdmin(_EventAdmin):
    """A reader for the audit log.

    Entirely read-only, including delete. Retention is the only route by which
    records leave, and it records what it removed; a delete button here would
    be a way to remove evidence without leaving any.

    The actor column shows the opaque token rather than a name, because that is
    genuinely all the table holds. Resolving it needs the mapping, and after an
    erasure request there is nothing to resolve.
    """

    list_display = (
        "chain_seq",
        "occurred_at",
        "event_type",
        "outcome",
        "actor_pseudonym",
        "connection",
        "is_privileged",
    )
    list_filter = ("event_type", "outcome", "severity", "is_privileged", "connection")
    search_fields = ("actor_pseudonym", "subject", "correlation_id", "target_id")
    date_hierarchy = "occurred_at"
    ordering = ("-chain_seq",)

    readonly_fields = tuple(field.name for field in AuditEvent._meta.fields if field.name != "id")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False
