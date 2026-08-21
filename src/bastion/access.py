"""Who can reach the admin right now, and how each of them got there.

The audit chain records provisioning, linking, grants and refusals. What it
does not do is answer the question a compliance review actually asks, which is
about the present tense: not "what happened" but "who holds this today, and on
what basis".

The interesting rows are the ones with no basis at all. An account that predates
SSO, or that someone ticked ``is_staff`` on in the admin, holds exactly the same
access as one a group claim granted this morning, and only one of them leaves a
record. Those are what an auditor is looking for and they are invisible in a
list of events.

Two things this refuses to conflate, because they look identical from a query
and mean entirely different things:

- **granted outside SSO** -- no grant record, and the chain has never been
  purged, so there is nothing to find and never was
- **granted before the retained window** -- no grant record, but the chain has
  been purged, so the record may have existed and been removed on schedule

Reporting the first when the second is true accuses somebody of ticking a box
by hand on the strength of a retention policy doing its job.

A third case exists and cannot be attached to a person, by design: a grant
whose actor row was deleted for erasure. The events survive, the link does not,
and from a user's side there is nothing to find -- which is erasure working.
:func:`unattributable_grants` counts them separately, because "there are grants
here we can no longer attribute" is itself an answer an auditor wants.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from bastion.audit.events import Event


class Basis(enum.Enum):
    """How this account came to hold the privilege."""

    #: A group claim granted it, and the chain says when.
    GRANTED_BY_SSO = "granted_by_sso"
    #: No record, and none was ever purged. Somebody set the flag directly.
    OUTSIDE_SSO = "outside_sso"
    #: No record, but the chain has been purged, so one may have existed.
    BEFORE_THE_WINDOW = "before_the_window"


@dataclass(frozen=True, slots=True)
class Holder:
    username: str
    email: str
    is_staff: bool
    is_superuser: bool
    is_active: bool
    basis: Basis
    #: When the privilege was granted, where the chain still says so.
    granted_at: Any | None = None
    #: The connection that granted it, where known.
    connection: str = ""
    #: Federated identities, as "issuer subject" strings. Empty means the
    #: account has never signed in through a provider.
    identities: tuple[str, ...] = ()
    break_glass: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def predates_sso(self) -> bool:
        """No federated identity at all. Not the same as no grant record.

        An account can hold a flag granted by SSO and later have its identity
        unlinked, and an account with an identity can still have had the flag
        ticked by hand.
        """
        return not self.identities


def holders() -> list[Holder]:
    """Every account that can reach the admin, and the basis for it."""
    from django.contrib.auth import get_user_model
    from django.db.models import Q

    from bastion.audit.models import AuditActor, AuditChain, AuditEvent
    from bastion.breakglass.service import is_break_glass

    user_model = get_user_model()
    privileged = user_model._default_manager.filter(
        Q(is_staff=True) | Q(is_superuser=True)
    ).distinct()

    purged = AuditChain.objects.filter(purged_through_seq__gt=0).exists()

    found: list[Holder] = []
    for user in privileged.prefetch_related("federated_identities").iterator(chunk_size=2000):
        pseudonym = AuditActor.objects.filter(user=user).values_list("pseudonym", flat=True).first()
        grant = _last_grant(AuditEvent, pseudonym) if pseudonym else None

        basis, notes = _basis(grant=grant, pseudonym=pseudonym, purged=purged)

        found.append(
            Holder(
                username=_username(user),
                email=str(getattr(user, "email", "") or ""),
                is_staff=bool(getattr(user, "is_staff", False)),
                is_superuser=bool(getattr(user, "is_superuser", False)),
                is_active=bool(getattr(user, "is_active", True)),
                basis=basis,
                granted_at=grant.occurred_at if grant else None,
                connection=grant.connection if grant else "",
                identities=_identities(user),
                break_glass=is_break_glass(user),
                notes=notes,
            )
        )

    # Superusers first, then accounts with no basis on the chain, because those
    # two together are what a review is looking for.
    order = {
        Basis.OUTSIDE_SSO: 0,
        Basis.BEFORE_THE_WINDOW: 1,
        Basis.GRANTED_BY_SSO: 2,
    }
    return sorted(found, key=lambda h: (not h.is_superuser, order[h.basis], h.username))


def unattributable_grants() -> int:
    """Privileged grants on the chain whose actor no longer resolves.

    Erasure deletes the row linking a pseudonym to a person, leaving the events
    behind and unattributable on purpose. Counting them is not an attempt to
    undo that -- it is the difference between a report that has accounted for
    every grant and one that has quietly skipped some.
    """
    from bastion.audit.models import AuditActor, AuditEvent

    known = set(AuditActor.objects.values_list("pseudonym", flat=True))
    orphaned = (
        AuditEvent.objects.filter(event_type=Event.ROLE_GRANTED.value)
        .exclude(actor_pseudonym="")
        .values_list("actor_pseudonym", flat=True)
        .distinct()
    )
    return sum(1 for pseudonym in orphaned if pseudonym not in known)


def _username(user: Any) -> str:
    """The account's own name for itself, falling back to its primary key."""
    field_name = getattr(user, "USERNAME_FIELD", None)
    value = getattr(user, field_name, None) if field_name else None
    return str(value or user.pk)


def _identities(user: Any) -> tuple[str, ...]:
    """Reverse accessor by name.

    Without the django-stubs plugin the user model is only ``AbstractBaseUser``,
    which has no ``federated_identities``, and pyright runs without the plugin
    deliberately -- to prove this works for someone who is not using it.
    """
    related = getattr(user, "federated_identities", None)
    if related is None:
        return ()
    return tuple(f"{i.issuer} {i.subject}" for i in related.all())


def _last_grant(audit_event: Any, pseudonym: str) -> Any | None:
    """The most recent event that set a privilege flag to true for this actor.

    Filtered in Python rather than in the query: ``changes`` is JSON and its
    shape is ``{"is_staff": {"from": ..., "to": ...}}``, which no portable
    lookup reaches across the four databases this package supports.
    """
    candidates = audit_event.objects.filter(
        actor_pseudonym=pseudonym, event_type=Event.ROLE_GRANTED.value
    ).order_by("-occurred_at")[:50]

    for event in candidates:
        changes = event.changes or {}
        if any(
            isinstance(change, dict) and change.get("to")
            for field_name, change in changes.items()
            if field_name in ("is_staff", "is_superuser")
        ):
            return event
    return None


def _basis(
    *, grant: Any | None, pseudonym: str | None, purged: bool
) -> tuple[Basis, tuple[str, ...]]:
    if grant is not None:
        return Basis.GRANTED_BY_SSO, ()

    if purged:
        # The record may have existed and been removed on schedule. Calling
        # this "set by hand" would accuse somebody on the strength of the
        # retention policy working.
        return Basis.BEFORE_THE_WINDOW, (
            "the chain has been purged, so a grant record may have been removed",
        )

    if pseudonym is None:
        return Basis.OUTSIDE_SSO, ("no audit actor: nothing has ever acted as this account",)
    return Basis.OUTSIDE_SSO, ("the flag was set directly, not by a group claim",)
