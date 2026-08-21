"""What ``verified_email_once`` would adopt, before anyone signs in.

Adoption is the step an administrator is most nervous about, and it happens
invisibly at somebody's first sign-in. "Turn it on and hope it attaches to the
right account" is not a thing to ask of a person who is about to hand a
federated identity the keys to an existing administrator.

So this walks the local user table and says, per account, what would happen.

One thing it cannot know, and says so rather than implying otherwise: whether
the provider will mark that address **verified**. That arrives in the
assertion, at sign-in, and `Verified.UNKNOWN` is not enough for adoption --
Entra emits no ``email_verified`` at all, so an Entra deployment adopts
nothing however good this report looks. Every eligible row here is therefore
conditional, and the report says on what.

The rules are not restated here. They are imported from the backend that
applies them, because a preview that drifts from the real path is worse than no
preview: it would be reassuring at exactly the moment it was wrong.
"""

from __future__ import annotations

import enum
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from bastion.conf import SUBJECT_ONLY, VERIFIED_EMAIL_ONCE, get_setting


class Outcome(enum.Enum):
    """What the first sign-in on this address would do."""

    #: Would be adopted, if the provider marks the address verified.
    ELIGIBLE = "eligible"
    #: More than one local account holds the address, so none is adopted.
    AMBIGUOUS = "ambiguous"
    #: Ruled out for a reason that will not change at sign-in.
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class Candidate:
    outcome: Outcome
    email: str
    username: str
    privileged: bool
    reason: str


def preview() -> list[Candidate]:
    """Every local account, and what adoption would do with it.

    Sorted so the rows that matter are first: eligible administrators, then
    eligible ordinary accounts, then the ones that would not be adopted.
    """
    from django.contrib.auth import get_user_model

    from bastion.backends import _has_field, _is_privileged, _linkable_domains
    from bastion.breakglass.service import is_break_glass

    identity = get_setting("IDENTITY")
    if identity.get("LINKING_POLICY", SUBJECT_ONLY) != VERIFIED_EMAIL_ONCE:
        return []
    if not _has_field("email"):
        return []

    domains = {str(d).lower().lstrip("@") for d in _linkable_domains()}
    user_model = get_user_model()

    # How many *adoptable* accounts share each address, lower-cased.
    #
    # Counting every holder would be wrong, and wrong in the direction that
    # matters: the adoption query is
    # `filter(email__iexact=..., federated_identities__isnull=True)[:2]`, so an
    # address held by one linked account and one unlinked one has exactly one
    # candidate and is adopted. Counting both would report that as ambiguous
    # and tell an administrator nothing would happen, right before it did.
    holders: dict[str, int] = {}
    unlinked = user_model._default_manager.exclude(email="").filter(
        federated_identities__isnull=True
    )
    for user in unlinked.only("email").iterator():
        # getattr, because the user model is only AbstractBaseUser to a checker
        # without the django-stubs plugin, and `email` is not on it. The rest
        # of this package reads user attributes the same way.
        address = str(getattr(user, "email", "") or "").lower()
        holders[address] = holders.get(address, 0) + 1

    found: list[Candidate] = []
    for user in _accounts(user_model):
        found.append(
            _judge(
                user,
                domains=domains,
                holders=holders,
                is_break_glass=is_break_glass,
                privileged=_is_privileged(user),
            )
        )

    order = {Outcome.ELIGIBLE: 0, Outcome.AMBIGUOUS: 1, Outcome.SKIPPED: 2}
    return sorted(found, key=lambda c: (order[c.outcome], not c.privileged, c.email, c.username))


#: Rows per batch when walking the user table. Django requires an explicit
#: size once ``prefetch_related`` is involved, and refuses to guess.
CHUNK = 2000


def _accounts(user_model: Any) -> Iterator[Any]:
    """Every local account, with its identities loaded.

    ``prefetch_related`` because the alternative is a query per row, and this
    runs against the whole user table -- which on the deployments that need
    this report is exactly the table that is large.
    """
    yield from user_model._default_manager.prefetch_related("federated_identities").iterator(
        chunk_size=CHUNK
    )


def _judge(
    user: Any,
    *,
    domains: set[str],
    holders: dict[str, int],
    is_break_glass: Any,
    privileged: bool,
) -> Candidate:
    """One account, against the same five conditions the backend applies."""
    email = (getattr(user, "email", "") or "").strip()
    username = str(getattr(user, user.USERNAME_FIELD, "") or user.pk)

    def verdict(outcome: Outcome, reason: str) -> Candidate:
        return Candidate(
            outcome=outcome,
            email=email,
            username=username,
            privileged=privileged,
            reason=reason,
        )

    if not email:
        return verdict(Outcome.SKIPPED, "no email address")

    _, _, domain = email.rpartition("@")
    if not domain or domain.lower() not in domains:
        return verdict(
            Outcome.SKIPPED, f"{domain or 'the address'} is not in LINKABLE_EMAIL_DOMAINS"
        )

    # Adoption filters on federated_identities__isnull=True, so an account that
    # already has one is not a candidate however well the address matches.
    if user.federated_identities.all():
        return verdict(Outcome.SKIPPED, "already linked to a federated identity")

    if is_break_glass(user):
        return verdict(Outcome.SKIPPED, "break-glass accounts are never adopted")

    if holders.get(email.lower(), 0) > 1:
        return verdict(
            Outcome.AMBIGUOUS,
            "another local account holds this address, so neither is adopted",
        )

    return verdict(Outcome.ELIGIBLE, "if the provider marks this address verified")
