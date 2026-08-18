"""The authentication backend.

Two things about the signature are load-bearing.

``authenticate`` takes no ``**kwargs``. Django decides whether a backend can
handle a credential set by calling ``inspect.getcallargs`` and skipping the
backend on ``TypeError``. Without the catch-all, a call carrying a username and
password raises there and Django moves on, so this backend is structurally
unreachable from a password form. A backend that accepts ``**kwargs`` is
reachable by any credential set, which is how the wrong backend ends up
answering.

``get_user`` calls ``user_can_authenticate``. That single line is the entire
reason deactivating a user ends their sessions: ``get_user`` runs on every
request, and a backend omitting it leaves every deprovisioned session live
indefinitely. It is easy to miss, and easy to drop in a subclass, so
``tests/test_backend.py`` asserts the behaviour rather than the line.

This paragraph used to say a ``bastion.W025`` startup check warned about
backends that omit it. There is no such check and there was never going to be
one: whether an override honours the method is a property of what it does at
request time, and a check that guessed from the source would be confidently
wrong in both directions. The sentence is corrected rather than deleted because
a docstring promising a guard that does not exist is the same defect as the
missing ``ALLOWED_NETWORKS`` warning, and worth naming once.
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import AbstractBaseUser
from django.db import IntegrityError, transaction
from django.http import HttpRequest
from django.utils import timezone

from bastion.audit import emit
from bastion.audit.events import Event, Outcome, Severity
from bastion.claims import IdentityClaims, Verified
from bastion.conf import SUBJECT_ONLY, VERIFIED_EMAIL_ONCE, get_setting
from bastion.connections import Connection
from bastion.db import retry_on_lock_contention
from bastion.exceptions import ProvisioningConflict
from bastion.models import FederatedIdentity

logger = logging.getLogger(__name__)


class SSOBackend(BaseBackend):
    """Resolves a verified identity to a Django user.

    The extension points are deliberately the same names mozilla-django-oidc
    uses. That package is the most-subclassed auth backend in the ecosystem and
    its vocabulary is already in people's heads; anyone porting an override
    should find the method where they expect it.
    """

    def authenticate(  # type: ignore[override]
        self,
        request: HttpRequest | None = None,
        *,
        sso_identity: IdentityClaims | None = None,
        sso_connection: Connection | None = None,
    ) -> AbstractBaseUser | None:
        if sso_identity is None or sso_connection is None:
            return None
        return self.resolve_or_provision(sso_identity, sso_connection)

    # django-stubs resolves the supertype's return to the *configured* user
    # model, which for most projects is auth.User. The runtime contract is
    # wider than that -- Django documents any AbstractBaseUser subclass -- and
    # a package must honour the wider one. The narrowing is the stubs being
    # more specific than Django is, so the override is deliberate.
    def get_user(self, user_id: Any) -> AbstractBaseUser | None:  # type: ignore[override]
        user_model = get_user_model()
        try:
            user = user_model._default_manager.get(pk=user_id)
        except user_model.DoesNotExist:
            return None
        # Do not remove. See the module docstring.
        return user if self.user_can_authenticate(user) else None

    def user_can_authenticate(self, user: AbstractBaseUser) -> bool:
        return getattr(user, "is_active", True)

    # ------------------------------------------------------------- resolution --

    @retry_on_lock_contention()
    @transaction.atomic
    def resolve_or_provision(
        self, claims: IdentityClaims, connection: Connection
    ) -> AbstractBaseUser | None:
        """Find the federated identity or create it, with the user behind it.

        The retry is outside the atomic block and not inside it, which is the
        only place it can work: a deadlock marks the whole transaction for
        rollback, so reissuing anything nested within it fails on the first
        query. This is also the transaction that every audit write during a
        login is nested inside, so their own retry defers to this one.

        The shape here is the one InnoDB deadlocks on -- select_for_update
        against a row that may not exist, then create it -- and two people
        signing in for the first time at once is not a rare event on the
        morning a provider is switched on.
        """
        identity = (
            FederatedIdentity.objects.select_for_update()
            .filter(issuer=claims.issuer, subject=claims.subject)
            .select_related("user")
            .first()
        )

        if identity is None:
            # Resolved before the gate, not after: an existing local account
            # this identity would adopt may already be privileged, and refusing
            # to provision on the strength of a group claim that grants nothing
            # would then refuse the migrated administrator this policy exists to
            # let in. Google publishes no groups at all, which is where the two
            # settings meet most often.
            adopted = self.link_existing_user(claims, connection)

            if not self.may_provision(claims, connection, adopted=adopted):
                logger.info(
                    "Refusing to provision %s on %s: the connection requires a "
                    "privileged user and persist_refused_identities is off.",
                    claims.subject,
                    connection.identifier,
                )
                emit(
                    Event.LOGIN_DENIED,
                    outcome=Outcome.DENIED,
                    severity=Severity.NOTICE,
                    connection=connection.identifier,
                    issuer=claims.issuer,
                    subject=claims.subject,
                    reason="unprivileged; identity not persisted",
                )
                return None

            user = adopted if adopted is not None else self.create_user(claims, connection)

            FederatedIdentity.objects.create(
                # Same stubs narrowing as get_user: the foreign key is to
                # AUTH_USER_MODEL, which the plugin resolves to the concrete
                # configured model.
                user=user,  # type: ignore[misc]
                issuer=claims.issuer,
                subject=claims.subject,
                subject_source=claims.subject_source,
                connection=connection.identifier,
            )
            if adopted is None:
                emit(
                    Event.USER_PROVISIONED,
                    actor=user,
                    connection=connection.identifier,
                    issuer=claims.issuer,
                    subject=claims.subject,
                    target_type="user",
                    target_id=str(user.pk),
                )
            emit(
                Event.IDENTITY_LINKED,
                actor=user,
                connection=connection.identifier,
                issuer=claims.issuer,
                subject=claims.subject,
                target_type="user",
                target_id=str(user.pk),
                # An adoption hands control of an account that already had
                # permissions to whoever the provider says owns that address.
                # It is the one event here that an investigation starts from,
                # so it is recorded at a severity that survives a filter.
                severity=Severity.WARNING if adopted is not None else Severity.INFO,
                is_privileged=adopted is not None and _is_privileged(user),
                context={
                    "subject_source": claims.subject_source,
                    "linking_policy": VERIFIED_EMAIL_ONCE if adopted is not None else SUBJECT_ONLY,
                    "adopted_local_account": adopted is not None,
                },
            )
            if adopted is not None:
                # An adopted account keeps its username and gains everything
                # else the provider asserts, including the group flags. Skipping
                # this would leave the first sign-in of a migrated admin without
                # the privileges the connection grants until their second.
                self.update_user(user, claims, connection)
        else:
            if identity.subject_source_changed(claims.subject_source):
                emit(
                    Event.IDENTITY_SOURCE_CONFLICT,
                    outcome=Outcome.DENIED,
                    severity=Severity.CRITICAL,
                    connection=connection.identifier,
                    issuer=claims.issuer,
                    subject=claims.subject,
                    changes={
                        "subject_source": {
                            "from": identity.subject_source,
                            "to": claims.subject_source,
                        }
                    },
                )
                # Same string, different claim. Almost always a configuration
                # change rather than the same person, and silently accepting it
                # means the next person to use that value inherits an account.
                logger.warning(
                    "Identity %s arrived with subject_source %r but was linked "
                    "with %r. Refusing until this is resolved.",
                    identity.pk,
                    claims.subject_source,
                    identity.subject_source,
                )
                return None
            user = identity.user
            identity.last_seen_at = timezone.now()
            identity.connection = connection.identifier
            identity.save(update_fields=["last_seen_at", "connection"])
            self.update_user(user, claims, connection)

        if not self.user_can_authenticate(user):
            return None
        return user

    def may_provision(
        self,
        claims: IdentityClaims,
        connection: Connection,
        *,
        adopted: AbstractBaseUser | None = None,
    ) -> bool:
        """Whether an unknown identity gets rows before the gate looks at it.

        ``resolve_or_provision`` runs before the privilege gate in the callback
        view, so by default a person the connection will refuse still leaves a
        ``User`` row and a ``FederatedIdentity`` row behind. That is deliberate
        and it is useful -- the row is the audit trail, and ticking ``is_staff``
        on it is how the first administrator is onboarded -- but it also means
        anyone the provider will authenticate can append to the user table by
        attempting a login they cannot complete.

        With ``persist_refused_identities`` off, the refusal happens here
        instead, before anything is written. The decision has to be taken from
        the claims alone, because the flags that the gate reads do not exist
        until the row does: an identity may provision when the group claim
        would grant it staff or superuser through this connection.

        ``adopted`` is the local account the linking policy matched, if any. It
        is already privileged or it is not, and that is a better answer than the
        claims can give: nothing has to be granted from a group for a migrated
        administrator to pass.

        The corollary is worth stating plainly. A connection with no
        ``staff_groups`` or ``superuser_groups`` and no linking policy grants
        nothing from claims, so turning this off there refuses *everyone* on
        their first sign-in and leaves no row to grant access on.
        ``bastion_doctor`` says so rather than letting it be discovered during
        an onboarding.
        """
        if not connection.require_privileged_user or connection.persist_refused_identities:
            return True
        if adopted is not None and _is_privileged(adopted):
            return True
        if not claims.may_escalate_privileges():
            # Truncated group list. Refusing to escalate on it is settled
            # policy; provisioning on it would be escalating by another route.
            return False
        return any(connection.flags_for(claims.groups).values())

    def link_existing_user(
        self, claims: IdentityClaims, connection: Connection
    ) -> AbstractBaseUser | None:
        """Adopt a local account for this identity, or return ``None``.

        ``None`` under the default policy, always. Matching an incoming
        assertion to a local account by email is django-allauth CVE-2025-65431,
        and the reason ``IDENTITY["KEY"]`` is ``(issuer, subject)``.

        The gap that leaves is real, though, and every project with existing
        administrators lives in it: without linking, each of them gets a second
        account on their first SSO sign-in and their permissions, groups and
        history are stranded on the first. ``LINKING_POLICY =
        "verified_email_once"`` closes it under conditions that are all
        necessary, in the order they are cheapest to check:

        1. The provider says the address is verified. ``Verified.UNKNOWN`` is
           not enough here, unlike ``REQUIRE_VERIFIED_EMAIL``: that setting
           refuses a login the provider called a lie, while this one hands over
           an existing account, and "the provider did not say" cannot carry
           that.
        2. The domain is one of ``IDENTITY["LINKABLE_EMAIL_DOMAINS"]``. Without
           the pin, anyone who can prove an address at any domain the provider
           will federate can claim a local account holding that address.
        3. Exactly one local account holds the address. ``User.email`` has no
           unique constraint, and picking one of two is picking at random.
        4. That account has no federated identity yet. Linking is once, and
           after it the account is pinned to the subject like any other.
        5. That account is not a break-glass account. The emergency route
           exists for the morning the provider is wrong or unavailable, and an
           account the provider can claim through is not that.

        Every outcome is audited, including a refusal to link, because "linking
        is on and did nothing" is otherwise indistinguishable from "linking is
        off" from the outside.

        Two things this deliberately does not do.

        It does not skip an inactive local account. Adopting one means the login
        is then refused by ``user_can_authenticate``, which is the point:
        somebody switched that account off, and handing the same person a fresh
        active account instead would be a way around the decision.

        It does not lock the candidate row. Two first sign-ins by *different*
        subjects carrying the same verified address, at the same instant, can
        both adopt it and leave the account with two identities. The lock that
        would close that cannot be taken here -- ``select_for_update`` against
        the nullable side of the outer join this filter needs is refused by
        PostgreSQL -- and the outcome is two identities for one verified address
        at a domain the deployment controls, which is not a boundary being
        crossed. The constraint that matters, one account per ``(issuer,
        subject)``, is held by the database.
        """
        if get_setting("IDENTITY").get("LINKING_POLICY", SUBJECT_ONLY) != VERIFIED_EMAIL_ONCE:
            return None
        if not claims.email or claims.email_verified is not Verified.YES:
            return None
        if not _has_field("email"):
            return None

        domains = {str(d).lower().lstrip("@") for d in _linkable_domains()}
        _, _, domain = claims.email.rpartition("@")
        if not domain or domain.lower() not in domains:
            return None

        user_model = get_user_model()
        candidates = list(
            user_model._default_manager.filter(
                email__iexact=claims.email, federated_identities__isnull=True
            )[:2]
        )
        if len(candidates) != 1:
            if candidates:
                self._refuse_link(claims, connection, "more than one local account holds it")
            return None

        user = candidates[0]
        from bastion.breakglass.service import is_break_glass

        if is_break_glass(user):
            self._refuse_link(claims, connection, "the local account is a break-glass account")
            return None
        return user

    def _refuse_link(self, claims: IdentityClaims, connection: Connection, reason: str) -> None:
        logger.warning(
            "Not linking %s on %s to a local account: %s",
            claims.subject,
            connection.identifier,
            reason,
        )
        emit(
            Event.IDENTITY_LINKED,
            outcome=Outcome.DENIED,
            severity=Severity.WARNING,
            connection=connection.identifier,
            issuer=claims.issuer,
            subject=claims.subject,
            reason=reason,
            context={"linking_policy": VERIFIED_EMAIL_ONCE},
        )

    def create_user(self, claims: IdentityClaims, connection: Connection) -> AbstractBaseUser:
        user_model = get_user_model()
        attributes = self.user_attributes(claims, connection)
        user = user_model(**attributes)
        # Never a usable password. An account that can be reached with one is
        # an account that bypasses the identity provider.
        user.set_unusable_password()
        self.apply_flags(user, claims, connection)

        username = attributes.get(user_username_field())
        try:
            # Nested so the collision rolls back only the insert, leaving the
            # caller's transaction usable enough to record why it failed.
            with transaction.atomic():
                user.save()
        except IntegrityError as exc:
            raise ProvisioningConflict(
                f"cannot provision {username!r}: an account with that name already "
                "exists and is not linked to this identity. This package will not "
                "adopt a local account on the strength of a name the provider "
                "supplied. Rename one of them, link them by hand, or -- if the two "
                'are the same person -- set IDENTITY["LINKING_POLICY"] to '
                '"verified_email_once" with LINKABLE_EMAIL_DOMAINS pinned, which '
                "adopts on a verified address from a domain you control rather than "
                "on a name."
            ) from exc
        return user

    def update_user(
        self, user: AbstractBaseUser, claims: IdentityClaims, connection: Connection
    ) -> AbstractBaseUser:
        touched: set[str] = set()

        for field, value in self.user_attributes(claims, connection).items():
            if field == user_username_field() or value in (None, ""):
                continue
            if getattr(user, field, None) != value:
                setattr(user, field, value)
                touched.add(field)

        touched |= self.apply_flags(user, claims, connection)

        if touched:
            # update_fields, because this runs on every single login.
            user.save(update_fields=sorted(touched))
        return user

    def user_attributes(self, claims: IdentityClaims, connection: Connection) -> dict[str, Any]:
        """Map claims onto user model fields.

        The username is derived from the subject rather than from the email or
        a hash of it. mozilla-django-oidc hashes the email, which produces an
        identifier that is opaque to administrators and changes when the
        address does.
        """
        attributes: dict[str, Any] = {user_username_field(): claims.subject[:150]}
        if claims.email:
            attributes["email"] = claims.email
        if claims.display_name:
            first, _, last = claims.display_name.partition(" ")
            attributes["first_name"] = first[:150]
            attributes["last_name"] = last[:150]
        return {k: v for k, v in attributes.items() if _has_field(k)}

    def apply_flags(
        self, user: AbstractBaseUser, claims: IdentityClaims, connection: Connection
    ) -> set[str]:
        """Apply staff and superuser flags from group membership.

        Refuses to escalate on an incomplete group list. Entra above its
        overage threshold sends a pointer to Microsoft Graph rather than the
        groups; treating that as "member of nothing" would strip permissions,
        and treating it as grounds to grant would be worse.
        """
        if not connection.grants_privileges:
            return set()

        if not claims.may_escalate_privileges():
            logger.warning(
                "Group list for %s is incomplete (%s); not applying privilege flags.",
                claims.subject,
                claims.group_value_format.value,
            )
            emit(
                Event.MAPPING_INCOMPLETE,
                outcome=Outcome.DENIED,
                severity=Severity.WARNING,
                connection=connection.identifier,
                issuer=claims.issuer,
                subject=claims.subject,
                context={"group_format": claims.group_value_format.value},
            )
            return set()

        touched: set[str] = set()
        changes: dict[str, dict[str, Any]] = {}
        for field, value in connection.flags_for(claims.groups).items():
            current = getattr(user, field, None)
            if current != value:
                setattr(user, field, value)
                touched.add(field)
                changes[field] = {"from": current, "to": value}

        if changes:
            emit(
                Event.ROLE_GRANTED
                if any(c["to"] for c in changes.values())
                else Event.ROLE_REVOKED,
                actor=user if user.pk else None,
                connection=connection.identifier,
                issuer=claims.issuer,
                subject=claims.subject,
                changes=changes,
                is_privileged=True,
                severity=Severity.NOTICE,
            )
        return touched


def user_username_field() -> str:
    """The field the configured user model logs in with.

    The one place that reads USERNAME_FIELD. Django declares it on
    AbstractUser rather than AbstractBaseUser, because each user model is
    required to define it instead of inheriting one -- so every valid
    AUTH_USER_MODEL has it and no static type can say so. mypy's plugin
    resolves the concrete model; checkers without the plugin see the stub, and
    suppressing that once here beats suppressing it at every call site.
    """
    return get_user_model().USERNAME_FIELD  # pyright: ignore[reportAttributeAccessIssue]


def _has_field(name: str) -> bool:
    return name in {f.name for f in get_user_model()._meta.get_fields()}


def _is_privileged(user: AbstractBaseUser) -> bool:
    return bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))


def _linkable_domains() -> list[str]:
    domains: list[str] = list(get_setting("IDENTITY").get("LINKABLE_EMAIL_DOMAINS", []) or [])
    return domains
