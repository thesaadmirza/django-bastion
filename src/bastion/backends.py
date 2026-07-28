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
indefinitely. It is easy to miss, so ``bastion.W025`` warns about backends that
do.
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction
from django.http import HttpRequest
from django.utils import timezone

from bastion.audit import emit
from bastion.audit.events import Event, Outcome, Severity
from bastion.claims import IdentityClaims
from bastion.connections import Connection
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

    @transaction.atomic
    def resolve_or_provision(
        self, claims: IdentityClaims, connection: Connection
    ) -> AbstractBaseUser | None:
        identity = (
            FederatedIdentity.objects.select_for_update()
            .filter(issuer=claims.issuer, subject=claims.subject)
            .select_related("user")
            .first()
        )

        if identity is None:
            user = self.create_user(claims, connection)
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
                context={"subject_source": claims.subject_source},
            )
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

    def create_user(self, claims: IdentityClaims, connection: Connection) -> AbstractBaseUser:
        user_model = get_user_model()
        user = user_model(**self.user_attributes(claims, connection))
        # Never a usable password. An account that can be reached with one is
        # an account that bypasses the identity provider.
        user.set_unusable_password()
        self.apply_flags(user, claims, connection)
        user.save()
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
    return get_user_model().USERNAME_FIELD


def _has_field(name: str) -> bool:
    return name in {f.name for f in get_user_model()._meta.get_fields()}
