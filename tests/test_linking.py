"""Adopting an existing local account, and refusing to create one.

Two settings meet here, and both exist because the honest answer to a real
migration problem was "you cannot, sorry".

``IDENTITY["LINKING_POLICY"]`` decides whether a local account is ever adopted.
The default never adopts, for CVE-2025-65431 reasons that are sound and stay
sound; the gap that leaves is that every project with existing administrators
gets a second account for each of them on the first sign-in, with the
permissions and history stranded on the first.

``persist_refused_identities`` decides whether a person the connection refuses
gets a row at all. The default persists, because the row is the audit trail and
the way the first administrator is granted access; turning it off closes the
door where anyone the provider will authenticate can append to the user table
by attempting a login they cannot complete.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from bastion.audit.events import Event, Outcome
from bastion.audit.models import AuditEvent
from bastion.backends import SSOBackend
from bastion.breakglass.models import BreakGlassAccount
from bastion.claims import GroupFormat, IdentityClaims, Verified
from bastion.connections import Connection
from bastion.models import FederatedIdentity
from bastion.protocols.oidc.transaction import MemoryTransactionStore

pytestmark = pytest.mark.django_db

User = get_user_model()

LINKING = {
    "IDENTITY": {
        "LINKING_POLICY": "verified_email_once",
        "LINKABLE_EMAIL_DOMAINS": ["example.test"],
    }
}


def identity(**overrides) -> IdentityClaims:
    defaults = {
        "issuer": "https://idp.example.test",
        "subject": "108423041852049",
        "subject_source": "sub",
        "email": "ada@example.test",
        "display_name": "Ada Lovelace",
        "email_verified": Verified.YES,
        "groups": (),
        "group_value_format": GroupFormat.DISPLAY_NAME,
        "groups_complete": True,
    }
    defaults.update(overrides)
    return IdentityClaims(**defaults)


@pytest.fixture
def connection() -> Connection:
    return Connection(
        identifier="corp",
        issuer="https://idp.example.test",
        client_id="cid",
        transactions=MemoryTransactionStore(),
    )


@pytest.fixture
def existing() -> User:  # type: ignore[valid-type]
    """The administrator who was here before SSO was."""
    return User.objects.create_user(
        username="ada", email="ada@example.test", is_staff=True, is_superuser=True
    )


def resolve(connection: Connection, **overrides):
    return SSOBackend().resolve_or_provision(identity(**overrides), connection)


class TestTheDefaultNeverAdopts:
    def test_a_matching_address_still_gets_its_own_account(
        self, connection: Connection, existing
    ) -> None:
        """Documented behaviour, not an accident. Matching an assertion to a
        local account by address is the CVE this package was built around."""
        user = resolve(connection)
        assert user.pk != existing.pk
        assert User.objects.count() == 2

    def test_the_new_account_is_named_from_the_subject(
        self, connection: Connection, existing
    ) -> None:
        """Which for Google is a long number, and is exactly what makes the
        stranded pair obvious to whoever finds it."""
        assert resolve(connection).get_username() == "108423041852049"


class TestVerifiedEmailOnce:
    @pytest.fixture(autouse=True)
    def _policy(self, settings) -> None:
        settings.BASTION = LINKING

    def test_an_existing_account_is_adopted(self, connection: Connection, existing) -> None:
        user = resolve(connection)
        assert user.pk == existing.pk
        assert User.objects.count() == 1

    def test_the_adopted_account_keeps_its_username(self, connection: Connection, existing) -> None:
        """The point of adopting is that nothing about the account moves except
        who can sign in to it."""
        assert resolve(connection).get_username() == "ada"

    def test_the_permissions_it_already_had_survive(self, connection: Connection, existing) -> None:
        user = resolve(connection)
        assert user.is_staff and user.is_superuser

    def test_the_identity_is_pinned_to_the_subject_afterwards(
        self, connection: Connection, existing
    ) -> None:
        """Linking is once. The second sign-in is keyed on (issuer, subject)
        like any other, so an address that changes at the provider no longer
        selects anything."""
        resolve(connection)
        again = resolve(connection, email="ada.lovelace@example.test")
        assert again.pk == existing.pk
        assert FederatedIdentity.objects.count() == 1
        assert User.objects.count() == 1

    def test_group_flags_are_applied_on_the_first_sign_in(self, existing) -> None:
        """Not on the second. An adopted administrator arriving through a
        connection that grants superuser should have it immediately."""
        connection = Connection(
            identifier="corp",
            issuer="https://idp.example.test",
            client_id="cid",
            transactions=MemoryTransactionStore(),
            superuser_groups=("django-admins",),
        )
        existing.is_superuser = False
        existing.save(update_fields=["is_superuser"])

        user = SSOBackend().resolve_or_provision(identity(groups=("django-admins",)), connection)
        assert user.pk == existing.pk
        assert user.is_superuser

    def test_the_address_match_is_case_insensitive(self, connection: Connection) -> None:
        User.objects.create_user(username="ada", email="Ada@Example.Test")
        assert resolve(connection).get_username() == "ada"

    def test_an_unverified_address_is_refused(self, connection: Connection, existing) -> None:
        assert resolve(connection, email_verified=Verified.NO).pk != existing.pk

    def test_an_unknown_verification_state_is_refused(
        self, connection: Connection, existing
    ) -> None:
        """Stricter than REQUIRE_VERIFIED_EMAIL deliberately. That setting
        refuses a login the provider called a lie; this one hands over an
        account that already has permissions, and "the provider did not say"
        cannot carry that. Entra never says."""
        assert resolve(connection, email_verified=Verified.UNKNOWN).pk != existing.pk

    def test_an_unpinned_domain_is_refused(self, connection: Connection) -> None:
        """Without the pin, proving an address at any domain the provider will
        federate claims the local account that holds it."""
        outsider = User.objects.create_user(username="mal", email="mal@other.test")
        user = resolve(connection, email="mal@other.test", subject="99")
        assert user.pk != outsider.pk

    def test_two_matching_accounts_are_refused_and_recorded(
        self, connection: Connection, existing
    ) -> None:
        """User.email has no unique constraint, so picking one is picking at
        random."""
        User.objects.create_user(username="ada2", email="ada@example.test")
        user = resolve(connection)

        assert user.get_username() == "108423041852049"
        assert User.objects.count() == 3
        assert AuditEvent.objects.filter(
            event_type=Event.IDENTITY_LINKED, outcome=str(Outcome.DENIED)
        ).exists()

    def test_an_account_that_already_has_an_identity_is_refused(
        self, connection: Connection, existing
    ) -> None:
        """Linking is once, and the second provider does not get to arrive by
        address."""
        FederatedIdentity.objects.create(
            user=existing,
            issuer="https://other.idp.test",
            subject="abc",
            subject_source="sub",
            connection="other",
        )
        assert resolve(connection).pk != existing.pk

    def test_a_break_glass_account_is_never_adopted(self, connection: Connection) -> None:
        """The fire escape exists for the morning the provider is wrong or
        unreachable. An account the provider can claim through is not one."""
        firefighter = User.objects.create_user(
            username="firefighter", email="ada@example.test", is_superuser=True
        )
        BreakGlassAccount.objects.create(user=firefighter, reason="incident response")

        user = resolve(connection)
        assert user.pk != firefighter.pk
        assert AuditEvent.objects.filter(
            event_type=Event.IDENTITY_LINKED, outcome=str(Outcome.DENIED)
        ).exists()

    def test_the_adoption_is_audited_as_one(self, connection: Connection, existing) -> None:
        """An adoption is where an investigation into "how did they get this
        account" starts, so it is distinguishable from an ordinary first login
        and recorded above info severity."""
        resolve(connection)
        record = AuditEvent.objects.get(event_type=Event.IDENTITY_LINKED)
        assert record.context["adopted_local_account"] is True
        assert record.context["linking_policy"] == "verified_email_once"
        assert record.severity == "warning"
        assert record.is_privileged

    def test_provisioning_a_stranger_is_still_ordinary(self, connection: Connection) -> None:
        """Nobody local holds the address, so this is a plain first login and
        must not be recorded as an adoption."""
        resolve(connection)
        record = AuditEvent.objects.get(event_type=Event.IDENTITY_LINKED)
        assert record.context["adopted_local_account"] is False
        assert AuditEvent.objects.filter(event_type=Event.USER_PROVISIONED).exists()


class TestRefusedIdentitiesArePersistedByDefault:
    def test_a_refused_person_still_gets_a_row(self, connection: Connection) -> None:
        """Surprising, useful, and now written down. The row is the audit trail,
        and ticking is_staff on it is how the first administrator is onboarded.
        """
        connection.require_privileged_user = True
        connection.staff_groups = ("django-staff",)

        assert SSOBackend().resolve_or_provision(identity(), connection) is not None
        assert User.objects.count() == 1


class TestRefusedIdentitiesCanBeDiscarded:
    @pytest.fixture
    def strict(self, connection: Connection) -> Connection:
        connection.require_privileged_user = True
        connection.persist_refused_identities = False
        connection.staff_groups = ("django-staff",)
        return connection

    def test_nothing_is_written_for_a_refusal(self, strict: Connection) -> None:
        assert SSOBackend().resolve_or_provision(identity(), strict) is None
        assert User.objects.count() == 0
        assert FederatedIdentity.objects.count() == 0

    def test_the_refusal_is_still_audited(self, strict: Connection) -> None:
        """No row does not mean no evidence: the attempt is what an
        investigation needs, and it carries the issuer and subject."""
        SSOBackend().resolve_or_provision(identity(), strict)
        record = AuditEvent.objects.get(event_type=Event.LOGIN_DENIED)
        assert record.subject == "108423041852049"
        assert "not persisted" in record.reason

    def test_a_matching_group_provisions_normally(self, strict: Connection) -> None:
        """The decision is taken from the claims, because the flags the gate
        reads do not exist until the row does."""
        user = SSOBackend().resolve_or_provision(identity(groups=("django-staff",)), strict)
        assert user is not None
        assert user.is_staff

    def test_a_truncated_group_list_is_refused(self, strict: Connection) -> None:
        """Refusing to escalate on a truncated list is settled policy;
        provisioning on one would be escalating by another route."""
        claims = identity(groups=("django-staff",), groups_complete=False)
        assert SSOBackend().resolve_or_provision(claims, strict) is None
        assert User.objects.count() == 0

    def test_an_already_linked_person_is_unaffected(self, strict: Connection) -> None:
        """The setting governs provisioning. Somebody granted access in the
        admin after a refusal keeps signing in."""
        user = SSOBackend().resolve_or_provision(identity(groups=("django-staff",)), strict)
        user.is_staff = False
        user.save(update_fields=["is_staff"])

        assert SSOBackend().resolve_or_provision(identity(), strict) is not None

    def test_the_setting_is_ignored_without_the_gate(self, connection: Connection) -> None:
        """Nothing is refused before a session exists unless
        require_privileged_user says so, so there is nothing to discard."""
        connection.persist_refused_identities = False
        assert SSOBackend().resolve_or_provision(identity(), connection) is not None


class TestTheTwoSettingsTogether:
    """``require_privileged_user`` with linking on is the migration case.

    A connection strict enough to refuse a session to anyone unprivileged, on a
    provider that publishes no groups, adopting administrators who already have
    their permissions locally. Each setting alone is straightforward; the order
    they are evaluated in is not, and getting it wrong refuses exactly the
    people the linking policy exists to let in.
    """

    @pytest.fixture
    def strict(self, connection: Connection, settings) -> Connection:
        settings.BASTION = LINKING
        connection.require_privileged_user = True
        connection.persist_refused_identities = False
        return connection

    def test_an_adopted_administrator_is_let_in_without_any_group_claim(
        self, strict: Connection, existing
    ) -> None:
        """The local account is already staff, which is a better answer than a
        group claim that does not exist on this provider."""
        user = SSOBackend().resolve_or_provision(identity(), strict)
        assert user is not None
        assert user.pk == existing.pk

    def test_an_adopted_account_with_no_privileges_is_still_refused(
        self, strict: Connection
    ) -> None:
        """Adoption is not a grant. An ordinary local account matched by address
        gets no more than it had."""
        User.objects.create_user(username="ada", email="ada@example.test")
        assert SSOBackend().resolve_or_provision(identity(), strict) is None
        assert FederatedIdentity.objects.count() == 0

    def test_a_stranger_is_refused_without_a_row(self, strict: Connection) -> None:
        assert SSOBackend().resolve_or_provision(identity(), strict) is None
        assert User.objects.count() == 0
