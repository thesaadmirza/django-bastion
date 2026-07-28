"""The authentication backend, in isolation.

Three properties here are not visible from the flow tests and are the ones most
likely to be broken by a well-meaning refactor.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import authenticate, get_user_model
from django.test import Client, override_settings

from bastion.backends import SSOBackend
from bastion.claims import GroupFormat, IdentityClaims, Verified
from bastion.connections import Connection
from bastion.models import FederatedIdentity
from bastion.protocols.oidc.transaction import MemoryTransactionStore

pytestmark = pytest.mark.django_db

User = get_user_model()


def identity(**overrides) -> IdentityClaims:
    defaults = {
        "issuer": "https://idp.example.test",
        "subject": "user-0001",
        "subject_source": "sub",
        "email": "person@example.test",
        "display_name": "Test Person",
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


class TestSignatureIsolation:
    def test_a_password_call_never_reaches_this_backend(self) -> None:
        """Django decides whether a backend can handle a credential set by
        calling inspect.getcallargs and skipping on TypeError. Without the
        catch-all kwargs, a username and password call raises there and Django
        moves on, so this backend is structurally unreachable from a password
        form.
        """
        assert authenticate(username="someone", password="hunter2") is None

    def test_calling_the_backend_directly_with_no_identity_returns_none(self) -> None:
        assert SSOBackend().authenticate(None) is None

    def test_an_identity_without_a_connection_returns_none(self) -> None:
        assert SSOBackend().authenticate(None, sso_identity=identity()) is None


class TestGetUser:
    def test_an_active_user_is_returned(self, connection: Connection) -> None:
        user = SSOBackend().resolve_or_provision(identity(), connection)
        assert SSOBackend().get_user(user.pk) is not None

    def test_an_inactive_user_is_not(self, connection: Connection) -> None:
        """The single line that makes deactivation end a session. get_user runs
        on every request; a backend omitting user_can_authenticate leaves every
        deprovisioned session live indefinitely."""
        user = SSOBackend().resolve_or_provision(identity(), connection)
        User.objects.filter(pk=user.pk).update(is_active=False)
        assert SSOBackend().get_user(user.pk) is None

    def test_a_missing_user_returns_none(self) -> None:
        assert SSOBackend().get_user(999_999) is None


class TestDeprovisioning:
    def test_deactivating_a_user_ends_their_session_on_the_next_request(
        self, client: Client, connection: Connection
    ) -> None:
        user = SSOBackend().resolve_or_provision(identity(), connection)
        client.force_login(user, backend="bastion.backends.SSOBackend")
        assert client.session.get("_auth_user_id")

        User.objects.filter(pk=user.pk).update(is_active=False)

        # get_user runs on every request. Resolving the session the way the
        # auth middleware does is the check, without needing a configured view.
        from django.contrib.auth import get_user as get_session_user

        request = type("R", (), {"session": client.session})()
        assert get_session_user(request).is_anonymous  # type: ignore[arg-type]


class TestSubjectSourceDrift:
    def test_a_changed_subject_source_is_refused(self, connection: Connection) -> None:
        """A deployment switching Entra from sub to oid produces the same
        person under a different identifier. Accepting it silently means the
        next login creates a duplicate and the original permissions strand."""
        SSOBackend().resolve_or_provision(identity(subject_source="sub"), connection)

        result = SSOBackend().resolve_or_provision(identity(subject_source="oid"), connection)
        assert result is None

    def test_the_same_source_is_accepted(self, connection: Connection) -> None:
        first = SSOBackend().resolve_or_provision(identity(), connection)
        second = SSOBackend().resolve_or_provision(identity(), connection)
        assert first.pk == second.pk


class TestProvisioning:
    def test_the_username_is_the_subject_not_a_hash_of_the_email(
        self, connection: Connection
    ) -> None:
        """mozilla-django-oidc hashes the email, producing an identifier that
        is opaque to administrators and changes when the address does."""
        user = SSOBackend().resolve_or_provision(identity(subject="alice"), connection)
        assert user.get_username() == "alice"

    def test_attributes_are_updated_on_a_later_login(self, connection: Connection) -> None:
        SSOBackend().resolve_or_provision(identity(), connection)
        SSOBackend().resolve_or_provision(
            identity(email="new@example.test", display_name="New Name"), connection
        )
        user = User.objects.get()
        assert user.email == "new@example.test"
        assert user.first_name == "New"

    def test_an_inactive_user_cannot_authenticate(self, connection: Connection) -> None:
        user = SSOBackend().resolve_or_provision(identity(), connection)
        User.objects.filter(pk=user.pk).update(is_active=False)
        assert SSOBackend().resolve_or_provision(identity(), connection) is None

    def test_one_identity_row_per_person(self, connection: Connection) -> None:
        SSOBackend().resolve_or_provision(identity(), connection)
        SSOBackend().resolve_or_provision(identity(), connection)
        assert FederatedIdentity.objects.count() == 1


class TestPrivilegeFlags:
    def test_incomplete_groups_block_escalation(self, connection: Connection) -> None:
        connection.staff_groups = ("django-staff",)
        user = SSOBackend().resolve_or_provision(
            identity(groups=("django-staff",), groups_complete=False), connection
        )
        assert user.is_staff is False

    def test_complete_groups_permit_escalation(self, connection: Connection) -> None:
        connection.staff_groups = ("django-staff",)
        user = SSOBackend().resolve_or_provision(identity(groups=("django-staff",)), connection)
        assert user.is_staff is True

    def test_no_configured_groups_means_no_flags_touched(self, connection: Connection) -> None:
        user = SSOBackend().resolve_or_provision(identity(groups=("anything",)), connection)
        assert user.is_staff is False
        assert user.is_superuser is False


class TestModelBackendCoexistence:
    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "bastion.backends.SSOBackend",
            "django.contrib.auth.backends.ModelBackend",
        ]
    )
    def test_a_password_call_falls_through_to_model_backend(self, connection: Connection) -> None:
        """Ordering sanity: with both installed, a password call must reach
        ModelBackend rather than being swallowed."""
        User.objects.create_user(username="local", password="correct-horse")
        assert authenticate(username="local", password="correct-horse") is not None
        assert authenticate(username="local", password="wrong") is None
