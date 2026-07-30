"""Provisioning onto a username that is already taken.

The username is the subject, so a collision means the same person arriving
under an identity the package does not recognise. That happens for ordinary
reasons: the issuer URL changes and the identity is keyed on it, or a second
connection is added for a directory whose people already signed in through the
first. Both leave a user row whose name is the subject and no FederatedIdentity
to find it by.

Found by following the tutorial twice against providers on different ports,
where it surfaced as an unhandled IntegrityError and a 500 on the callback.

Linking by name is not the fix and must never become it: letting a
provider-supplied value select a local account is allauth CVE-2025-65431, and
avoiding that is why IDENTITY.KEY is (issuer, subject). Refusing is right.
Refusing with a traceback is not.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from bastion.backends import SSOBackend
from bastion.claims import IdentityClaims, Verified
from bastion.connections import Connection
from bastion.exceptions import ProvisioningConflict
from bastion.models import FederatedIdentity
from bastion.protocols.oidc.transaction import MemoryTransactionStore

SUBJECT = "6f3b1c28-9d4a-4f77-b2e5-0a1c8d5e7f90"


def connection_at(issuer: str) -> Connection:
    return Connection(
        identifier="corp",
        issuer=issuer,
        client_id="cid",
        transactions=MemoryTransactionStore(),
    )


def claims_from(issuer: str, subject: str = SUBJECT) -> IdentityClaims:
    return IdentityClaims(
        issuer=issuer,
        subject=subject,
        subject_source="oid",
        email="alice@example.test",
        email_verified=Verified.YES,
    )


@pytest.mark.django_db
class TestTheIssuerChanged:
    """The reproduction: sign in, move the issuer, sign in again."""

    def test_the_second_issuer_is_refused_rather_than_crashing(self) -> None:
        old, new = "https://idp.example.test", "https://login.example.test"
        SSOBackend().resolve_or_provision(claims_from(old), connection_at(old))

        with pytest.raises(ProvisioningConflict) as caught:
            SSOBackend().resolve_or_provision(claims_from(new), connection_at(new))

        assert SUBJECT in str(caught.value)
        assert "already exists" in str(caught.value)

    def test_the_original_account_survives(self) -> None:
        old, new = "https://idp.example.test", "https://login.example.test"
        first = SSOBackend().resolve_or_provision(claims_from(old), connection_at(old))

        with pytest.raises(ProvisioningConflict):
            SSOBackend().resolve_or_provision(claims_from(new), connection_at(new))

        assert get_user_model().objects.filter(username=SUBJECT).count() == 1
        assert get_user_model().objects.get(pk=first.pk).username == SUBJECT

    def test_no_half_built_identity_is_left_behind(self) -> None:
        """resolve_or_provision is atomic, so the FederatedIdentity for the new
        issuer must roll back with the user that could not be created."""
        old, new = "https://idp.example.test", "https://login.example.test"
        SSOBackend().resolve_or_provision(claims_from(old), connection_at(old))

        with pytest.raises(ProvisioningConflict):
            SSOBackend().resolve_or_provision(claims_from(new), connection_at(new))

        assert FederatedIdentity.objects.filter(issuer=new).count() == 0
        assert FederatedIdentity.objects.filter(issuer=old).count() == 1

    def test_the_original_issuer_still_signs_in(self) -> None:
        """The failed attempt must not have broken the identity that worked."""
        old, new = "https://idp.example.test", "https://login.example.test"
        first = SSOBackend().resolve_or_provision(claims_from(old), connection_at(old))

        with pytest.raises(ProvisioningConflict):
            SSOBackend().resolve_or_provision(claims_from(new), connection_at(new))

        again = SSOBackend().resolve_or_provision(claims_from(old), connection_at(old))
        assert again is not None
        assert again.pk == first.pk


@pytest.mark.django_db
class TestOrdinaryProvisioningStillWorks:
    def test_a_free_username_provisions(self) -> None:
        issuer = "https://idp.example.test"
        user = SSOBackend().resolve_or_provision(
            claims_from(issuer, "newcomer"), connection_at(issuer)
        )
        assert user is not None
        assert get_user_model().objects.filter(username="newcomer").exists()

    def test_the_same_identity_twice_is_the_same_user(self) -> None:
        issuer = "https://idp.example.test"
        first = SSOBackend().resolve_or_provision(claims_from(issuer), connection_at(issuer))
        second = SSOBackend().resolve_or_provision(claims_from(issuer), connection_at(issuer))
        assert first.pk == second.pk
