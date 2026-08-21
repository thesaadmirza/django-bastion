"""Shared fixtures.

Key generation is session-scoped because 2048-bit RSA costs roughly 50ms and
the corpus needs several keys. Nothing here depends on the database; the
synthetic IdP is pure computation, which is what makes the adversarial corpus
cheap enough to run on every pull request.
"""

from __future__ import annotations

import pytest

from bastion.testing import provider
from bastion.testing.keys import SigningKey, generate_key
from bastion.testing.provider import FakeIdP


@pytest.fixture(scope="session")
def signing_key() -> SigningKey:
    return generate_key()


@pytest.fixture(scope="session")
def second_key() -> SigningKey:
    """A second legitimate key, for rollover tests."""
    return generate_key()


@pytest.fixture(scope="session")
def attacker_key() -> SigningKey:
    """A key the relying party has never seen and must never trust."""
    return generate_key()


@pytest.fixture(scope="session")
def ec_key() -> SigningKey:
    return generate_key("ES256")


@pytest.fixture
def idp(signing_key: SigningKey) -> FakeIdP:
    return FakeIdP(keys=[signing_key])


@pytest.fixture
def entra_idp(signing_key: SigningKey) -> FakeIdP:
    return provider.entra(keys=[signing_key])


@pytest.fixture
def okta_idp(signing_key: SigningKey) -> FakeIdP:
    return provider.okta(keys=[signing_key])


@pytest.fixture
def google_idp(signing_key: SigningKey) -> FakeIdP:
    return provider.google(keys=[signing_key])


@pytest.fixture
def keycloak_idp(signing_key: SigningKey) -> FakeIdP:
    return provider.keycloak(keys=[signing_key])


@pytest.fixture(params=["entra", "okta", "google", "keycloak"])
def any_vendor(request: pytest.FixtureRequest, signing_key: SigningKey) -> FakeIdP:
    """Parametrised across every preset, for invariants that must hold
    regardless of provider. Parametrise the fixture rather than looping inside
    it, so a failure names the vendor that broke."""
    factory = getattr(provider, request.param)
    return factory(keys=[signing_key])
