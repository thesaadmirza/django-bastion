"""Provider metadata discovery and validation."""

from __future__ import annotations

from typing import Any

import pytest

from bastion.exceptions import DiscoveryError, InsecureEndpoint
from bastion.protocols.oidc.discovery import (
    DiscoveryCache,
    discovery_url,
    validate_metadata,
)
from tests.idp.provider import FakeIdP
from tests.idp.transport import FakeTransport

ISSUER = "https://idp.example.test"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def transport(idp: FakeIdP) -> FakeTransport:
    return FakeTransport(idp=idp)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def cache(transport: FakeTransport, clock: Clock) -> DiscoveryCache:
    return DiscoveryCache(issuer=ISSUER, transport=transport, clock=clock)


def document(idp: FakeIdP, **overrides: Any) -> dict[str, Any]:
    doc = dict(idp.discovery_document())
    doc.update(overrides)
    return doc


class TestDiscoveryUrl:
    def test_appends_the_well_known_path(self) -> None:
        assert discovery_url(ISSUER) == f"{ISSUER}/.well-known/openid-configuration"

    def test_a_trailing_slash_does_not_double_up(self) -> None:
        assert discovery_url(ISSUER + "/") == f"{ISSUER}/.well-known/openid-configuration"


class TestIssuerBinding:
    def test_matching_issuer_passes(self, idp: FakeIdP) -> None:
        assert validate_metadata(document(idp), expected_issuer=ISSUER).issuer == ISSUER

    def test_declared_issuer_must_match_exactly(self, idp: FakeIdP) -> None:
        """OIDC Discovery 4.3, and the reason this module exists.

        Without it, whoever controls what we fetch also controls the value
        every later iss check compares against.
        """
        doc = document(idp, issuer="https://attacker.test")
        with pytest.raises(DiscoveryError, match="does not match"):
            validate_metadata(doc, expected_issuer=ISSUER)

    def test_a_trailing_slash_is_a_mismatch(self, idp: FakeIdP) -> None:
        doc = document(idp, issuer=ISSUER + "/")
        with pytest.raises(DiscoveryError):
            validate_metadata(doc, expected_issuer=ISSUER)


class TestRequiredFields:
    @pytest.mark.parametrize(
        "missing", ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"]
    )
    def test_missing_required_field_is_rejected(self, idp: FakeIdP, missing: str) -> None:
        doc = document(idp)
        del doc[missing]
        with pytest.raises(DiscoveryError, match=missing):
            validate_metadata(doc, expected_issuer=ISSUER)

    def test_empty_required_field_is_rejected(self, idp: FakeIdP) -> None:
        with pytest.raises(DiscoveryError):
            validate_metadata(document(idp, token_endpoint=""), expected_issuer=ISSUER)


class TestEndpointSchemes:
    @pytest.mark.parametrize(
        "field",
        ["authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"],
    )
    def test_a_non_https_endpoint_is_rejected(self, idp: FakeIdP, field: str) -> None:
        doc = document(idp, **{field: "http://idp.example.test/x"})
        with pytest.raises(InsecureEndpoint):
            validate_metadata(doc, expected_issuer=ISSUER)

    def test_an_absent_optional_endpoint_is_fine(self, idp: FakeIdP) -> None:
        doc = document(idp)
        doc.pop("userinfo_endpoint")
        assert validate_metadata(doc, expected_issuer=ISSUER)


class TestPkceRequirement:
    def test_s256_is_required_by_default(self, idp: FakeIdP) -> None:
        doc = document(idp, code_challenge_methods_supported=["plain"])
        with pytest.raises(DiscoveryError, match="S256"):
            validate_metadata(doc, expected_issuer=ISSUER)

    def test_an_absent_field_is_also_a_refusal(self, idp: FakeIdP) -> None:
        doc = document(idp)
        doc.pop("code_challenge_methods_supported")
        with pytest.raises(DiscoveryError, match="S256"):
            validate_metadata(doc, expected_issuer=ISSUER)

    def test_the_requirement_can_be_waived_per_connection(self, idp: FakeIdP) -> None:
        """Some providers support S256 without advertising it. The escape
        hatch exists; the docs ask you to record why you used it."""
        doc = document(idp)
        doc.pop("code_challenge_methods_supported")
        assert validate_metadata(doc, expected_issuer=ISSUER, require_s256=False)


class TestResponseTypes:
    def test_a_provider_without_the_code_flow_is_rejected(self, idp: FakeIdP) -> None:
        doc = document(idp, response_types_supported=["id_token"])
        with pytest.raises(DiscoveryError, match="authorization code"):
            validate_metadata(doc, expected_issuer=ISSUER)


class TestLogoutCapability:
    def test_an_end_session_endpoint_is_reported(self, idp: FakeIdP) -> None:
        metadata = validate_metadata(document(idp), expected_issuer=ISSUER)
        assert metadata.supports_rp_initiated_logout is True

    def test_google_is_reported_as_incapable(self, google_idp: FakeIdP) -> None:
        """Google publishes no end_session_endpoint, so RP-initiated logout is
        impossible. Better surfaced here than discovered at logout time."""
        metadata = validate_metadata(
            google_idp.discovery_document(), expected_issuer=google_idp.issuer
        )
        assert metadata.supports_rp_initiated_logout is False


class TestCache:
    def test_first_get_fetches(self, cache: DiscoveryCache, transport: FakeTransport) -> None:
        cache.get()
        assert len(transport.gets) == 1

    def test_second_get_is_cached(self, cache: DiscoveryCache, transport: FakeTransport) -> None:
        cache.get()
        cache.get()
        assert len(transport.gets) == 1

    def test_the_cache_expires(
        self, cache: DiscoveryCache, transport: FakeTransport, clock: Clock
    ) -> None:
        cache.get()
        clock.advance(3601)
        cache.get()
        assert len(transport.gets) == 2

    def test_a_forced_refetch_is_throttled(
        self, cache: DiscoveryCache, transport: FakeTransport
    ) -> None:
        """A repeatable failure that triggers a refetch must not become a
        stampede against the provider."""
        cache.get()
        for _ in range(20):
            cache.get(force=True)
        assert len(transport.gets) == 1

    def test_a_forced_refetch_works_after_the_interval(
        self, cache: DiscoveryCache, transport: FakeTransport, clock: Clock
    ) -> None:
        cache.get()
        clock.advance(61)
        cache.get(force=True)
        assert len(transport.gets) == 2

    def test_a_non_https_issuer_is_refused_at_construction(self) -> None:
        with pytest.raises(InsecureEndpoint):
            DiscoveryCache(issuer="http://idp.example.test")

    def test_a_bad_document_propagates(
        self, transport: FakeTransport, idp: FakeIdP, clock: Clock
    ) -> None:
        transport.discovery_override = document(idp, issuer="https://attacker.test")
        cache = DiscoveryCache(issuer=ISSUER, transport=transport, clock=clock)
        with pytest.raises(DiscoveryError):
            cache.get()
