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
from bastion.testing.provider import FakeIdP
from bastion.testing.transport import FakeTransport

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

    def test_a_templated_issuer_says_what_is_wrong(self, entra_idp: FakeIdP) -> None:
        """The literal string Microsoft serves at /common and /organizations.

        A bare mismatch reads like a typo in the URL, and the remedy is the
        opposite of fixing one: the endpoint has to be abandoned for a
        tenant-specific issuer. Nothing here knows it is Entra -- the braces
        are what identify a template.
        """
        doc = document(entra_idp, issuer="https://login.microsoftonline.com/{tenantid}/v2.0")
        with pytest.raises(DiscoveryError, match="template, not an issuer"):
            validate_metadata(
                doc, expected_issuer="https://login.microsoftonline.com/organizations/v2.0"
            )

    def test_an_ordinary_mismatch_does_not_mention_templates(self, idp: FakeIdP) -> None:
        doc = document(idp, issuer="https://attacker.test")
        with pytest.raises(DiscoveryError, match="does not match") as caught:
            validate_metadata(doc, expected_issuer=ISSUER)
        assert "template" not in str(caught.value)


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
    """Silence and refusal are different facts about a provider.

    RFC 8414 makes ``code_challenge_methods_supported`` optional, so an absent
    field carries no information. A present field that omits S256 does: the
    provider is stating what it accepts, and S256 is all this package sends.
    """

    def test_a_method_set_without_s256_is_refused(self, idp: FakeIdP) -> None:
        doc = document(idp, code_challenge_methods_supported=["plain"])
        with pytest.raises(DiscoveryError, match="S256"):
            validate_metadata(doc, expected_issuer=ISSUER)

    def test_an_absent_field_is_not_a_refusal(self, idp: FakeIdP) -> None:
        """This is the shape Microsoft actually publishes.

        Entra's v2.0 document omits the field entirely and accepts S256 without
        complaint. Reading that as a refusal failed every Entra deployment at
        startup, and the advice it printed -- require_s256=False -- is the wrong
        switch for a metadata gap: it also silences a provider that genuinely
        refuses S256.
        """
        doc = document(idp)
        doc.pop("code_challenge_methods_supported")
        metadata = validate_metadata(doc, expected_issuer=ISSUER)
        assert metadata.code_challenge_methods_supported == ()

    def test_the_refusal_can_still_be_waived_per_connection(self, idp: FakeIdP) -> None:
        """For a provider whose metadata understates what it accepts. The docs
        ask you to record why you used it."""
        doc = document(idp, code_challenge_methods_supported=["plain"])
        assert validate_metadata(doc, expected_issuer=ISSUER, require_s256=False)

    def test_the_error_names_what_the_provider_offered(self, idp: FakeIdP) -> None:
        doc = document(idp, code_challenge_methods_supported=["plain"])
        with pytest.raises(DiscoveryError, match="plain"):
            validate_metadata(doc, expected_issuer=ISSUER)


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
