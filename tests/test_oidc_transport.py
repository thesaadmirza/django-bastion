"""The default HTTP transport.

Only the parts that can be tested without a network are tested here. The
request path itself is exercised through the fake transport everywhere else,
which is the right split: what matters about ``UrllibTransport`` is its
policy, not that urllib works.
"""

from __future__ import annotations

import io

import pytest

from bastion.exceptions import InsecureEndpoint
from bastion.protocols.oidc.transport import (
    DEFAULT_TIMEOUT,
    MAX_RESPONSE_BYTES,
    TransportError,
    UrllibTransport,
    require_https,
)


class TestSchemeEnforcement:
    @pytest.mark.parametrize(
        "url",
        [
            "http://idp.example.test/token",
            "file:///etc/passwd",
            "ftp://idp.example.test/x",
            "gopher://idp.example.test/x",
            "//idp.example.test/x",
            "idp.example.test/x",
        ],
    )
    def test_non_https_is_refused(self, url: str) -> None:
        with pytest.raises(InsecureEndpoint):
            require_https(url)

    def test_https_passes(self) -> None:
        require_https("https://idp.example.test/token")

    def test_the_message_names_what_was_being_checked(self) -> None:
        with pytest.raises(InsecureEndpoint, match="token_endpoint"):
            require_https("http://x.test", what="token_endpoint")


class TestDefaults:
    def test_a_timeout_is_always_set(self) -> None:
        """urllib has no default timeout. A provider that accepts the
        connection and then stalls would hold a worker indefinitely, and that
        needs no attacker to happen."""
        assert UrllibTransport().timeout == DEFAULT_TIMEOUT
        assert UrllibTransport().timeout > 0

    def test_a_response_size_cap_is_always_set(self) -> None:
        assert UrllibTransport().max_bytes == MAX_RESPONSE_BYTES


class TestResponseSizeCap:
    """The cap has to be enforced, not merely configured.

    Extracted from the request path so it can be tested without a socket. A
    mutation survived here before this existed, which is the whole argument
    for running mutations rather than counting tests.
    """

    def test_a_body_within_the_cap_is_returned(self) -> None:
        transport = UrllibTransport(max_bytes=100)
        assert transport.read_capped(io.BytesIO(b"x" * 100)) == b"x" * 100

    def test_a_body_over_the_cap_is_refused(self) -> None:
        transport = UrllibTransport(max_bytes=100)
        with pytest.raises(TransportError, match="exceeded"):
            transport.read_capped(io.BytesIO(b"x" * 101))

    def test_a_vastly_oversized_body_is_refused(self) -> None:
        transport = UrllibTransport(max_bytes=1024)
        with pytest.raises(TransportError):
            transport.read_capped(io.BytesIO(b"x" * (10 * 1024 * 1024)))

    def test_only_one_byte_past_the_cap_is_ever_read(self) -> None:
        """A response too large to fit in memory must not reach memory."""
        transport = UrllibTransport(max_bytes=64)
        requested: list[int] = []

        class RecordingReader:
            def read(self, size: int) -> bytes:
                requested.append(size)
                return b"x" * size

        with pytest.raises(TransportError):
            transport.read_capped(RecordingReader())
        assert requested == [65]


class TestJsonDecoding:
    def test_valid_json_object_decodes(self) -> None:
        transport = UrllibTransport()
        assert transport._decode(b'{"a": 1}', "https://x.test") == {"a": 1}

    def test_invalid_json_is_a_transport_error(self) -> None:
        transport = UrllibTransport()
        with pytest.raises(TransportError, match="not valid JSON"):
            transport._decode(b"not json", "https://x.test")

    def test_a_json_array_is_rejected(self) -> None:
        """A discovery document or token response is an object. Accepting a
        top-level array means every later ``.get`` raises AttributeError
        somewhere less obvious."""
        transport = UrllibTransport()
        with pytest.raises(TransportError, match="not a JSON object"):
            transport._decode(b"[1, 2, 3]", "https://x.test")

    def test_invalid_utf8_is_a_transport_error(self) -> None:
        transport = UrllibTransport()
        with pytest.raises(TransportError):
            transport._decode(b"\xff\xfe not utf-8", "https://x.test")

    def test_the_error_names_the_url_but_not_the_body(self) -> None:
        transport = UrllibTransport()
        with pytest.raises(TransportError) as caught:
            transport._decode(b'{"access_token": "hunter2"', "https://x.test")
        assert "hunter2" not in str(caught.value)
        assert "x.test" in str(caught.value)
