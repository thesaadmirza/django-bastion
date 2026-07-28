"""The request path of the default transport.

Stubbing ``urlopen`` rather than opening a socket. What is under test is our
policy — status handling, the post-redirect scheme check, error-body handling,
what reaches an exception message — not whether urllib works.

This file exists because the module sat at 53% coverage, and the uncovered half
was every error path. Error paths are the ones nobody exercises by hand.
"""

from __future__ import annotations

import datetime as dt
import io
import urllib.error
from typing import Any

import pytest

from bastion.exceptions import InsecureEndpoint
from bastion.protocols.oidc.transport import TransportError, UrllibTransport


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, *, status: int = 200, url: str, headers: dict | None = None):
        super().__init__(body)
        self.status = status
        self._url = url
        self.headers = headers or {}

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def stub_urlopen(monkeypatch, result: Any) -> list[Any]:
    """Replace urlopen. Returns the list of requests it was handed."""
    seen: list[Any] = []

    def fake(request, timeout=None):
        seen.append((request, timeout))
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr("urllib.request.urlopen", fake)
    return seen


URL = "https://idp.example.test/.well-known/openid-configuration"


class TestGetJson:
    def test_a_200_is_decoded(self, monkeypatch) -> None:
        stub_urlopen(monkeypatch, FakeResponse(b'{"issuer": "x"}', url=URL))
        assert UrllibTransport().get_json(URL) == {"issuer": "x"}

    def test_the_timeout_is_passed_through(self, monkeypatch) -> None:
        """urllib has no default timeout, so a provider that accepts the
        connection and stalls would hold a worker forever."""
        seen = stub_urlopen(monkeypatch, FakeResponse(b"{}", url=URL))
        UrllibTransport(timeout=3.5).get_json(URL)
        assert seen[0][1] == 3.5

    def test_a_non_200_raises(self, monkeypatch) -> None:
        stub_urlopen(monkeypatch, FakeResponse(b"{}", status=204, url=URL))
        with pytest.raises(TransportError, match="204"):
            UrllibTransport().get_json(URL)

    def test_a_redirect_to_http_is_refused(self, monkeypatch) -> None:
        """urllib follows redirects. Checking only where we asked to go would
        let a 302 put a client secret on the wire in clear."""
        stub_urlopen(monkeypatch, FakeResponse(b"{}", url="http://idp.example.test/downgraded"))
        with pytest.raises(InsecureEndpoint, match="redirect"):
            UrllibTransport().get_json(URL)

    def test_a_redirect_to_https_is_fine(self, monkeypatch) -> None:
        stub_urlopen(monkeypatch, FakeResponse(b"{}", url="https://elsewhere.test/x"))
        assert UrllibTransport().get_json(URL) == {}

    def test_a_connection_failure_raises(self, monkeypatch) -> None:
        stub_urlopen(monkeypatch, urllib.error.URLError("refused"))
        with pytest.raises(TransportError, match="failed"):
            UrllibTransport().get_json(URL)

    def test_a_timeout_raises(self, monkeypatch) -> None:
        stub_urlopen(monkeypatch, TimeoutError())
        with pytest.raises(TransportError, match="timed out"):
            UrllibTransport().get_json(URL)

    def test_an_oversized_body_is_refused(self, monkeypatch) -> None:
        stub_urlopen(monkeypatch, FakeResponse(b"x" * 200, url=URL))
        with pytest.raises(TransportError, match="exceeded"):
            UrllibTransport(max_bytes=100).get_json(URL)

    def test_a_non_https_url_never_reaches_the_network(self, monkeypatch) -> None:
        seen = stub_urlopen(monkeypatch, FakeResponse(b"{}", url=URL))
        with pytest.raises(InsecureEndpoint):
            UrllibTransport().get_json("http://idp.example.test/x")
        assert seen == []


class TestPostForm:
    def test_a_form_body_is_encoded(self, monkeypatch) -> None:
        seen = stub_urlopen(monkeypatch, FakeResponse(b'{"id_token": "t"}', url=URL))
        status, body = UrllibTransport().post_form(
            URL, data={"grant_type": "authorization_code", "code": "c"}
        )
        assert status == 200
        assert body == {"id_token": "t"}
        assert b"grant_type=authorization_code" in seen[0][0].data

    def test_headers_are_merged(self, monkeypatch) -> None:
        seen = stub_urlopen(monkeypatch, FakeResponse(b"{}", url=URL))
        UrllibTransport().post_form(URL, data={}, headers={"Authorization": "Basic x"})
        request = seen[0][0]
        assert request.get_header("Authorization") == "Basic x"
        assert request.get_header("Content-type") == "application/x-www-form-urlencoded"

    def test_an_error_status_returns_its_body(self, monkeypatch) -> None:
        """RFC 6749 5.2 error responses carry a body worth parsing, so a 400 is
        returned rather than raised."""
        error = urllib.error.HTTPError(
            URL, 400, "Bad Request", {}, io.BytesIO(b'{"error": "invalid_grant"}')
        )
        stub_urlopen(monkeypatch, error)
        status, body = UrllibTransport().post_form(URL, data={})
        assert status == 400
        assert body == {"error": "invalid_grant"}


class TestServerTime:
    def test_a_date_header_is_parsed(self, monkeypatch) -> None:
        stub_urlopen(
            monkeypatch,
            FakeResponse(b"", url=URL, headers={"Date": "Tue, 28 Jul 2026 12:00:00 GMT"}),
        )
        when = UrllibTransport().server_time("https://idp.example.test")
        assert when == dt.datetime(2026, 7, 28, 12, 0, tzinfo=dt.UTC)

    def test_a_missing_header_returns_none(self, monkeypatch) -> None:
        stub_urlopen(monkeypatch, FakeResponse(b"", url=URL))
        assert UrllibTransport().server_time("https://idp.example.test") is None

    def test_an_unparseable_header_returns_none(self, monkeypatch) -> None:
        stub_urlopen(monkeypatch, FakeResponse(b"", url=URL, headers={"Date": "nonsense"}))
        assert UrllibTransport().server_time("https://idp.example.test") is None

    def test_a_connection_failure_returns_none(self, monkeypatch) -> None:
        """A clock check is a diagnostic. It must not turn a reachable provider
        into a failed startup."""
        stub_urlopen(monkeypatch, urllib.error.URLError("refused"))
        assert UrllibTransport().server_time("https://idp.example.test") is None
