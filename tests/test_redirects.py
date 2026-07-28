"""Return-URL safety.

Django does the parsing; what is tested here is the policy. The one worth
proving is that ALLOWED_HOSTS is not the allowlist -- a host Django will serve
requests for is not thereby a host we should send a freshly-authenticated
session to.
"""

from __future__ import annotations

import pytest
from django.test import RequestFactory, override_settings

from bastion.redirects import is_safe_redirect_url, safe_redirect_url

FALLBACK = "/admin/"


@pytest.fixture
def request_factory() -> RequestFactory:
    return RequestFactory()


@pytest.fixture
def http_request(request_factory: RequestFactory):
    return request_factory.get("/sso/callback/", HTTP_HOST="app.example.test")


@pytest.fixture
def secure_request(request_factory: RequestFactory):
    return request_factory.get("/sso/callback/", HTTP_HOST="app.example.test", secure=True)


class TestSafeUrls:
    @pytest.mark.parametrize(
        "url",
        ["/admin/", "/admin/auth/user/", "/admin/auth/user/?q=x", "/a/b#frag"],
    )
    def test_relative_paths_are_allowed(self, http_request, url: str) -> None:
        assert safe_redirect_url(url, request=http_request, fallback=FALLBACK) == url

    def test_the_current_host_is_allowed(self, http_request) -> None:
        url = "http://app.example.test/admin/"
        assert safe_redirect_url(url, request=http_request, fallback=FALLBACK) == url

    def test_an_explicitly_allowed_host_is_permitted(self, http_request) -> None:
        url = "http://other.example.test/admin/"
        result = safe_redirect_url(
            url,
            request=http_request,
            extra_allowed_hosts={"other.example.test"},
            fallback=FALLBACK,
        )
        assert result == url


class TestHostileUrls:
    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.test/",
            "//evil.test/",
            "///evil.test/",
            "http:///evil.test",
            "\\\\evil.test",
            "/\\evil.test",
            "javascript:alert(1)",
            "\x01https://evil.test",
        ],
        ids=[
            "absolute",
            "protocol-relative",
            "triple-slash",
            "empty-netloc",
            "backslashes",
            "slash-backslash",
            "javascript",
            "control-char",
        ],
    )
    def test_hostile_urls_fall_back(self, http_request, url: str) -> None:
        assert safe_redirect_url(url, request=http_request, fallback=FALLBACK) == FALLBACK

    def test_none_falls_back(self, http_request) -> None:
        assert safe_redirect_url(None, request=http_request, fallback=FALLBACK) == FALLBACK

    def test_empty_string_falls_back(self, http_request) -> None:
        assert safe_redirect_url("", request=http_request, fallback=FALLBACK) == FALLBACK

    def test_over_length_urls_fall_back(self, http_request) -> None:
        """Django caps at 2048 characters."""
        url = "/" + "a" * 3000
        assert safe_redirect_url(url, request=http_request, fallback=FALLBACK) == FALLBACK


class TestAllowedHostsIsNotTheAllowlist:
    @override_settings(ALLOWED_HOSTS=["app.example.test", "evil.example.test"])
    def test_a_host_in_allowed_hosts_is_still_refused(self, http_request) -> None:
        """The distinction that catches people out. ALLOWED_HOSTS says which
        hosts Django will serve. It says nothing about where it is safe to send
        an authenticated session."""
        url = "https://evil.example.test/steal"
        assert safe_redirect_url(url, request=http_request, fallback=FALLBACK) == FALLBACK


class TestSchemeDowngrade:
    def test_a_secure_request_refuses_an_http_target(self, secure_request) -> None:
        url = "http://app.example.test/admin/"
        assert safe_redirect_url(url, request=secure_request, fallback=FALLBACK) == FALLBACK

    def test_a_secure_request_allows_an_https_target(self, secure_request) -> None:
        url = "https://app.example.test/admin/"
        assert safe_redirect_url(url, request=secure_request, fallback=FALLBACK) == url


class TestPredicateForm:
    def test_reports_true_for_safe_urls(self, http_request) -> None:
        assert is_safe_redirect_url("/admin/", request=http_request)

    def test_reports_false_for_hostile_urls(self, http_request) -> None:
        assert not is_safe_redirect_url("https://evil.test/", request=http_request)

    def test_reports_false_for_none(self, http_request) -> None:
        assert not is_safe_redirect_url(None, request=http_request)
