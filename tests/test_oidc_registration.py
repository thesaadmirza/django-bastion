"""The redirect-URI registration probe.

Every provider answers this differently and one answers it badly, so the
classifier is the part worth testing and it is pure: no network, no Django.
"""

from __future__ import annotations

import urllib.parse

import pytest

from bastion.protocols.oidc.registration import (
    MAX_BODY,
    Registration,
    build_authorize_url,
    classify,
    probe_registration,
)

CALLBACK = "https://admin.example.com/sso/callback/"


def verdict(**kwargs: object) -> Registration:
    defaults: dict[str, object] = {
        "status": 200,
        "location": None,
        "body": "",
        "redirect_uri": CALLBACK,
    }
    return classify(**{**defaults, **kwargs}).verdict  # type: ignore[arg-type]


class TestPositiveProof:
    def test_a_redirect_to_our_callback_proves_registration(self) -> None:
        """RFC 6749 4.1.2.1: the server must not redirect to an unregistered
        URI, so arriving there is the answer."""
        assert verdict(status=302, location=f"{CALLBACK}?code=abc") is Registration.REGISTERED

    def test_even_when_the_redirect_carries_an_error(self) -> None:
        """`access_denied` says the person refused consent. It still had to
        reach a registered URI to say so."""
        assert (
            verdict(status=302, location=f"{CALLBACK}?error=access_denied")
            is Registration.REGISTERED
        )

    def test_a_sign_in_page_counts(self) -> None:
        body = '<form><input name="loginfmt" type="email"></form>'
        assert verdict(body=body) is Registration.REGISTERED


class TestNegativeProof:
    @pytest.mark.parametrize("marker", ["redirect_uri_mismatch", "invalid_redirect_uri"])
    def test_the_named_oauth_errors(self, marker: str) -> None:
        assert verdict(status=400, body=f'{{"error":"{marker}"}}') is Registration.NOT_REGISTERED

    def test_in_a_redirect_query_rather_than_a_body(self) -> None:
        location = "https://provider.test/error?error=redirect_uri_mismatch"
        assert verdict(status=302, location=location) is Registration.NOT_REGISTERED

    def test_the_microsoft_code(self) -> None:
        """Entra names it AADSTS50011 and sends no `error` parameter at all."""
        assert verdict(body="AADSTS50011: reply url does not match") is Registration.NOT_REGISTERED

    @pytest.mark.parametrize("marker", ["unauthorized_client", "invalid_client", "AADSTS700016"])
    def test_a_refused_client_is_reported_separately(self, marker: str) -> None:
        """The fix is a different field, and the URI cannot be judged yet."""
        assert verdict(status=200, body=marker) is Registration.CLIENT_REJECTED


class TestWhatProvidersActuallySend:
    """Captured from live endpoints. Both were classified inconclusive by the
    first version of this module, which is how they were found."""

    def test_google_hides_the_error_in_a_base64_parameter(self) -> None:
        """Google redirects to its own error page with the OAuth error base64ed
        into `authError`, so `invalid_client` appears nowhere as plain text."""
        location = (
            "https://accounts.google.com/signin/oauth/error?authError="
            "Cg5pbnZhbGlkX2NsaWVudBIfVGhlIE9BdXRoIGNsaWVudCB3YXMgbm90IGZvdW5kLiCRAw"
            "&flowName=GeneralOAuthFlow"
        )
        assert verdict(status=302, location=location) is Registration.CLIENT_REJECTED

    def test_an_undecodable_parameter_does_not_crash(self) -> None:
        location = "https://accounts.google.com/signin/oauth/error?authError=!!!not-base64!!!"
        assert verdict(status=302, location=location) is Registration.INCONCLUSIVE

    def test_entra_uses_a_code_no_list_had(self) -> None:
        """Written against 700016 and 90002; the first live run met 700038.
        The phrase rule catches it whether or not the code is listed."""
        body = (
            '<meta name="PageID" content="ConvergedError" />'
            '{"strServiceExceptionMessage":"AADSTS700038: '
            '00000000-0000-0000-0000-000000000000 is not a valid application identifier."}'
        )
        assert verdict(status=200, body=body) is Registration.CLIENT_REJECTED

    def test_the_phrase_alone_is_enough(self) -> None:
        """A code Microsoft has not minted yet still classifies."""
        body = "AADSTS999999: something is not a valid application identifier."
        assert verdict(status=200, body=body) is Registration.CLIENT_REJECTED

    def test_a_reply_url_complaint_in_prose(self) -> None:
        body = "AADSTS50011: The reply URL specified in the request does not match."
        assert verdict(status=200, body=body) is Registration.NOT_REGISTERED


class TestRefusingToGuess:
    def test_an_unreadable_answer_is_not_a_pass(self) -> None:
        """The bug this exists for: Entra answers a bad client id with HTTP 200
        and an HTML page carrying no error parameter, so "no error seen"
        reported a broken deployment as healthy."""
        assert verdict(status=200, body="<html><body>Something else</body></html>") is (
            Registration.INCONCLUSIVE
        )

    def test_an_empty_body_is_not_a_pass(self) -> None:
        assert verdict(status=204) is Registration.INCONCLUSIVE

    def test_a_lookalike_host_does_not_count_as_our_callback(self) -> None:
        """A prefix comparison would accept this. The netloc differs, and this
        function's answer is the one that reports success."""
        location = "https://admin.example.com.attacker.test/sso/callback/?code=abc"
        assert verdict(status=302, location=location) is Registration.INCONCLUSIVE

    def test_a_different_path_on_our_host_does_not_count(self) -> None:
        location = "https://admin.example.com/somewhere-else/?code=abc"
        assert verdict(status=302, location=location) is Registration.INCONCLUSIVE

    def test_a_relative_location_is_resolved_before_comparing(self) -> None:
        assert verdict(status=302, location="/sso/callback/?code=abc") is Registration.REGISTERED


class TestTheRequest:
    def test_it_carries_what_providers_require(self) -> None:
        url = build_authorize_url(
            authorization_endpoint="https://provider.test/authorize",
            client_id="cid",
            redirect_uri=CALLBACK,
        )
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        assert query["client_id"] == ["cid"]
        assert query["redirect_uri"] == [CALLBACK]
        assert query["response_type"] == ["code"]
        assert query["code_challenge_method"] == ["S256"]
        assert query["code_challenge"] and query["state"] and query["nonce"]

    def test_no_secret_is_ever_in_the_url(self) -> None:
        url = build_authorize_url(
            authorization_endpoint="https://provider.test/authorize",
            client_id="cid",
            redirect_uri=CALLBACK,
        )
        assert "secret" not in url.lower()

    def test_each_request_is_unique(self) -> None:
        """The state and verifier are thrown away, so they must not be reused
        across runs either."""
        kwargs = {
            "authorization_endpoint": "https://provider.test/authorize",
            "client_id": "cid",
            "redirect_uri": CALLBACK,
        }
        assert build_authorize_url(**kwargs) != build_authorize_url(**kwargs)  # type: ignore[arg-type]

    def test_an_endpoint_with_a_query_string_is_appended_to(self) -> None:
        url = build_authorize_url(
            authorization_endpoint="https://provider.test/authorize?p=1",
            client_id="cid",
            redirect_uri=CALLBACK,
        )
        assert "?p=1&client_id=" in url

    def test_a_plain_http_endpoint_is_refused(self) -> None:
        from bastion.exceptions import InsecureEndpoint

        with pytest.raises(InsecureEndpoint):
            build_authorize_url(
                authorization_endpoint="http://provider.test/authorize",
                client_id="cid",
                redirect_uri=CALLBACK,
            )


class TestNetworkFailures:
    def test_an_unreachable_provider_is_inconclusive_not_a_crash(self) -> None:
        import urllib.error

        class Failing:
            def open(self, *args: object, **kwargs: object) -> None:
                raise urllib.error.URLError("no route to host")

        probe = probe_registration(
            authorization_endpoint="https://provider.test/authorize",
            client_id="cid",
            redirect_uri=CALLBACK,
            opener=Failing(),
        )
        assert probe.verdict is Registration.INCONCLUSIVE
        assert "could not be reached" in probe.detail

    def test_a_suppressed_redirect_is_read_rather_than_followed(self) -> None:
        """The common real case. Suppressing the redirect makes urllib raise,
        and the exception carries the Location that holds the answer -- Google
        answers a bad client id exactly this way.
        """
        import email.message
        import io
        import urllib.error

        headers = email.message.Message()
        headers["Location"] = f"{CALLBACK}?code=abc"

        class Redirecting:
            def open(self, *args: object, **kwargs: object) -> None:
                raise urllib.error.HTTPError(
                    "https://provider.test/authorize", 302, "Found", headers, io.BytesIO(b"")
                )

        probe = probe_registration(
            authorization_endpoint="https://provider.test/authorize",
            client_id="cid",
            redirect_uri=CALLBACK,
            opener=Redirecting(),
        )
        assert probe.verdict is Registration.REGISTERED

    def test_redirects_are_not_followed(self) -> None:
        """Following would send this wherever a misconfigured client points,
        and would lose the header carrying the answer."""
        from bastion.protocols.oidc.registration import _NoRedirects

        handler = _NoRedirects()
        assert handler.redirect_request(None, None, 302, "Found", {}, "https://x.test") is None

    def test_the_body_is_capped(self) -> None:
        """An authorization endpoint answering with megabytes is not one whose
        answer improves after the first few kilobytes."""

        class Huge:
            status = 200

            def __init__(self) -> None:
                self.headers: dict[str, str] = {}

            def read(self, size: int) -> bytes:
                assert size == MAX_BODY
                return b"x" * size

            def __enter__(self) -> Huge:
                return self

            def __exit__(self, *args: object) -> None:
                return None

        class Opener:
            def open(self, *args: object, **kwargs: object) -> Huge:
                return Huge()

        probe = probe_registration(
            authorization_endpoint="https://provider.test/authorize",
            client_id="cid",
            redirect_uri=CALLBACK,
            opener=Opener(),
        )
        assert probe.verdict is Registration.INCONCLUSIVE
