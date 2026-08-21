"""The token endpoint exchange."""

from __future__ import annotations

import base64
import datetime as dt

import pytest

from bastion.exceptions import InsecureEndpoint, TokenError
from bastion.protocols.oidc.client import (
    ClientAuthMethod,
    TokenEndpointError,
    TokenResponse,
    exchange_code,
)
from bastion.protocols.oidc.transaction import MemoryTransactionStore, start_transaction
from bastion.testing.provider import FakeIdP
from bastion.testing.transport import FakeTransport

TOKEN_ENDPOINT = "https://idp.example.test/token"
REDIRECT_URI = "https://app.test/sso/callback/"
NOW = dt.datetime(2026, 7, 28, 12, 0, 0, tzinfo=dt.UTC)


@pytest.fixture
def transport(idp: FakeIdP) -> FakeTransport:
    return FakeTransport(idp=idp)


@pytest.fixture
def transaction():
    return start_transaction(connection="corp", store=MemoryTransactionStore(), now=NOW)


def exchange(transaction, transport: FakeTransport, **kwargs):
    kwargs.setdefault("token_endpoint", TOKEN_ENDPOINT)
    kwargs.setdefault("client_id", "cid")
    kwargs.setdefault("client_secret", "shh")
    kwargs.setdefault("redirect_uri", REDIRECT_URI)
    return exchange_code("the-code", transaction=transaction, transport=transport, **kwargs)


class TestSuccessfulExchange:
    def test_returns_the_id_token(self, transaction, transport: FakeTransport) -> None:
        response = exchange(transaction, transport)
        assert response.id_token
        assert response.token_type == "Bearer"
        assert response.expires_in == 3600

    def test_posts_the_authorization_code_grant(
        self, transaction, transport: FakeTransport
    ) -> None:
        exchange(transaction, transport)
        _, data, _ = transport.posts[0]
        assert data["grant_type"] == "authorization_code"
        assert data["code"] == "the-code"
        assert data["redirect_uri"] == REDIRECT_URI

    def test_the_verifier_comes_from_the_transaction(
        self, transaction, transport: FakeTransport
    ) -> None:
        """Not a caller-supplied argument, so there is no call site where it
        can be omitted or substituted."""
        exchange(transaction, transport)
        _, data, _ = transport.posts[0]
        assert data["code_verifier"] == transaction.code_verifier


class TestClientAuthentication:
    def test_basic_is_the_default(self, transaction, transport: FakeTransport) -> None:
        exchange(transaction, transport)
        _, data, headers = transport.posts[0]
        assert headers["Authorization"].startswith("Basic ")
        assert "client_secret" not in data

    def test_basic_credentials_are_form_encoded_before_base64(
        self, transaction, transport: FakeTransport
    ) -> None:
        """RFC 6749 2.3.1. Skipping the encoding works until a secret contains
        a character that needs it, then fails against some providers only."""
        exchange(transaction, transport, client_id="a b", client_secret="p@ss/word")
        _, _, headers = transport.posts[0]
        decoded = base64.b64decode(headers["Authorization"].split(" ", 1)[1]).decode()
        assert decoded == "a%20b:p%40ss%2Fword"

    def test_post_method_puts_the_secret_in_the_body(
        self, transaction, transport: FakeTransport
    ) -> None:
        exchange(transaction, transport, auth_method=ClientAuthMethod.POST)
        _, data, headers = transport.posts[0]
        assert data["client_secret"] == "shh"
        assert "Authorization" not in headers

    def test_none_sends_no_secret(self, transaction, transport: FakeTransport) -> None:
        exchange(transaction, transport, auth_method=ClientAuthMethod.NONE, client_secret=None)
        _, data, headers = transport.posts[0]
        assert "client_secret" not in data
        assert "Authorization" not in headers

    @pytest.mark.parametrize("method", [ClientAuthMethod.BASIC, ClientAuthMethod.POST])
    def test_a_missing_secret_is_a_configuration_failure(
        self, transaction, transport: FakeTransport, method: ClientAuthMethod
    ) -> None:
        with pytest.raises(TokenError):
            exchange(transaction, transport, auth_method=method, client_secret=None)


class TestErrorResponses:
    @pytest.mark.parametrize(
        "code",
        [
            "invalid_grant",
            "invalid_client",
            "invalid_request",
            "unauthorized_client",
            "unsupported_grant_type",
            "invalid_scope",
        ],
    )
    def test_rfc_error_codes_are_surfaced(
        self, transaction, transport: FakeTransport, code: str
    ) -> None:
        transport.token_responses = [(400, {"error": code})]
        with pytest.raises(TokenEndpointError) as caught:
            exchange(transaction, transport)
        assert caught.value.code == code
        assert caught.value.status == 400

    def test_the_free_text_description_is_discarded(
        self, transaction, transport: FakeTransport
    ) -> None:
        """error_description is provider-controlled and ends up rendered or
        logged. Only the closed-vocabulary code survives.

        The control doing the work here is the allowlist in ``_error_code``,
        not the field selection: anything outside the RFC 6749 vocabulary is
        normalised to ``unrecognised_error`` regardless of which key it came
        from. Mutating the field selection alone survives, which is the
        correct outcome and the reason the allowlist exists. See
        ``test_an_unrecognised_code_is_normalised`` for the direct check.
        """
        transport.token_responses = [
            (
                400,
                {
                    "error": "invalid_grant",
                    "error_description": "<script>alert(1)</script> secret=hunter2",
                    "error_uri": "https://attacker.test/",
                },
            )
        ]
        with pytest.raises(TokenEndpointError) as caught:
            exchange(transaction, transport)
        message = str(caught.value)
        assert "hunter2" not in message
        assert "script" not in message
        assert "attacker.test" not in message

    def test_an_unrecognised_code_is_normalised(
        self, transaction, transport: FakeTransport
    ) -> None:
        transport.token_responses = [(400, {"error": "something_bespoke"})]
        with pytest.raises(TokenEndpointError) as caught:
            exchange(transaction, transport)
        assert caught.value.code == "unrecognised_error"

    def test_an_error_response_with_no_code(self, transaction, transport: FakeTransport) -> None:
        transport.token_responses = [(500, {})]
        with pytest.raises(TokenEndpointError) as caught:
            exchange(transaction, transport)
        assert caught.value.code == "no_error_code"


class TestMalformedSuccess:
    def test_a_200_without_an_id_token_is_rejected(
        self, transaction, transport: FakeTransport
    ) -> None:
        """An OAuth-only response is not authentication. Treating it as a
        partial success is how an access token gets mistaken for proof of
        identity."""
        transport.token_responses = [(200, {"access_token": "at", "token_type": "Bearer"})]
        with pytest.raises(TokenError, match="no id_token"):
            exchange(transaction, transport)

    def test_an_empty_id_token_is_rejected(self, transaction, transport: FakeTransport) -> None:
        transport.token_responses = [(200, {"id_token": ""})]
        with pytest.raises(TokenError):
            exchange(transaction, transport)

    def test_unexpected_field_types_become_none(
        self, transaction, transport: FakeTransport, idp: FakeIdP
    ) -> None:
        transport.token_responses = [
            (200, {"id_token": idp.id_token(), "expires_in": "3600", "access_token": 42})
        ]
        response = exchange(transaction, transport)
        assert response.expires_in is None
        assert response.access_token is None


class TestSecrecy:
    def test_the_repr_does_not_leak_tokens(self, idp: FakeIdP) -> None:
        """This object reaches tracebacks and debug pages. The default
        dataclass repr would print every credential it holds."""
        response = TokenResponse(id_token=idp.id_token(), access_token="super-secret")
        assert "super-secret" not in repr(response)
        assert "redacted" in repr(response)

    def test_the_raw_body_is_excluded_from_the_repr(self, idp: FakeIdP) -> None:
        response = TokenResponse(id_token="x", raw={"refresh_token": "leaky"})
        assert "leaky" not in repr(response)


class TestEndpointScheme:
    def test_a_non_https_token_endpoint_is_refused(
        self, transaction, transport: FakeTransport
    ) -> None:
        with pytest.raises(InsecureEndpoint):
            exchange(transaction, transport, token_endpoint="http://idp.example.test/token")
