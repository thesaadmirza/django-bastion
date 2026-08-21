"""Drive a whole login against a fake provider.

The pieces below existed separately and every project wiring them together
rediscovered the same three things: that the fake has to be reachable without a
network, that the views resolve their connection through a module-level lookup,
and that the callback needs an ID token carrying the nonce minted moments
earlier by a view you did not call.

That last one is the reason this file exists. The nonce is in the authorization
URL the begin view redirected to, which is ordinary public data -- but the
first version of this in bastion's own suite read it out of
``connection.transactions._records``, and anything that reaches into a private
attribute to work is something every integrator will get wrong or give up on.
"""

from __future__ import annotations

import contextlib
import datetime as dt
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from bastion.connections import Connection
from bastion.protocols.oidc.transaction import MemoryTransactionStore
from bastion.testing.provider import FakeIdP
from bastion.testing.transport import FakeTransport


@dataclass
class AuthorizationRequest:
    """What the begin view sent the browser to, unpacked."""

    url: str
    state: str
    nonce: str

    @classmethod
    def from_location(cls, location: str) -> AuthorizationRequest:
        query = parse_qs(urlparse(location).query)
        missing = [name for name in ("state", "nonce") if name not in query]
        if missing:
            raise AssertionError(
                f"the authorization URL carried no {' or '.join(missing)}: {location}"
            )
        return cls(url=location, state=query["state"][0], nonce=query["nonce"][0])


@dataclass
class Harness:
    """A fake provider, a connection pointed at it, and the login flow.

    Build it with :func:`harness`. Nothing here touches the network or needs a
    certificate: ``Connection`` takes its transport as a field, so the fake is
    injected rather than served.
    """

    idp: FakeIdP
    transport: FakeTransport
    connection: Connection

    #: Every authorization request begun through this harness, oldest first.
    requests: list[AuthorizationRequest] = field(default_factory=list)

    # ------------------------------------------------------------- wiring --

    @contextlib.contextmanager
    def installed(self) -> Iterator[Harness]:
        """Point bastion's views at this connection for the duration.

        A context manager rather than a pytest fixture so it works under
        unittest too, and so the patching is visible at the call site instead
        of arriving through fixture magic.
        """
        from unittest.mock import patch

        from bastion.conf import get_setting as real_get_setting

        def only_connections(key: str) -> Any:
            # Answering every key with the connections dict is the obvious
            # stub and it is wrong: a view that reads a second setting gets a
            # dict where a URL belongs. SUCCESS_URL did exactly that.
            if key == "CONNECTIONS":
                return {self.connection.identifier: {}}
            return real_get_setting(key)

        with (
            patch("bastion.views.get_connection", lambda name=None: self.connection),
            patch("bastion.views.get_setting", only_connections),
            patch("bastion.connections.get_connection", lambda name=None: self.connection),
        ):
            yield self

    # -------------------------------------------------------------- flow --

    def begin(self, client: Any, path: str = "/sso/login/") -> AuthorizationRequest:
        """Hit the begin view and unpack where it sent the browser."""
        response = client.get(path)
        if response.status_code != 302:
            raise AssertionError(
                f"{path} answered {response.status_code}, expected a redirect to the provider"
            )
        request = AuthorizationRequest.from_location(response["Location"])
        self.requests.append(request)
        return request

    def complete(
        self,
        client: Any,
        request: AuthorizationRequest,
        *,
        path: str = "/sso/callback/",
        code: str = "test-authorization-code",
        claims: dict[str, Any] | None = None,
        **overrides: Any,
    ) -> Any:
        """Answer the callback with a token bound to that request's nonce.

        Keyword overrides shape individual claims, which is most of the point:
        an unverified address, a missing ``sub`` or an absent ``amr`` is one
        argument rather than a hand-built token.

        ``claims`` takes a whole set instead, for the provider builders that
        return one -- ``with_groups``, ``with_group_overage``. Its nonce is
        replaced with this request's, because those builders carry the
        provider's placeholder and threading the live one through by hand is
        the friction this exists to remove.

        Overrides are applied last, so ``nonce="wrong"`` still gets you the
        mismatch case deliberately.
        """
        minted = dict(claims) if claims is not None else self.idp.base_claims(nonce=request.nonce)
        minted["nonce"] = request.nonce
        minted.update(overrides)
        self.transport.token_responses = [
            (200, {"id_token": self.idp.id_token_with(minted), "token_type": "Bearer"})
        ]
        return client.get(f"{path}?state={request.state}&code={code}")

    def login(self, client: Any, *, claims: dict[str, Any] | None = None, **overrides: Any) -> Any:
        """Begin and complete in one call, for the ordinary case."""
        return self.complete(client, self.begin(client), claims=claims, **overrides)


def harness(
    *,
    vendor: str = "generic",
    identifier: str = "corp",
    live_clock: bool = True,
    **connection_overrides: Any,
) -> Harness:
    """A provider, a transport and a connection, wired together.

    ``live_clock`` exists because the provider mints at a fixed timestamp so
    unit tests are reproducible, while the login flow validates against the
    wall clock, as it must. Driving a whole login needs the two to agree; set
    it false only when asserting on a fixed ``iat``.
    """
    idp = FakeIdP(vendor=vendor)  # type: ignore[arg-type]
    if live_clock:
        idp.now = dt.datetime.now(tz=dt.UTC)
    transport = FakeTransport(idp=idp)

    defaults: dict[str, Any] = {
        "identifier": identifier,
        "issuer": idp.issuer,
        "client_id": idp.client_id,
        "client_secret": "test-client-secret",
        "provider": vendor,
        "transport": transport,
        "transactions": MemoryTransactionStore(),
    }
    defaults.update(connection_overrides)
    return Harness(idp=idp, transport=transport, connection=Connection(**defaults))
