"""A synthetic identity provider for the test suite.

This exists because the cases that matter most cannot be produced on demand by
a real IdP. No Entra tenant will emit a groups-overage claim because you asked
it to, no provider will rotate a signing key mid-request, and none of them will
hand you a token signed with `alg: none` so you can prove you reject it.

So we mint our own, at the byte level.

Deliberately hand-rolled rather than built on authlib or PyJWT: a JOSE library
that is working correctly will *refuse* to produce most of the corpus below.
You cannot test that `alg: none` is rejected using a library that will not
serialise it. Everything here assembles the compact serialisation directly and
signs with `cryptography` primitives, so we can produce tokens that are
malformed, hostile, or simply illegal.

Nothing in this package is importable from `bastion`. It is test scaffolding
and it stays that way.
"""

from tests.idp.keys import SigningKey, generate_key
from tests.idp.provider import FakeIdP
from tests.idp.tokens import b64u, b64u_json, compact

__all__ = [
    "FakeIdP",
    "SigningKey",
    "b64u",
    "b64u_json",
    "compact",
    "generate_key",
]
