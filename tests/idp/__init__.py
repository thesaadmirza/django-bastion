"""This project's own view of the fake provider.

The provider, its keys and the transport that serves it moved to
``bastion.testing`` when the harness became a supported thing for other
projects to import. One implementation, two audiences: this package re-exports
it so the suite's existing imports keep working, and adds the part that stays
private.

That part is ``tokens``: `alg: none`, algorithm confusion, key injection, an
unknown `crit`. They exist to prove bastion refuses them, which is this
project's job to test and nobody else's.
"""

from bastion.testing.keys import SigningKey, generate_key
from bastion.testing.provider import DEFAULT_NOW, FakeIdP
from bastion.testing.tokens import b64u, b64u_json, compact
from bastion.testing.transport import FakeTransport

__all__ = [
    "DEFAULT_NOW",
    "FakeIdP",
    "FakeTransport",
    "SigningKey",
    "b64u",
    "b64u_json",
    "compact",
    "generate_key",
]
