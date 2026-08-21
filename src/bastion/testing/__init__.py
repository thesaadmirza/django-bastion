"""A fake identity provider you can point this package at.

Testing an SSO integration means producing assertions a real provider will not
produce on demand. No Entra tenant emits a group-overage claim because you
asked, none will mark an address unverified for you, and none will omit ``amr``
on request. So the interesting paths -- an unverified email, incomplete group
evidence, a replayed ``state`` -- are exactly the ones a project ends up not
testing.

    from bastion.testing import harness

    def test_an_unverified_address_is_refused(client, db):
        rig = harness()
        with rig.installed():
            response = rig.login(client, email_verified=False)
        # refused: the failure page rather than a redirect, and no session

(Written without an ``assert`` on purpose. This package's lint refuses the
statement anywhere under ``src/``, because ``python -O`` strips it and a
security check written as one disappears silently -- and a grep cannot tell a
docstring from a code path.)

No certificate, no local HTTPS server, no CA bundle. ``Connection`` takes its
transport as a field, so the fake is injected rather than served -- which is
also why bastion can keep refusing plain-http issuers with no localhost
exemption.

What is not here: malformed and hostile tokens. `alg: none`, algorithm
confusion and key injection live in this project's own suite, because they
prove *bastion* refuses them rather than telling you anything about your
deployment.

This module is supported API. The rest of ``bastion`` may change under you
between alpha releases; what is exported here is meant to be imported.
"""

from bastion.testing.harness import AuthorizationRequest, Harness, harness
from bastion.testing.keys import SigningKey, generate_key
from bastion.testing.provider import DEFAULT_NOW, FakeIdP, entra, google, keycloak, okta
from bastion.testing.tokens import b64u, b64u_json, compact, decode_segment, sign
from bastion.testing.transport import FakeTransport

__all__ = [
    "DEFAULT_NOW",
    "AuthorizationRequest",
    "FakeIdP",
    "FakeTransport",
    "Harness",
    "SigningKey",
    "b64u",
    "b64u_json",
    "compact",
    "decode_segment",
    "entra",
    "generate_key",
    "google",
    "harness",
    "keycloak",
    "okta",
    "sign",
]
