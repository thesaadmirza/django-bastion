"""Show what bastion_doctor actually prints.

Run: python tests/manual_doctor_demo.py
Not part of the automated suite; tests/test_doctor.py covers the behaviour.
"""

from __future__ import annotations

import django
from django.conf import settings

import tests.settings as base

config = {k: getattr(base, k) for k in dir(base) if k.isupper()}
settings.configure(**config)
django.setup()

from unittest import mock

from django.core.management import call_command

from bastion.connections import Connection
from bastion.protocols.oidc.transaction import MemoryTransactionStore
from tests.idp.provider import FakeIdP, google
from tests.idp.transport import FakeTransport


def connection_for(idp: FakeIdP, **kwargs) -> Connection:
    return Connection(
        identifier=kwargs.pop("identifier", "corp"),
        issuer=idp.issuer,
        client_id=idp.client_id,
        client_secret="shh",
        transport=FakeTransport(idp=idp),
        transactions=MemoryTransactionStore(),
        **kwargs,
    )


healthy = connection_for(FakeIdP(), staff_groups=("django-staff",), require_mfa=True)
awkward = connection_for(google(), identifier="workspace", provider="google")

connections = {"corp": healthy, "workspace": awkward}

with (
    mock.patch(
        "bastion.management.commands.bastion_doctor.get_connection",
        side_effect=lambda name: connections[name],
    ),
    mock.patch(
        "bastion.management.commands.bastion_doctor.get_setting",
        side_effect=lambda key: {"corp": {}, "workspace": {}},
    ),
):
    try:
        call_command("bastion_doctor")
    except Exception as exc:
        print(f"\nexit: {exc}")
