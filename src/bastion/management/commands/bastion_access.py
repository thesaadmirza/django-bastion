"""``manage.py bastion_access``.

The artefact a compliance review asks for: who can reach the admin right now,
and on what basis.
"""

from __future__ import annotations

import json
from typing import Any

from django.core.management.base import BaseCommand

from bastion.access import Basis, Holder, holders, unattributable_grants

MARKERS = {
    Basis.OUTSIDE_SSO: ("outside SSO ", "WARNING"),
    Basis.BEFORE_THE_WINDOW: ("unrecorded ", "NOTICE"),
    Basis.GRANTED_BY_SSO: ("by group   ", "SUCCESS"),
}


class Command(BaseCommand):
    help = "Report who holds admin access and how each of them got it."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--json",
            action="store_true",
            dest="as_json",
            help="Machine-readable, for attaching to a review.",
        )
        parser.add_argument(
            "--unexplained-only",
            action="store_true",
            help="Only the accounts with no grant on the audit chain.",
        )

    def handle(self, **options: Any) -> None:
        found = holders()
        if options["unexplained_only"]:
            found = [h for h in found if h.basis is not Basis.GRANTED_BY_SSO]

        if options["as_json"]:
            self._emit_json(found)
            return
        self._emit_text(found)

    # ------------------------------------------------------------------ output --

    def _emit_json(self, found: list[Holder]) -> None:
        self.stdout.write(
            json.dumps(
                {
                    "holders": [
                        {
                            "username": h.username,
                            "email": h.email,
                            "is_staff": h.is_staff,
                            "is_superuser": h.is_superuser,
                            "is_active": h.is_active,
                            "basis": h.basis.value,
                            "granted_at": h.granted_at.isoformat() if h.granted_at else None,
                            "connection": h.connection,
                            "identities": list(h.identities),
                            "break_glass": h.break_glass,
                            "notes": list(h.notes),
                        }
                        for h in found
                    ],
                    "unattributable_grants": unattributable_grants(),
                },
                indent=2,
            )
        )

    def _emit_text(self, found: list[Holder]) -> None:
        if not found:
            self.stdout.write("Nobody holds is_staff or is_superuser.")
            return

        for holder in found:
            marker, style_name = MARKERS[holder.basis]
            style = getattr(self.style, style_name)
            roles = ", ".join(
                name
                for name, held in (("superuser", holder.is_superuser), ("staff", holder.is_staff))
                if held
            )
            suffix = "".join(
                [
                    "  [break-glass]" if holder.break_glass else "",
                    "  [inactive]" if not holder.is_active else "",
                ]
            )
            self.stdout.write(f"  {style(marker)}  {holder.username}  ({roles}){suffix}")

            if holder.granted_at:
                where = f" via {holder.connection}" if holder.connection else ""
                self.stdout.write(f"            granted {holder.granted_at:%Y-%m-%d %H:%M}{where}")
            for note in holder.notes:
                self.stdout.write(f"            {note}")
            if holder.predates_sso:
                self.stdout.write("            no federated identity: has never signed in via SSO")

        self._emit_summary(found)

    def _emit_summary(self, found: list[Holder]) -> None:
        unexplained = [h for h in found if h.basis is not Basis.GRANTED_BY_SSO]
        no_identity = [h for h in found if h.predates_sso]
        orphaned = unattributable_grants()

        self.stdout.write("")
        self.stdout.write(
            f"{len(found)} account(s) can reach the admin. "
            f"{len(unexplained)} have no grant on the audit chain, "
            f"{len(no_identity)} have never signed in through a provider."
        )

        if orphaned:
            self.stdout.write("")
            self.stdout.write(
                f"{orphaned} privileged grant(s) on the chain belong to an actor that no "
                "longer resolves. That is erasure working as intended, and it means this "
                "report cannot account for every grant ever made."
            )
