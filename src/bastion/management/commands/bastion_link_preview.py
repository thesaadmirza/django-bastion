"""``manage.py bastion_link_preview``.

Named for what it does. There is no apply mode and there will not be one:
adoption happens at sign-in, against an assertion in which the provider has
marked the address verified. A command that linked accounts without one would
be matching identities by email, which is the vulnerability the whole design
avoids -- django-allauth CVE-2025-65431, seen in the wild.
"""

from __future__ import annotations

import json
from typing import Any

from django.core.management.base import BaseCommand

from bastion.conf import SUBJECT_ONLY, VERIFIED_EMAIL_ONCE, get_setting
from bastion.linking import Outcome, preview

MARKERS = {
    Outcome.ELIGIBLE: ("would link", "SUCCESS"),
    Outcome.AMBIGUOUS: ("ambiguous", "WARNING"),
    Outcome.SKIPPED: ("skipped  ", "NOTICE"),
}


class Command(BaseCommand):
    help = "Show which local accounts verified_email_once would adopt, before anyone signs in."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--json",
            action="store_true",
            dest="as_json",
            help="Machine-readable output, for a review that has to be attached to a ticket.",
        )
        parser.add_argument(
            "--eligible-only",
            action="store_true",
            help="Only the accounts that would be adopted.",
        )

    def handle(self, **options: Any) -> None:
        policy = get_setting("IDENTITY").get("LINKING_POLICY", SUBJECT_ONLY)
        if policy != VERIFIED_EMAIL_ONCE:
            self.stdout.write(
                self.style.NOTICE(
                    f'LINKING_POLICY is "{policy}", so no local account is ever adopted '
                    f'and this report is empty. Set it to "{VERIFIED_EMAIL_ONCE}" with '
                    "LINKABLE_EMAIL_DOMAINS pinned to see what would happen."
                )
            )
            return

        candidates = preview()
        if options["eligible_only"]:
            candidates = [c for c in candidates if c.outcome is Outcome.ELIGIBLE]

        if options["as_json"]:
            self._emit_json(candidates)
            return
        self._emit_text(candidates)

    # ------------------------------------------------------------------ output --

    def _emit_json(self, candidates: list[Any]) -> None:
        self.stdout.write(
            json.dumps(
                {
                    "conditional_on": "the provider marking the address verified at sign-in",
                    "candidates": [
                        {
                            "outcome": c.outcome.value,
                            "email": c.email,
                            "username": c.username,
                            "privileged": c.privileged,
                            "reason": c.reason,
                        }
                        for c in candidates
                    ],
                },
                indent=2,
            )
        )

    def _emit_text(self, candidates: list[Any]) -> None:
        if not candidates:
            self.stdout.write("No local accounts.")
            return

        for candidate in candidates:
            marker, style_name = MARKERS[candidate.outcome]
            style = getattr(self.style, style_name)
            flag = " [privileged]" if candidate.privileged else ""
            self.stdout.write(
                f"  {style(marker)}  {candidate.email or '(no address)'}"
                f"  {candidate.username}{flag}"
            )
            self.stdout.write(f"            {candidate.reason}")

        eligible = [c for c in candidates if c.outcome is Outcome.ELIGIBLE]
        privileged = [c for c in eligible if c.privileged]

        self.stdout.write("")
        self.stdout.write(
            f"{len(eligible)} of {len(candidates)} accounts would be adopted, "
            f"{len(privileged)} of them privileged."
        )
        self.stdout.write("")
        self.stdout.write(
            "Every one of those is conditional on the provider marking that "
            "address verified in the assertion, which cannot be known from "
            "here. Entra emits no email_verified at all, so an Entra "
            "deployment adopts nothing however this reads."
        )
