"""``manage.py bastion_doctor``.

Exits non-zero on any failure, so it can be wired into a deployment pipeline or
a monitoring check rather than only run by a human who remembers to.
"""

from __future__ import annotations

import json
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from bastion.conf import get_setting
from bastion.connections import get_connection
from bastion.diagnostics import Report, Result, Status, check_connection, check_project
from bastion.exceptions import ConfigurationError

MARKERS = {
    Status.OK: ("ok  ", "SUCCESS"),
    Status.WARN: ("warn", "WARNING"),
    Status.FAIL: ("FAIL", "ERROR"),
    Status.UNVERIFIABLE: ("?   ", "NOTICE"),
    Status.INFO: ("--  ", "NOTICE"),
}


class Command(BaseCommand):
    help = "Check that every configured SSO connection is usable."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "connections",
            nargs="*",
            help="Connections to check. Defaults to all of them.",
        )
        parser.add_argument(
            "--offline",
            action="store_true",
            help="Validate configuration only, making no network requests.",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            dest="as_json",
            help="Emit machine-readable output for monitoring.",
        )
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Treat warnings as failures.",
        )
        parser.add_argument(
            "--base-url",
            dest="base_url",
            default=None,
            metavar="URL",
            help=(
                "The scheme and host this deployment is reached on, for example "
                "https://admin.example.com. Used to print the exact callback URL "
                "the provider has to have registered. Without it the URL is "
                "assembled from ALLOWED_HOSTS and the TLS settings, and the "
                "assumptions are printed with it."
            ),
        )

    def handle(self, **options: Any) -> None:
        names = options["connections"] or sorted(get_setting("CONNECTIONS"))
        if not names:
            raise CommandError(
                'No connections are configured. Add one under BASTION["CONNECTIONS"].'
            )

        reports = [check_project(base_url=options["base_url"])]
        for name in names:
            try:
                connection = get_connection(name)
            except ConfigurationError as exc:
                reports.append(
                    Report(
                        connection=name,
                        results=[Result("config", Status.FAIL, str(exc))],
                    )
                )
                continue
            reports.append(check_connection(connection, offline=options["offline"]))

        if options["as_json"]:
            self._emit_json(reports)
        else:
            self._emit_text(reports)

        failed = any(r.failed for r in reports)
        warned = any(r.warned for r in reports)
        if failed or (options["strict"] and warned):
            raise CommandError("bastion_doctor found problems.")

    # ------------------------------------------------------------------ output --

    def _emit_json(self, reports: list[Report]) -> None:
        payload = {
            "ok": not any(r.failed for r in reports),
            "reports": [
                {
                    "connection": report.connection,
                    "results": [
                        {
                            "name": result.name,
                            "status": result.status.value,
                            "detail": result.detail,
                            "hint": result.hint,
                        }
                        for result in report.results
                    ],
                }
                for report in reports
            ],
        }
        self.stdout.write(json.dumps(payload, indent=2))

    def _emit_text(self, reports: list[Report]) -> None:
        for report in reports:
            title = f"connection: {report.connection}" if report.connection else "project"
            self.stdout.write("")
            self.stdout.write(self.style.MIGRATE_HEADING(title))
            for result in report.results:
                marker, style_name = MARKERS[result.status]
                style = getattr(self.style, style_name)
                self.stdout.write(f"  {style(marker)}  {result.name}: {result.detail}")
                if result.hint:
                    for line in _wrap(result.hint):
                        self.stdout.write(f"        {line}")

        self.stdout.write("")
        counts = _counts(reports)
        summary = ", ".join(f"{n} {status.value}" for status, n in counts.items() if n)
        self.stdout.write(summary or "nothing to report")

        if counts.get(Status.UNVERIFIABLE):
            self.stdout.write("")
            self.stdout.write(
                "Items marked ? could not be checked from here. They are listed "
                "rather than skipped so that a clean run is not mistaken for a "
                "complete one."
            )


def _counts(reports: list[Report]) -> dict[Status, int]:
    counts = dict.fromkeys(Status, 0)
    for report in reports:
        for result in report.results:
            counts[result.status] += 1
    return counts


def _wrap(text: str, width: int = 72) -> list[str]:
    import textwrap

    return textwrap.wrap(text, width=width)
