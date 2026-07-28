"""``manage.py bastion_audit`` — verify, export, purge.

Evidence you cannot hand to an auditor is not evidence yet, so all three of
these exist before anyone asks for them.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from bastion.audit.events import Event, Outcome, Severity
from bastion.audit.models import (
    DEFAULT_CHAIN,
    AuditChain,
    AuditEvent,
    export_manifest,
    purge_before,
    verify_chain,
)
from bastion.audit.recorder import emit
from bastion.conf import get_setting


class Command(BaseCommand):
    help = "Verify, export or apply retention to the audit log."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("action", choices=["verify", "export", "purge", "status"])
        parser.add_argument("--chain", default=DEFAULT_CHAIN)
        parser.add_argument(
            "--since",
            help="ISO date. Export only, limits the range.",
        )
        parser.add_argument(
            "--days",
            type=int,
            help="Purge only. Overrides the configured retention period.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Purge only. Report what would go, remove nothing.",
        )

    def handle(self, **options: Any) -> None:
        getattr(self, f"_{options['action']}")(options)

    # ---------------------------------------------------------------- verify --

    def _verify(self, options: dict[str, Any]) -> None:
        chain = options["chain"]
        ok, problems = verify_chain(chain)

        emit(
            Event.AUDIT_VERIFIED if ok else Event.AUDIT_VERIFICATION_FAILED,
            outcome=Outcome.SUCCESS if ok else Outcome.FAILURE,
            severity=Severity.INFO if ok else Severity.CRITICAL,
            context={"chain": chain, "problems": problems[:20]},
        )

        if ok:
            head = AuditChain.objects.filter(name=chain).first()
            self.stdout.write(self.style.SUCCESS(f"chain {chain!r} verifies"))
            if head:
                self.stdout.write(f"  head sequence: {head.last_seq}")
                self.stdout.write(f"  head hash:     {head.last_hash}")
                self.stdout.write("")
                self.stdout.write(
                    "Anchor that hash somewhere this deployment does not control. "
                    "Verification proves the chain is internally consistent; it "
                    "cannot detect an adversary who recomputed it after editing."
                )
            return

        for problem in problems:
            self.stdout.write(self.style.ERROR(f"  {problem}"))
        raise CommandError(f"{len(problems)} integrity problem(s) in chain {chain!r}")

    # ---------------------------------------------------------------- export --

    def _export(self, options: dict[str, Any]) -> None:
        """JSON lines to stdout, manifest last.

        Line-delimited rather than one array so that an export larger than
        memory is still streamable, at either end.
        """
        since = _parse_date(options.get("since"))
        events = AuditEvent.objects.filter(chain=options["chain"])
        if since:
            events = events.filter(occurred_at__gte=since)

        count = 0
        for event in events.order_by("chain_seq").iterator():
            self.stdout.write(json.dumps(_serialise(event), sort_keys=True))
            count += 1

        manifest = export_manifest(chain=options["chain"], since=since)
        self.stdout.write(json.dumps({"manifest": manifest}, sort_keys=True))

        emit(
            Event.AUDIT_EXPORTED,
            outcome=Outcome.SUCCESS,
            severity=Severity.NOTICE,
            context={
                "chain": options["chain"],
                "count": count,
                "since": since.isoformat() if since else None,
            },
        )

    # ----------------------------------------------------------------- purge --

    def _purge(self, options: dict[str, Any]) -> None:
        days = options.get("days") or get_setting("AUDIT").get("RETENTION_DAYS", 365)
        cutoff = dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=days)

        doomed = AuditEvent.objects.filter(chain=options["chain"], occurred_at__lt=cutoff).count()

        if options["dry_run"]:
            self.stdout.write(f"{doomed} event(s) older than {cutoff.date()} would be removed.")
            self.stdout.write("Nothing was changed.")
            return

        removed = purge_before(cutoff, chain=options["chain"])
        self.stdout.write(
            self.style.SUCCESS(f"removed {removed} event(s) older than {cutoff.date()}")
        )
        if removed:
            self.stdout.write(
                "The retention watermark was advanced, so verification will not "
                "report the resulting gap. A purge that left no trace would be "
                "indistinguishable from evidence destruction."
            )

    # ---------------------------------------------------------------- status --

    def _status(self, options: dict[str, Any]) -> None:
        chain = options["chain"]
        head = AuditChain.objects.filter(name=chain).first()
        stored = AuditEvent.objects.filter(chain=chain).count()
        retention = get_setting("AUDIT").get("RETENTION_DAYS", 365)

        self.stdout.write(f"chain:            {chain}")
        self.stdout.write(f"events stored:    {stored}")
        self.stdout.write(f"head sequence:    {head.last_seq if head else 0}")
        self.stdout.write(f"purged through:   {head.purged_through_seq if head else 0}")
        self.stdout.write(f"retention (days): {retention}")
        self.stdout.write(f"sinks:            {get_setting('AUDIT').get('SINKS', [])}")


def _parse_date(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise CommandError(f"could not parse {value!r} as an ISO date") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def _serialise(event: AuditEvent) -> dict[str, Any]:
    return {
        "seq": event.chain_seq,
        "type": event.event_type,
        "occurred_at": event.occurred_at.isoformat(),
        "recorded_at": event.recorded_at.isoformat(),
        "outcome": event.outcome,
        "severity": event.severity,
        "actor": event.actor_pseudonym,
        "actor_type": event.actor_type,
        "source_ip": event.source_ip,
        "target": {"type": event.target_type, "id": event.target_id},
        "subject": event.subject,
        "issuer": event.issuer,
        "connection": event.connection,
        "auth_protocol": event.auth_protocol,
        "auth_methods": event.auth_methods,
        "session_id": event.session_id,
        "correlation_id": event.correlation_id,
        "changes": event.changes,
        "reason": event.reason,
        "is_privileged": event.is_privileged,
        "context": event.context,
        "prev_hash": event.prev_hash,
        "record_hash": event.record_hash,
        "schema_version": event.schema_version,
    }
