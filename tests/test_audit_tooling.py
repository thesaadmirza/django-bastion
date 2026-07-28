"""Retention, export and verification tooling.

Evidence you cannot hand to an auditor is not evidence yet. These are the three
operations that make the audit log usable rather than merely present.
"""

from __future__ import annotations

import datetime as dt
import json
from io import StringIO
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.core import signing
from django.core.management import call_command
from django.core.management.base import CommandError

from bastion.audit.events import Event
from bastion.audit.models import (
    AuditChain,
    AuditEvent,
    export_manifest,
    purge_before,
    verify_chain,
)
from bastion.audit.recorder import emit

pytestmark = pytest.mark.django_db

User = get_user_model()


def run(*args: str, **kwargs: Any) -> str:
    out = StringIO()
    call_command("bastion_audit", *args, stdout=out, stderr=StringIO(), **kwargs)
    return out.getvalue()


def make_events(count: int, *, age_days: int = 0) -> None:
    when = dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=age_days)
    for _ in range(count):
        emit(Event.LOGIN_SUCCEEDED, occurred_at=when)


class TestRetention:
    def test_old_events_are_removed(self) -> None:
        make_events(3, age_days=400)
        make_events(2)
        removed = purge_before(dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=365))
        assert removed == 3

    def test_recent_events_survive(self) -> None:
        make_events(3, age_days=400)
        make_events(2)
        purge_before(dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=365))
        # Two survivors plus the purge record itself.
        assert AuditEvent.objects.filter(event_type=Event.LOGIN_SUCCEEDED).count() == 2

    def test_the_purge_records_itself(self) -> None:
        """A hole in an audit sequence with nothing accounting for it looks
        exactly like evidence destruction."""
        make_events(3, age_days=400)
        purge_before(dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=365))

        record = AuditEvent.objects.get(event_type=Event.AUDIT_PURGED)
        assert record.context["removed"] == 3
        assert record.context["through_seq"] == 3

    def test_verification_still_passes_after_a_purge(self) -> None:
        """Without the watermark, the first purge would make the integrity
        check fail for the rest of the chain's life, and a permanently failing
        check is one nobody reads."""
        make_events(4, age_days=400)
        make_events(3)
        purge_before(dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=365))

        ok, problems = verify_chain()
        assert ok, problems

    def test_the_watermark_advances(self) -> None:
        make_events(4, age_days=400)
        purge_before(dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=365))
        assert AuditChain.objects.get(name="default").purged_through_seq == 4

    def test_tampering_after_a_purge_is_still_detected(self) -> None:
        """The watermark must forgive the purge, not everything before it."""
        make_events(3, age_days=400)
        make_events(3)
        purge_before(dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=365))

        survivor = AuditEvent.objects.filter(chain_seq=5).first()
        AuditEvent.objects.filter(pk=survivor.pk).update(reason="tampered")

        ok, problems = verify_chain()
        assert not ok
        assert any("does not match its hash" in p for p in problems)

    def test_purging_nothing_is_a_no_op(self) -> None:
        make_events(2)
        assert purge_before(dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=365)) == 0


class TestManifest:
    def test_it_reports_the_range_and_count(self) -> None:
        make_events(5)
        manifest = export_manifest()
        assert manifest["count"] == 5
        assert manifest["first_seq"] == 1
        assert manifest["last_seq"] == 5

    def test_it_is_signed_by_this_deployment(self) -> None:
        make_events(2)
        manifest = export_manifest()
        body = dict(manifest)
        signature = body.pop("signature")
        assert signing.loads(signature, salt="bastion.audit.manifest") == body

    def test_a_forged_manifest_does_not_verify(self) -> None:
        make_events(2)
        manifest = export_manifest()
        with pytest.raises(signing.BadSignature):
            signing.loads(manifest["signature"] + "x", salt="bastion.audit.manifest")

    def test_it_carries_the_chain_head(self) -> None:
        make_events(3)
        manifest = export_manifest()
        head = AuditChain.objects.get(name="default")
        assert manifest["chain_head_hash"] == head.last_hash


class TestVerifyCommand:
    def test_a_clean_chain_reports_success(self) -> None:
        make_events(3)
        assert "verifies" in run("verify")

    def test_it_tells_you_to_anchor_the_head(self) -> None:
        """The chain's limit belongs in the output, not only in a docstring."""
        make_events(2)
        assert "does not control" in run("verify")

    def test_a_broken_chain_exits_non_zero(self) -> None:
        make_events(3)
        AuditEvent.objects.filter(chain_seq=2).update(reason="tampered")
        with pytest.raises(CommandError):
            run("verify")

    def test_verification_is_itself_recorded(self) -> None:
        make_events(2)
        run("verify")
        assert AuditEvent.objects.filter(event_type=Event.AUDIT_VERIFIED).exists()

    def test_a_failed_verification_is_recorded_as_critical(self) -> None:
        make_events(3)
        AuditEvent.objects.filter(chain_seq=2).update(reason="tampered")
        with pytest.raises(CommandError):
            run("verify")
        record = AuditEvent.objects.filter(event_type=Event.AUDIT_VERIFICATION_FAILED).first()
        assert record is not None
        assert record.severity == "critical"


class TestExportCommand:
    def test_every_event_is_emitted_as_one_line(self) -> None:
        make_events(4)
        lines = [line for line in run("export").splitlines() if line.strip()]
        # Four events plus the manifest.
        assert len(lines) == 5

    def test_the_last_line_is_the_manifest(self) -> None:
        make_events(2)
        last = json.loads(run("export").splitlines()[-1])
        assert last["manifest"]["count"] >= 2

    def test_lines_are_parseable_json(self) -> None:
        make_events(3)
        for line in run("export").splitlines():
            assert json.loads(line)

    def test_the_export_is_recorded(self) -> None:
        make_events(2)
        run("export")
        assert AuditEvent.objects.filter(event_type=Event.AUDIT_EXPORTED).exists()

    def test_no_user_identifier_appears_in_the_export(self) -> None:
        user = User.objects.create_user(username="alice", email="alice@example.test")
        emit(Event.LOGIN_SUCCEEDED, actor=user)
        output = run("export")
        assert "alice" not in output


class TestPurgeCommand:
    def test_dry_run_changes_nothing(self) -> None:
        make_events(3, age_days=400)
        output = run("purge", "--dry-run")
        assert "would be removed" in output
        assert AuditEvent.objects.count() == 3

    def test_it_uses_the_configured_retention(self, settings) -> None:
        settings.BASTION = {"AUDIT": {"RETENTION_DAYS": 30}}
        make_events(2, age_days=60)
        make_events(1)
        run("purge")
        assert AuditEvent.objects.filter(event_type=Event.LOGIN_SUCCEEDED).count() == 1

    def test_days_can_be_overridden(self) -> None:
        make_events(2, age_days=10)
        run("purge", "--days", "5")
        assert AuditEvent.objects.filter(event_type=Event.LOGIN_SUCCEEDED).count() == 0


class TestStatusCommand:
    def test_it_reports_the_head_and_retention(self) -> None:
        make_events(3)
        output = run("status")
        assert "head sequence:    3" in output
        assert "retention (days)" in output
