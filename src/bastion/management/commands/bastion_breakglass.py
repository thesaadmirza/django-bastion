"""``manage.py bastion_breakglass`` — manage and validate the fire escape.

``check`` is meant to be wired into monitoring rather than run by someone who
remembers to. Microsoft's guidance is validation every 90 days and on staff
change; a cadence nobody measures is a cadence nobody keeps.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from bastion.audit import emit
from bastion.audit.events import Event, Outcome, Severity
from bastion.backends import user_username_field
from bastion.breakglass.models import BreakGlassAccount, LastBreakGlassAccount
from bastion.breakglass.service import notify
from bastion.conf import get_setting

VALIDATION_DAYS = 90
RECOMMENDED_MINIMUM = 2


class Command(BaseCommand):
    help = "Create, list, revoke and validate break-glass accounts."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("action", choices=["check", "list", "grant", "revoke", "drill"])
        parser.add_argument("--user", help="Username. Required for grant and revoke.")
        parser.add_argument("--reason", default="", help="Why this account exists.")

    def handle(self, **options: Any) -> None:
        getattr(self, f"_{options['action']}")(options)

    # ----------------------------------------------------------------- check --

    def _check(self, options: dict[str, Any]) -> None:
        config = get_setting("BREAK_GLASS")
        problems: list[str] = []
        warnings: list[str] = []

        if not config.get("ENABLED"):
            self.stdout.write(self.style.WARNING("Break-glass is disabled."))
            self.stdout.write(
                "  An identity provider outage will lock everyone out, including "
                "whoever would fix it."
            )
            raise CommandError("break-glass is not enabled")

        if not config.get("ALERT_SINKS"):
            problems.append("no ALERT_SINKS configured; use would be silent")

        if not config.get("ALLOWED_NETWORKS"):
            warnings.append(
                "ALLOWED_NETWORKS is empty, so the emergency login is reachable from anywhere"
            )

        active = BreakGlassAccount.objects.active().count()
        if active == 0:
            problems.append("no active break-glass accounts exist")
        elif active < RECOMMENDED_MINIMUM:
            warnings.append(
                f"only {active} active account; {RECOMMENDED_MINIMUM} is the "
                "recommended minimum, so that losing one is not losing all"
            )

        stale = list(BreakGlassAccount.objects.stale(days=VALIDATION_DAYS))
        for account in stale:
            when = account.last_validated_at
            warnings.append(
                f"{account.user} last validated {when.date() if when else 'never'}; run a drill"
            )

        for account in BreakGlassAccount.objects.active().select_related("user"):
            if not account.user.has_usable_password():
                problems.append(f"{account.user} has no usable password")
            if not account.user.is_active:
                problems.append(f"{account.user} is inactive")

        for warning in warnings:
            self.stdout.write(self.style.WARNING(f"  warn  {warning}"))
        for problem in problems:
            self.stdout.write(self.style.ERROR(f"  FAIL  {problem}"))

        if not problems and not warnings:
            self.stdout.write(self.style.SUCCESS(f"{active} account(s), all validated"))
        if problems:
            raise CommandError(f"{len(problems)} problem(s) with break-glass setup")

    # ------------------------------------------------------------------ list --

    def _list(self, options: dict[str, Any]) -> None:
        accounts = BreakGlassAccount.objects.select_related("user").order_by("created_at")
        if not accounts:
            self.stdout.write("No break-glass accounts.")
            return
        for account in accounts:
            state = "active" if account.is_active else "revoked"
            used = account.last_used_at.date() if account.last_used_at else "never"
            validated = account.last_validated_at.date() if account.last_validated_at else "never"
            self.stdout.write(f"  {account.user}  [{state}]  used: {used}  validated: {validated}")
            if account.reason:
                self.stdout.write(f"      {account.reason}")

    # ----------------------------------------------------------------- grant --

    def _grant(self, options: dict[str, Any]) -> None:
        user = self._resolve_user(options)
        if not options["reason"]:
            raise CommandError(
                "--reason is required. It is read during an incident by someone "
                "who was not here when the account was made."
            )
        if not user.has_usable_password():
            raise CommandError(
                f"{user} has no usable password, so this account could not be "
                "used to sign in. Set one with changepassword first."
            )

        account, created = BreakGlassAccount.objects.get_or_create(
            user=user, defaults={"reason": options["reason"]}
        )
        if not created:
            account.is_active = True
            account.reason = options["reason"]
            account.save(update_fields=["is_active", "reason"])

        emit(
            Event.ROLE_GRANTED,
            actor=user,
            severity=Severity.CRITICAL,
            is_privileged=True,
            reason=options["reason"],
            context={"break_glass": True},
        )
        notify(subject="Break-glass account created", detail=f"user={user}")
        self.stdout.write(self.style.SUCCESS(f"{user} can now use emergency access"))

    # ---------------------------------------------------------------- revoke --

    def _revoke(self, options: dict[str, Any]) -> None:
        user = self._resolve_user(options)
        account = BreakGlassAccount.objects.filter(user=user).first()
        if account is None:
            raise CommandError(f"{user} is not a break-glass account")

        remaining = BreakGlassAccount.objects.active().exclude(pk=account.pk).count()
        if account.is_active and remaining == 0:
            raise LastBreakGlassAccount(
                "This is the only active break-glass account. Create another "
                "first, or the next provider outage locks everyone out."
            )

        account.is_active = False
        account.save(update_fields=["is_active"])
        emit(
            Event.ROLE_REVOKED,
            actor=user,
            severity=Severity.CRITICAL,
            is_privileged=True,
            context={"break_glass": True},
        )
        notify(subject="Break-glass account revoked", detail=f"user={user}")
        self.stdout.write(self.style.SUCCESS(f"revoked emergency access for {user}"))

    # ----------------------------------------------------------------- drill --

    def _drill(self, options: dict[str, Any]) -> None:
        """Record a validation and prove the alert path works.

        Deliberately fires a real alert. A drill that does not confirm the
        alarm rings has only tested half of what matters, and the half it
        skipped is the half that makes the account safe to have.
        """
        user = self._resolve_user(options)
        account = BreakGlassAccount.objects.filter(user=user, is_active=True).first()
        if account is None:
            raise CommandError(f"{user} is not an active break-glass account")

        notify(
            subject="Break-glass drill",
            detail=f"Scheduled validation for {user}. No action needed.",
        )
        account.last_validated_at = timezone.now()
        account.save(update_fields=["last_validated_at"])

        emit(
            Event.AUDIT_VERIFIED,
            outcome=Outcome.SUCCESS,
            actor=user,
            severity=Severity.NOTICE,
            context={"break_glass_drill": True},
        )

        self.stdout.write(self.style.SUCCESS(f"drill recorded for {user}"))
        self.stdout.write("")
        self.stdout.write("Confirm before treating this as passed:")
        self.stdout.write("  1. The alert arrived, through a channel that does not")
        self.stdout.write("     depend on the identity provider being up.")
        self.stdout.write("  2. Whoever received it knew it was a drill.")
        self.stdout.write("  3. The credential is still where the runbook says.")

    # ------------------------------------------------------------------------

    def _resolve_user(self, options: dict[str, Any]) -> Any:
        if not options.get("user"):
            raise CommandError("--user is required")
        model = get_user_model()
        try:
            return model._default_manager.get(**{user_username_field(): options["user"]})
        except model.DoesNotExist as exc:
            raise CommandError(f"no user named {options['user']!r}") from exc
