"""Emergency access.

Two properties are unusual enough to be worth naming.

There is no lockout. Every other login path in this package should lock out;
this one must not, because locking the fire escape is itself the denial of
service. Failures alert instead.

Alerting is not optional. A startup check refuses a configuration where
break-glass is on and no sink is configured, and every outcome fires the sinks,
including refusals.
"""

from __future__ import annotations

from io import StringIO
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client
from django.utils import timezone

from bastion.audit.events import Event
from bastion.audit.models import AuditEvent
from bastion.breakglass.models import BreakGlassAccount, LastBreakGlassAccount
from bastion.breakglass.service import (
    BreakGlassDenied,
    authenticate_break_glass,
    is_break_glass,
)

pytestmark = pytest.mark.django_db

User = get_user_model()

SINK = "tests.test_breakglass.recording_sink"
ALERTS: list[tuple[str, str]] = []


def recording_sink(*, subject: str, detail: str) -> None:
    ALERTS.append((subject, detail))


@pytest.fixture(autouse=True)
def _clear_alerts():
    ALERTS.clear()
    yield
    ALERTS.clear()


@pytest.fixture
def enabled(settings):
    settings.BASTION = {
        "BREAK_GLASS": {"ENABLED": True, "ALERT_SINKS": [SINK], "ALLOWED_NETWORKS": []}
    }


@pytest.fixture
def operator():
    user = User.objects.create_user(username="firefighter", password="a-real-password")
    BreakGlassAccount.objects.create(user=user, reason="incident response")
    return user


def run(*args: str, **kwargs: Any) -> str:
    out = StringIO()
    call_command("bastion_breakglass", *args, stdout=out, stderr=StringIO(), **kwargs)
    return out.getvalue()


class TestAuthentication:
    def test_a_flagged_account_can_sign_in(self, enabled, operator) -> None:
        user = authenticate_break_glass(username="firefighter", password="a-real-password")
        assert user == operator

    def test_an_unflagged_account_cannot(self, enabled) -> None:
        User.objects.create_user(username="ordinary", password="a-real-password")
        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(username="ordinary", password="a-real-password")

    def test_a_wrong_password_is_refused(self, enabled, operator) -> None:
        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(username="firefighter", password="wrong")

    def test_an_unknown_account_is_refused(self, enabled) -> None:
        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(username="nobody", password="anything")

    def test_an_inactive_user_is_refused(self, enabled, operator) -> None:
        User.objects.filter(pk=operator.pk).update(is_active=False)
        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(username="firefighter", password="a-real-password")

    def test_a_revoked_account_is_refused(self, enabled, operator) -> None:
        BreakGlassAccount.objects.filter(user=operator).update(is_active=False)
        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(username="firefighter", password="a-real-password")

    def test_it_is_refused_entirely_when_disabled(self, operator) -> None:
        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(username="firefighter", password="a-real-password")

    @pytest.mark.parametrize(
        ("username", "case"),
        [
            ("nobody", "unknown account"),
            ("ordinary", "not flagged"),
            ("benched", "inactive"),
        ],
    )
    def test_a_refused_path_hashes_exactly_as_much_as_a_real_one(
        self, enabled, operator, monkeypatch, username: str, case: str
    ) -> None:
        """Timing equalisation, asserted structurally rather than measured.

        Returning early without hashing tells an attacker, by response time,
        whether the account exists, whether it is a break-glass account, and
        whether it is still active.

        Hashing *more* than the real path answers the same question with the
        sign reversed, which is what this used to do: the refused branches built
        a throwaway hash and then verified against it, spending two KDF rounds
        where a real comparison spends one. A name nobody held came back
        measurably slower than one somebody did.

        So the assertion is on the count rather than on presence, which is the
        version of this property that would have caught that. A statistical
        timing test would be flaky on a shared runner and slow everywhere;
        counting the rounds is what needs protecting from a future refactor.
        """
        User.objects.create_user(username="ordinary", password="a-real-password")
        # The only case needing a flagged account of its own. ``firefighter``
        # is what the count is measured against, so it has to stay usable --
        # deactivating it would move the baseline rather than produce the case.
        # No password, because this branch refuses before anything reads one.
        benched = User.objects.create_user(username="benched", is_active=False)
        BreakGlassAccount.objects.create(user=benched, reason="incident response")

        # Counted on the hasher itself rather than on ``make_password`` or
        # ``check_password``. Those two are imported by value into several
        # namespaces, so patching any one of them counts only the callers that
        # happen to resolve through it and reports zero for the rest -- which
        # reads as "no hashing happened" when the truth is "hashing happened
        # somewhere this test could not see".
        #
        # ``encode`` is where the KDF round is actually spent, and every route
        # to hashing goes through it: ``make_password`` calls it once, and
        # ``verify`` calls it once before comparing. So the count is rounds.
        from django.contrib.auth.hashers import get_hasher

        hasher = type(get_hasher())
        rounds: list[str] = []

        def counting(real: Any) -> Any:
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                rounds.append("encode")
                return real(*args, **kwargs)

            return wrapper

        monkeypatch.setattr(hasher, "encode", counting(hasher.encode))

        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(username=username, password="wrong")
        refused = len(rounds)

        rounds.clear()
        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(username="firefighter", password="wrong")
        genuine = len(rounds)

        assert refused, f"no password hash performed on the {case} path"
        assert refused == genuine, (
            f"the {case} path spends {refused} hashing rounds against {genuine} "
            "for an account that exists, which is an enumeration oracle"
        )

    def test_the_reason_is_never_the_message_shown(self, enabled, operator) -> None:
        """Which of the gates was failed is audit-record information. Telling
        an attacker whether the account exists is free help."""
        with pytest.raises(BreakGlassDenied) as unknown:
            authenticate_break_glass(username="nobody", password="x")
        with pytest.raises(BreakGlassDenied) as wrong:
            authenticate_break_glass(username="firefighter", password="x")
        assert unknown.value.reason == wrong.value.reason == "credentials"


class TestNetworkRestriction:
    def test_an_allowed_network_passes(self, settings, operator, rf) -> None:
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": [SINK],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }
        request = rf.post("/", REMOTE_ADDR="10.1.2.3")
        assert authenticate_break_glass(
            username="firefighter", password="a-real-password", request=request
        )

    def test_a_disallowed_network_is_refused(self, settings, operator, rf) -> None:
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": [SINK],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }
        request = rf.post("/", REMOTE_ADDR="203.0.113.9")
        with pytest.raises(BreakGlassDenied) as caught:
            authenticate_break_glass(
                username="firefighter", password="a-real-password", request=request
            )
        assert caught.value.reason == "network"

    def _refuse(self, rf, address: str = "203.0.113.9") -> None:
        request = rf.post("/", REMOTE_ADDR=address)
        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(
                username="firefighter", password="a-real-password", request=request
            )

    def test_repeated_refusals_are_recorded_and_alerted_once(self, settings, operator, rf) -> None:
        """The endpoint amplified: it is login_not_required and deliberately
        outside django-axes, so anyone who found the URL could spend one chained
        audit write and one synchronous alert per request -- and a sink that
        reaches a paging API on a sixty-second timeout holds a worker open for
        each one. The throttle below this branch had the deduplication from the
        start; the branch anyone can reach did not.
        """
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": [SINK],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }
        for _ in range(5):
            self._refuse(rf)

        from bastion.audit.models import AuditEvent

        assert AuditEvent.objects.filter(reason="network").count() == 1
        assert len(ALERTS) == 1

    def test_the_refusal_records_denied_with_the_network_reason(
        self, settings, operator, rf
    ) -> None:
        """The gate above the credential path, pinned the same way they are.

        This one is not a credential refusal and does not pretend to be. The
        caller is told "network" rather than the generic "credentials", because
        an address outside the allowlist has not made a claim about who it is
        and there is nothing to keep quiet about. What the record says is still
        the only thing an investigation has, and DENIED rather than FAILURE is
        the load-bearing half: nothing here failed a check, the request was
        turned away before it could make one.
        """
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": [SINK],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }
        self._refuse(rf)

        written = [
            (record.outcome, record.reason)
            for record in AuditEvent.objects.filter(event_type=Event.PROTOCOL_FALLBACK).order_by(
                "id"
            )
        ]
        assert written == [("denied", "network")]

    def test_a_second_address_is_recorded_separately(self, settings, operator, rf) -> None:
        """Deduplication must not lose the evidence that the source moved."""
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": [SINK],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }
        self._refuse(rf, "203.0.113.9")
        self._refuse(rf, "198.51.100.4")

        from bastion.audit.models import AuditEvent

        assert AuditEvent.objects.filter(reason="network").count() == 2

    def test_an_addressless_request_is_refused_and_recorded_once(
        self, settings, operator, rf
    ) -> None:
        """No REMOTE_ADDR cannot satisfy an allowlist, and there is nothing to
        tell two such requests apart, so they share one record per window."""
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": [SINK],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }
        for _ in range(3):
            request = rf.post("/")
            request.META.pop("REMOTE_ADDR", None)
            with pytest.raises(BreakGlassDenied) as caught:
                authenticate_break_glass(
                    username="firefighter", password="a-real-password", request=request
                )
            assert caught.value.reason == "network"

        from bastion.audit.models import AuditEvent

        assert AuditEvent.objects.filter(reason="network", source_ip__isnull=True).count() == 1

    def test_an_unusable_cidr_matches_nothing_rather_than_raising(
        self, settings, operator, rf
    ) -> None:
        """bastion.E102 refuses this at startup. Reaching it anyway must not
        raise out of the gate deciding whether to answer an unauthenticated
        caller, and must not grant."""
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": [SINK],
                "ALLOWED_NETWORKS": ["not-a-network", "10.0.0.0/8"],
            }
        }
        with pytest.raises(BreakGlassDenied) as caught:
            authenticate_break_glass(
                username="firefighter",
                password="a-real-password",
                request=rf.post("/", REMOTE_ADDR="203.0.113.9"),
            )
        assert caught.value.reason == "network"
        assert authenticate_break_glass(
            username="firefighter",
            password="a-real-password",
            request=rf.post("/", REMOTE_ADDR="10.1.2.3"),
        )


class TestAlerting:
    def test_a_successful_use_alerts(self, enabled, operator) -> None:
        authenticate_break_glass(username="firefighter", password="a-real-password")
        assert ALERTS

    def test_a_failed_attempt_also_alerts(self, enabled, operator) -> None:
        """A wrong password on an emergency account is more interesting than a
        successful login on a normal one."""
        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(username="firefighter", password="wrong")
        assert ALERTS

    def test_an_attempt_on_an_unknown_account_alerts(self, enabled) -> None:
        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(username="nobody", password="x")
        assert ALERTS

    def test_a_broken_sink_does_not_block_the_login(self, settings, operator) -> None:
        """A broken pager must not prevent the emergency login it was meant to
        announce."""
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["tests.test_breakglass.exploding_sink"],
            }
        }
        assert authenticate_break_glass(username="firefighter", password="a-real-password")


def exploding_sink(*, subject: str, detail: str) -> None:
    raise RuntimeError("pager is down")


class TestAudit:
    def test_every_outcome_is_recorded_as_critical(self, enabled, operator) -> None:
        authenticate_break_glass(username="firefighter", password="a-real-password")
        record = AuditEvent.objects.filter(event_type=Event.PROTOCOL_FALLBACK).first()
        assert record is not None
        assert record.severity == "critical"
        assert record.is_privileged is True
        assert record.auth_protocol == "break_glass"

    def test_a_refusal_is_recorded(self, enabled, operator) -> None:
        with pytest.raises(BreakGlassDenied):
            authenticate_break_glass(username="firefighter", password="wrong")
        assert AuditEvent.objects.filter(event_type=Event.PROTOCOL_FALLBACK).exists()

    @pytest.mark.parametrize(
        ("username", "password", "outcome", "reason"),
        [
            ("nobody", "wrong", "failure", "unknown-account"),
            ("ordinary", "wrong", "denied", "not-a-break-glass-account"),
            ("benched", "wrong", "denied", "inactive"),
            ("firefighter", "wrong", "failure", "bad-password"),
            ("firefighter", "a-real-password", "success", "used"),
        ],
    )
    def test_each_gate_records_its_own_outcome_and_reason(
        self, enabled, operator, username: str, password: str, outcome: str, reason: str
    ) -> None:
        """The audit record is the only place that says which gate was failed.

        Whichever of them refuses, the caller is told "credentials" and nothing
        else, deliberately and permanently. So an investigator reconstructing an
        attempt has the reason column and the outcome column, and that makes
        these strings a contract rather than an implementation detail. Renaming
        one, or moving a branch from DENIED to FAILURE, changes what a saved
        query matches and what an alert fires on. Nothing that merely asserts a
        record was written would notice.

        The distinction between the two outcomes carries the weight here.
        FAILURE is a name that did not resolve or a password that did not match;
        DENIED is an account that exists and is turned away anyway. Collapsing
        them would still leave every refusal audited and every test about
        refusing green.

        Asserted as literals rather than through ``Outcome`` and the reason
        constants the service uses, because the stored string is the thing being
        pinned. Reading a value back out of the same enum the writer used would
        keep passing through a rename, which is the change most worth catching.
        """
        User.objects.create_user(username="ordinary")
        benched = User.objects.create_user(username="benched", is_active=False)
        BreakGlassAccount.objects.create(user=benched, reason="incident response")

        if outcome == "success":
            authenticate_break_glass(username=username, password=password)
        else:
            with pytest.raises(BreakGlassDenied) as refusal:
                authenticate_break_glass(username=username, password=password)
            assert refusal.value.reason == "credentials"

        # One record per attempt, not merely one that matches. A branch that
        # recorded twice would still satisfy a filter on the pair below.
        written = [
            (record.outcome, record.reason)
            for record in AuditEvent.objects.filter(event_type=Event.PROTOCOL_FALLBACK).order_by(
                "id"
            )
        ]
        assert written == [(outcome, reason)]


class TestLifecycleExemption:
    def test_a_flagged_account_is_recognised(self, operator) -> None:
        """Directory sync must skip these. An emergency account deactivated by
        the nightly reconciliation is one that will not work in the
        emergency."""
        assert is_break_glass(operator) is True

    def test_an_ordinary_account_is_not(self) -> None:
        assert is_break_glass(User.objects.create_user(username="ordinary")) is False


class TestLastAccountGuard:
    def test_the_only_account_cannot_be_deleted(self, operator) -> None:
        with pytest.raises(LastBreakGlassAccount):
            BreakGlassAccount.objects.get(user=operator).delete()

    def test_one_of_two_can_be_deleted(self, operator) -> None:
        spare = User.objects.create_user(username="spare", password="x")
        BreakGlassAccount.objects.create(user=spare, reason="second")
        BreakGlassAccount.objects.get(user=operator).delete()
        assert BreakGlassAccount.objects.active().count() == 1


class TestView:
    def test_it_404s_when_disabled(self, client: Client) -> None:
        """A disabled emergency endpoint should not advertise itself."""
        assert client.get("/sso/break-glass/").status_code == 404

    def test_the_form_renders_when_enabled(self, client: Client, enabled) -> None:
        response = client.get("/sso/break-glass/")
        assert response.status_code == 200
        assert b"bypasses single sign-on" in response.content

    def test_a_good_credential_signs_in(self, client: Client, enabled, operator) -> None:
        response = client.post(
            "/sso/break-glass/",
            {"username": "firefighter", "password": "a-real-password"},
        )
        assert response.status_code == 302
        assert client.session.get("_auth_user_id")

    def test_the_session_is_marked(self, client: Client, enabled, operator) -> None:
        client.post(
            "/sso/break-glass/",
            {"username": "firefighter", "password": "a-real-password"},
        )
        assert client.session.get("bastion_break_glass") is True

    def test_a_bad_credential_returns_401(self, client: Client, enabled, operator) -> None:
        response = client.post(
            "/sso/break-glass/", {"username": "firefighter", "password": "wrong"}
        )
        assert response.status_code == 401

    def test_repeated_failures_never_lock_the_account(
        self, client: Client, enabled, operator
    ) -> None:
        """Locking the fire escape is the denial of service.

        Failures do throttle the address they came from, but the account itself
        is never locked, so the same credentials still work from somewhere else.
        Without that split, anyone who can reach this form could disable
        emergency access during the outage it exists for.
        """
        for _ in range(10):
            client.post(
                "/sso/break-glass/",
                {"username": "firefighter", "password": "wrong"},
                REMOTE_ADDR="203.0.113.7",
            )

        blocked = client.post(
            "/sso/break-glass/",
            {"username": "firefighter", "password": "a-real-password"},
            REMOTE_ADDR="203.0.113.7",
        )
        assert blocked.status_code == 401, "the flooded address should be refused"

        elsewhere = client.post(
            "/sso/break-glass/",
            {"username": "firefighter", "password": "a-real-password"},
            REMOTE_ADDR="198.51.100.4",
        )
        assert elsewhere.status_code == 302, "the account was locked, not just the address"


class TestCommand:
    def test_check_fails_when_disabled(self) -> None:
        with pytest.raises(CommandError, match="not enabled"):
            run("check")

    def test_check_fails_without_accounts(self, enabled) -> None:
        with pytest.raises(CommandError):
            run("check")

    def test_check_warns_about_a_single_account(self, enabled, operator) -> None:
        assert "recommended minimum" in run("check")

    def test_check_passes_with_two_validated_accounts(self, settings, operator) -> None:
        # A network allowlist too: leaving it empty is legitimate but produces
        # a warning, and a fully clean run is what this asserts.
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": [SINK],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }
        spare = User.objects.create_user(username="spare", password="x")
        BreakGlassAccount.objects.create(
            user=spare, reason="second", last_validated_at=timezone.now()
        )
        BreakGlassAccount.objects.filter(user=operator).update(last_validated_at=timezone.now())
        assert "all validated" in run("check")

    def test_check_warns_about_an_open_network_allowlist(self, enabled, operator) -> None:
        assert "reachable from anywhere" in run("check")

    def test_grant_requires_a_reason(self, enabled) -> None:
        User.objects.create_user(username="candidate", password="x")
        with pytest.raises(CommandError, match="reason"):
            run("grant", "--user", "candidate")

    def test_grant_requires_a_usable_password(self, enabled) -> None:
        user = User.objects.create_user(username="candidate")
        user.set_unusable_password()
        user.save()
        with pytest.raises(CommandError, match="usable password"):
            run("grant", "--user", "candidate", "--reason", "why")

    def test_grant_creates_the_account_and_alerts(self, enabled) -> None:
        User.objects.create_user(username="candidate", password="x")
        run("grant", "--user", "candidate", "--reason", "incident response")
        assert BreakGlassAccount.objects.filter(user__username="candidate").exists()
        assert ALERTS

    def test_revoke_refuses_the_last_account(self, enabled, operator) -> None:
        with pytest.raises(LastBreakGlassAccount):
            run("revoke", "--user", "firefighter")

    def test_a_drill_records_validation_and_alerts(self, enabled, operator) -> None:
        output = run("drill", "--user", "firefighter")
        assert ALERTS, "a drill that does not confirm the alarm rings tests half of it"
        assert BreakGlassAccount.objects.get(user=operator).last_validated_at
        assert "Confirm before treating this as passed" in output

    def test_list_shows_accounts(self, enabled, operator) -> None:
        assert "firefighter" in run("list")


class TestNetworkParsingInIsolation:
    """``_network_allows`` is called with an address the caller has already
    normalised, so these paths are defence in depth rather than reachable from
    the view — and defence in depth that nothing exercises is decoration."""

    @pytest.fixture(autouse=True)
    def _restricted(self, settings):
        settings.BASTION = {
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": [SINK],
                "ALLOWED_NETWORKS": ["10.0.0.0/8"],
            }
        }

    def test_an_address_in_range_is_allowed(self) -> None:
        from bastion.breakglass.service import _network_allows

        assert _network_allows("10.1.2.3")

    def test_a_string_that_is_not_an_address_fails_closed(self) -> None:
        """The direction to fail in: an allowlist exists, and this is not a
        member of it."""
        from bastion.breakglass.service import _network_allows

        assert not _network_allows("not-an-address")

    def test_no_address_fails_closed(self) -> None:
        from bastion.breakglass.service import _network_allows

        assert not _network_allows(None)

    def test_an_empty_allowlist_admits_everything(self, settings) -> None:
        """Documented, warned about by bastion.W032, and not silently applied."""
        from bastion.breakglass.service import _network_allows

        settings.BASTION = {"BREAK_GLASS": {"ENABLED": True, "ALLOWED_NETWORKS": []}}
        assert _network_allows(None)
