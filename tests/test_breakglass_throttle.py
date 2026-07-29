"""Throttling the emergency login.

Two properties matter more than the throttle firing at all, and both are here:
it must key on the source address rather than the account, and it must let go
on its own. Get either wrong and the control becomes a way to switch off the
route it is protecting.
"""

from __future__ import annotations

import datetime as dt

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from bastion.audit.models import AuditEvent
from bastion.breakglass.models import BreakGlassAccount
from bastion.breakglass.service import BreakGlassDenied, authenticate_break_glass

PASSWORD = "correct-horse-battery-staple-for-the-drill"


@pytest.fixture(autouse=True)
def _enabled(settings):
    settings.BASTION = {
        "BREAK_GLASS": {
            "ENABLED": True,
            "ALERT_SINKS": ["bastion.breakglass.service.log_only_sink"],
            "ALLOWED_NETWORKS": [],
            "MAX_FAILURES_PER_IP": 3,
            "FAILURE_WINDOW_SECONDS": 900,
        },
        "AUDIT": {"SINKS": ["bastion.audit.sinks.DatabaseSink"]},
    }


@pytest.fixture
def account(db):
    user = get_user_model().objects.create_user(username="rescue")
    user.set_password(PASSWORD)
    user.is_staff = True
    user.save()
    BreakGlassAccount.objects.create(user=user, reason="drill")
    return user


def attempt(rf, password: str, ip: str = "10.0.0.5", username: str = "rescue"):
    request = rf.post("/", REMOTE_ADDR=ip)
    return authenticate_break_glass(username=username, password=password, request=request)


def fail(rf, times: int, ip: str = "10.0.0.5") -> None:
    for _ in range(times):
        with pytest.raises(BreakGlassDenied):
            attempt(rf, "wrong-password", ip=ip)


@pytest.mark.django_db
class TestThrottleFires:
    def test_the_right_password_works_before_the_limit(self, rf, account) -> None:
        fail(rf, 2)
        assert attempt(rf, PASSWORD).username == "rescue"

    def test_the_address_is_refused_once_the_limit_is_reached(self, rf, account) -> None:
        fail(rf, 3)
        with pytest.raises(BreakGlassDenied) as caught:
            attempt(rf, PASSWORD)
        assert caught.value.reason == "throttled"

    def test_the_throttle_runs_before_the_password_is_checked(
        self, rf, account, monkeypatch
    ) -> None:
        """A flood should cost the attacker a query, not a KDF round."""
        fail(rf, 3)

        called = []
        monkeypatch.setattr(
            get_user_model(), "check_password", lambda self, raw: called.append(raw) or True
        )
        with pytest.raises(BreakGlassDenied):
            attempt(rf, PASSWORD)
        assert called == []

    def test_a_refusal_is_audited(self, rf, account) -> None:
        fail(rf, 3)
        with pytest.raises(BreakGlassDenied):
            attempt(rf, PASSWORD)
        assert AuditEvent.objects.filter(reason="throttled").exists()

    def test_unknown_accounts_count_too(self, rf, account) -> None:
        """Otherwise the limit is trivially avoided by varying the username."""
        for index in range(3):
            with pytest.raises(BreakGlassDenied):
                attempt(rf, "wrong-password", username=f"nobody-{index}")
        with pytest.raises(BreakGlassDenied) as caught:
            attempt(rf, PASSWORD)
        assert caught.value.reason == "throttled"


@pytest.mark.django_db
class TestThrottleDoesNotLockTheFireEscape:
    def test_another_address_is_unaffected(self, rf, account) -> None:
        """The property the whole design turns on.

        If failures locked the account rather than the address, anyone able to
        reach this form could disable emergency access by failing against it,
        during the outage it exists for.
        """
        fail(rf, 5, ip="10.0.0.5")
        assert attempt(rf, PASSWORD, ip="10.0.0.99").username == "rescue"

    def test_hammering_does_not_extend_the_window(self, rf, account) -> None:
        """A flood must not hold the window open against whoever shares the
        address.

        Counting refusals would make the throttle self-sustaining: each blocked
        attempt writes a record that keeps it blocked, so an attacker willing to
        keep going locks out the operator indefinitely. Only real credential
        failures age the window.
        """
        fail(rf, 3)
        for _ in range(10):
            with pytest.raises(BreakGlassDenied):
                attempt(rf, "wrong-password")

        # Age out the three genuine failures, leaving the ten refusals recent.
        stale = timezone.now() - dt.timedelta(seconds=1000)
        AuditEvent.objects.exclude(reason="throttled").update(occurred_at=stale)

        assert attempt(rf, PASSWORD).username == "rescue", (
            "refusals kept the window open, so hammering is a lockout"
        )

    def test_the_window_rolls_off(self, rf, account) -> None:
        fail(rf, 3)
        stale = timezone.now() - dt.timedelta(seconds=1000)
        AuditEvent.objects.all().update(occurred_at=stale)
        assert attempt(rf, PASSWORD).username == "rescue"

    def test_a_zero_limit_disables_it(self, rf, account, settings) -> None:
        settings.BASTION["BREAK_GLASS"]["MAX_FAILURES_PER_IP"] = 0
        fail(rf, 6)
        assert attempt(rf, PASSWORD).username == "rescue"

    def test_a_successful_login_does_not_count(self, rf, account) -> None:
        for _ in range(4):
            assert attempt(rf, PASSWORD).username == "rescue"
        assert attempt(rf, PASSWORD).username == "rescue"


@pytest.mark.django_db
class TestThrottleStorageCheck:
    def test_removing_the_database_sink_is_an_error(self, settings) -> None:
        from django.core.management import call_command
        from django.core.management.base import SystemCheckError

        settings.BASTION["AUDIT"]["SINKS"] = ["bastion.audit.sinks.LoggingSink"]
        with pytest.raises(SystemCheckError, match="E101"):
            call_command("check")

    def test_it_is_silent_when_the_throttle_is_off(self, settings) -> None:
        from django.core.management import call_command

        settings.BASTION["AUDIT"]["SINKS"] = ["bastion.audit.sinks.LoggingSink"]
        settings.BASTION["BREAK_GLASS"]["MAX_FAILURES_PER_IP"] = 0
        call_command("check")


@pytest.mark.django_db
def test_the_denial_page_does_not_say_it_was_the_throttle(client, account, rf) -> None:
    """Telling an attacker they hit the limit tells them the limit exists and
    roughly where it sits. The page says the same thing it always says."""
    fail(rf, 3)
    response = client.post(
        "/sso/break-glass/",
        {"username": "rescue", "password": PASSWORD},
        REMOTE_ADDR="10.0.0.5",
    )
    import re

    # Comments stripped, and whole words only: the template explains its own
    # design in a comment, and "deliberately" contains "rate".
    visible = re.sub(r"<!--.*?-->", "", response.content.decode(), flags=re.DOTALL).lower()
    for word in ("throttled", "throttling", "rate limit", "too many", "locked", "try again later"):
        assert not re.search(rf"\b{re.escape(word)}\b", visible), f"page leaks {word!r}"
