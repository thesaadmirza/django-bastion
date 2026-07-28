"""Admin integration.

The property under test throughout is **termination**. Every class of request
must reach a page or leave the application within a bounded number of hops.
Getting this wrong produces a redirect loop rather than an error, and a loop is
far harder to diagnose than a 403 -- which is why each test counts hops rather
than merely asserting a final status.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

from bastion.admin.site import SSOAdminSite
from bastion.models import FederatedIdentity

pytestmark = pytest.mark.django_db

User = get_user_model()

CONNECTIONS = {"corp": {"issuer": "https://idp.example.test", "client_id": "cid"}}


@pytest.fixture
def sso_configured(settings):
    """Configure one connection.

    A fixture rather than a class-level override_settings decorator, which
    Django accepts only on SimpleTestCase subclasses.
    """
    settings.BASTION = {"CONNECTIONS": CONNECTIONS}


#: Following past this would enter the login flow proper, which means a real
#: network call to a provider that does not exist. The admin's responsibility
#: ends at the handoff; what happens after it is tests/test_login_flow.py.
HANDOFF = "/sso/"


def follow(client: Client, url: str, limit: int = 6) -> tuple[Any, list[str]]:
    """Walk redirects by hand so a loop is a failed assertion, not a hang."""
    seen: list[str] = []
    for _ in range(limit):
        response = client.get(url)
        if response.status_code not in (301, 302):
            return response, seen
        url = response["Location"]
        if url in seen:
            pytest.fail(f"redirect loop: {[*seen, url]}")
        seen.append(url)
        if not url.startswith("/") or url.startswith(HANDOFF):
            return response, seen
    pytest.fail(f"still redirecting after {limit} hops: {seen}")


@pytest.fixture
def staff_user():
    user = User.objects.create_user(username="staffer", email="staff@example.test")
    user.is_staff = True
    user.set_unusable_password()
    user.save()
    return user


@pytest.fixture
def plain_user():
    user = User.objects.create_user(username="nobody", email="nobody@example.test")
    user.set_unusable_password()
    user.save()
    return user


class TestSiteInstallation:
    def test_the_default_site_is_ours(self) -> None:
        """AdminConfig.default_site did its job. Instantiating an AdminSite in
        urls.py instead would silently lose every registered model."""
        assert isinstance(admin.site, SSOAdminSite)

    def test_the_model_registry_survived_the_substitution(self) -> None:
        assert reverse("admin:bastion_federatedidentity_changelist")

    def test_admin_urls_still_reverse(self) -> None:
        assert reverse("admin:index")
        assert reverse("admin:login")
        assert reverse("admin:logout")

    def test_the_app_label_form_resolves_to_our_config(self) -> None:
        """``"bastion.admin"`` must work, not only the dotted config path.

        Django scans the module for AppConfig subclasses and treats every one
        with a truthy ``default`` as a candidate. Our config inherits ``default``
        from Django's ``AdminConfig``, so before this was pinned down the short
        form raised "declares more than one default AppConfig" and named a
        Django class the reader never configured.
        """
        from django.apps import AppConfig

        from bastion.admin.apps import BastionAdminConfig

        resolved = AppConfig.create("bastion.admin")
        assert isinstance(resolved, BastionAdminConfig)

    def test_the_base_config_is_not_a_module_level_candidate(self) -> None:
        """What makes the line above work is that the imported base is not left
        in the module namespace for Django's scan to find."""
        from bastion.admin import apps

        assert not hasattr(apps, "AdminConfig")


@pytest.mark.usefixtures("sso_configured")
class TestAnonymous:
    def test_an_anonymous_visit_reaches_the_provider_redirect(self, client: Client) -> None:
        _, hops = follow(client, "/admin/")
        assert any("/sso/login/" in hop for hop in hops)

    def test_the_original_destination_is_preserved(self, client: Client) -> None:
        _, hops = follow(client, "/admin/bastion/federatedidentity/")
        sso_hop = next(h for h in hops if "/sso/login/" in h)
        forwarded = parse_qs(urlparse(sso_hop).query)["next"][0]
        assert "federatedidentity" in forwarded

    def test_the_admin_login_page_itself_terminates(self, client: Client) -> None:
        _, hops = follow(client, "/admin/login/")
        assert any("/sso/login/" in hop for hop in hops)

    def test_no_password_form_is_served(self, client: Client) -> None:
        response = client.get("/admin/login/")
        assert response.status_code == 302
        assert b"password" not in response.content.lower()


@pytest.mark.usefixtures("sso_configured")
class TestLoginRequiredMiddleware:
    """Added in Django 5.1, and it breaks SSO login views by default.

    The middleware bounces anonymous requests to ``LOGIN_URL`` unless the view
    carries ``login_required = False``. Applied to a login view, that means
    anonymous users are redirected away from the one endpoint that could sign
    them in. Django's own ``AdminSite.login`` carries the exemption; replacing
    the method drops it unless it is re-applied, which is silent until someone
    enables the middleware.
    """

    @pytest.fixture(autouse=True)
    def _enable(self, settings) -> None:
        settings.MIDDLEWARE = [
            *settings.MIDDLEWARE,
            "django.contrib.auth.middleware.LoginRequiredMiddleware",
        ]
        settings.LOGIN_URL = "/sso/login/"

    def test_the_admin_login_still_hands_off(self, client: Client) -> None:
        _, hops = follow(client, "/admin/login/")
        assert any(hop.startswith(HANDOFF) for hop in hops)

    def test_an_anonymous_admin_visit_still_terminates(self, client: Client) -> None:
        _, hops = follow(client, "/admin/")
        assert any(hop.startswith(HANDOFF) for hop in hops)

    def test_the_view_declares_the_exemption(self) -> None:
        assert getattr(admin.site.login, "login_required", True) is False


@pytest.mark.usefixtures("sso_configured")
class TestAuthenticatedWithoutStaff:
    def test_the_request_terminates_in_a_403(self, client: Client, plain_user) -> None:
        """The trap: admin_view tests staff, a naive SSO login view tests
        authenticated, the predicates disagree, and neither terminates."""
        client.force_login(plain_user, backend="bastion.backends.SSOBackend")
        response, _ = follow(client, "/admin/")
        assert response.status_code == 403

    def test_the_page_names_the_account_used(self, client: Client, plain_user) -> None:
        client.force_login(plain_user, backend="bastion.backends.SSOBackend")
        response, _ = follow(client, "/admin/")
        assert b"nobody@example.test" in response.content

    def test_the_page_carries_a_reference(self, client: Client, plain_user) -> None:
        import re

        client.force_login(plain_user, backend="bastion.backends.SSOBackend")
        response, _ = follow(client, "/admin/")
        assert re.search(rb"[0-9A-F]{4}-[0-9A-F]{4}", response.content)

    def test_the_page_offers_a_post_sign_out(self, client: Client, plain_user) -> None:
        """Django's LogoutView is POST-only, so an anchor to it is a dead
        link."""
        client.force_login(plain_user, backend="bastion.backends.SSOBackend")
        response, _ = follow(client, "/admin/")
        assert b'method="post"' in response.content
        assert b"/admin/logout/" in response.content

    def test_a_deactivated_staff_user_is_handed_back_to_the_provider(
        self, client: Client, staff_user
    ) -> None:
        """Deactivation drops the session on the next request, via
        ``get_user``. From the admin's point of view the person is anonymous
        again, so the correct outcome is a handoff, not a 403."""
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        User.objects.filter(pk=staff_user.pk).update(is_active=False)
        _, hops = follow(client, "/admin/")
        assert any(hop.startswith(HANDOFF) for hop in hops)


@pytest.mark.usefixtures("sso_configured")
class TestAuthorised:
    def test_a_staff_user_reaches_the_index(self, client: Client, staff_user) -> None:
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        response, _ = follow(client, "/admin/")
        assert response.status_code == 200

    def test_visiting_the_login_page_redirects_into_the_admin(
        self, client: Client, staff_user
    ) -> None:
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        response = client.get("/admin/login/")
        assert response.status_code == 302
        assert response["Location"] == reverse("admin:index")

    def test_the_next_parameter_is_honoured(self, client: Client, staff_user) -> None:
        """Django 6.1 changed AdminSite.login to honour next. Reading the
        parameter directly gives that behaviour on 5.2 and 6.0 too, without
        version sniffing."""
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        target = "/admin/bastion/federatedidentity/"
        response = client.get(f"/admin/login/?next={target}")
        assert response["Location"] == target

    def test_a_hostile_next_falls_back_to_the_index(self, client: Client, staff_user) -> None:
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        response = client.get("/admin/login/?next=https://evil.test/")
        assert response["Location"] == reverse("admin:index")


class TestDisabled:
    def test_without_connections_the_stock_login_is_served(self, client: Client, settings) -> None:
        """A project that installed the app but has not configured it yet must
        still be able to reach its admin."""
        settings.BASTION = {"CONNECTIONS": {}}
        response = client.get("/admin/login/")
        assert response.status_code == 200
        assert b"password" in response.content.lower()

    def test_the_integration_can_be_turned_off(self, client: Client, settings) -> None:
        settings.BASTION = {"CONNECTIONS": CONNECTIONS, "ADMIN": {"enabled": False}}
        response = client.get("/admin/login/")
        assert response.status_code == 200


class TestIdentityAdmin:
    def test_identities_cannot_be_created_by_hand(self, client: Client, staff_user) -> None:
        """A hand-made row asserts that a person at a provider is a given local
        user, which is the claim the whole verification chain exists to make."""
        staff_user.is_superuser = True
        staff_user.save()
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        response = client.get("/admin/bastion/federatedidentity/add/")
        assert response.status_code == 403

    def test_identities_cannot_be_edited(self, client: Client, staff_user) -> None:
        identity = FederatedIdentity.objects.create(
            user=staff_user,
            issuer="https://idp.example.test",
            subject="s",
            subject_source="sub",
            connection="corp",
        )
        staff_user.is_superuser = True
        staff_user.save()
        client.force_login(staff_user, backend="bastion.backends.SSOBackend")
        response = client.get(f"/admin/bastion/federatedidentity/{identity.pk}/change/")
        # Django serves a read-only view rather than 403 when change is denied
        # but view permission is held; either way no form is submittable.
        assert b'name="subject"' not in response.content


@pytest.mark.usefixtures("sso_configured")
class TestDecoratorAlternative:
    def test_the_wrapper_preserves_the_middleware_exemption(self) -> None:
        """functools.wraps copies __dict__, which carries login_required=False
        from the original view. That is what keeps the wrapped view exempt from
        LoginRequiredMiddleware."""
        from bastion.admin.decorators import sso_admin_login

        def fake_login(request):  # pragma: no cover - never called here
            raise AssertionError

        fake_login.login_required = False  # type: ignore[attr-defined]
        wrapped = sso_admin_login(fake_login)
        assert getattr(wrapped, "login_required", True) is False

    def test_the_wrapper_redirects_anonymous_users(self, rf) -> None:
        from django.contrib.auth.models import AnonymousUser

        from bastion.admin.decorators import sso_admin_login

        def fake_login(request):  # pragma: no cover - not reached
            raise AssertionError("stock login should not run for anonymous users")

        request = rf.get("/admin/login/")
        request.user = AnonymousUser()
        response = sso_admin_login(fake_login)(request)
        assert response.status_code == 302
        assert "/sso/login/" in response["Location"]
