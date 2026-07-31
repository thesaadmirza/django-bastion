"""Base-template resolution for the four rendered pages.

Two properties, and they pull in opposite directions.

**The admin base must be used wherever it can be**, because the package is mostly
used to put the admin behind SSO and a foreign-looking 403 in the middle of the
admin is the thing people notice first.

**It must never be extended where it cannot work.** ``bastion.urls`` is designed
for a project protecting a normal site, and there ``admin/base_site.html`` is
either absent (``TemplateDoesNotExist``) or present but unroutable
(``NoReverseMatch`` from its branding block). Either one turns an error page into
a 500, which is the worst possible place for one.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.template.loader import get_template, render_to_string
from django.test import Client

from bastion.pages import ADMIN_BASE, FALLBACK_BASE, admin_base_is_usable, base_template

pytestmark = pytest.mark.django_db

User = get_user_model()

PAGES = (
    "bastion/access_denied.html",
    "bastion/login_failed.html",
    "bastion/logged_out.html",
    "bastion/break_glass.html",
)

#: Enough to render any of them. Missing keys are fine; the point is that no
#: page depends on a variable a caller might not pass.
CONTEXT = {
    "reference": "AAAA-BBBB",
    "identity": "nobody@example.test",
    "required_groups": ("django-staff",),
    "error": "Sign-in failed.",
    "provider_session_ended": False,
    "logout_url": "/admin/logout/",
}


@pytest.fixture
def sso_configured(settings):
    settings.BASTION = {
        "CONNECTIONS": {"corp": {"issuer": "https://idp.example.test", "client_id": "cid"}}
    }


@pytest.fixture
def plain_user():
    user = User.objects.create_user(username="nobody", email="nobody@example.test")
    user.set_unusable_password()
    user.save()
    return user


class TestResolution:
    def test_the_admin_base_is_used_when_installed_and_routed(self) -> None:
        assert admin_base_is_usable()
        assert base_template() == ADMIN_BASE

    def test_an_uninstalled_admin_falls_back(self, settings) -> None:
        settings.INSTALLED_APPS = [
            app for app in settings.INSTALLED_APPS if app != "bastion.admin.apps.BastionAdminConfig"
        ]
        assert base_template() == FALLBACK_BASE

    def test_an_unrouted_admin_falls_back(self, settings) -> None:
        """Installed but not included in urls.py.

        base_site.html reverses admin:index in its branding block, so extending
        it here would raise NoReverseMatch and turn a 403 into a 500. A project
        that disables the admin in one environment hits exactly this.
        """
        settings.ROOT_URLCONF = "tests.empty_urls"
        assert admin_base_is_usable() is False
        assert base_template() == FALLBACK_BASE

    def test_it_is_not_cached_across_a_settings_change(self, settings) -> None:
        """Caching would make a test that changes the admin see a stale answer.

        That is the failure mode which is order dependent and only shows up in
        CI, so the resolution stays a live check.
        """
        assert base_template() == ADMIN_BASE
        settings.ROOT_URLCONF = "tests.empty_urls"
        assert base_template() == FALLBACK_BASE


class TestEveryPageRendersUnderEitherBase:
    """These are reached by someone having a bad day.

    Which is the worst time to find a TemplateSyntaxError, and the reason they
    are rendered here rather than trusted.
    """

    @pytest.mark.parametrize("name", PAGES)
    def test_it_parses(self, name: str) -> None:
        assert get_template(name)

    @pytest.mark.parametrize("name", PAGES)
    def test_under_the_admin_base(self, name: str) -> None:
        body = render_to_string(name, {**CONTEXT, "base_template": ADMIN_BASE})
        assert "admin/css/base.css" in body

    @pytest.mark.parametrize("name", PAGES)
    def test_under_the_fallback_base(self, name: str) -> None:
        body = render_to_string(name, {**CONTEXT, "base_template": FALLBACK_BASE})
        assert "admin/css/base.css" not in body
        assert "<!doctype html>" in body.lower()

    @pytest.mark.parametrize("name", PAGES)
    def test_with_no_base_template_in_the_context_at_all(self, name: str) -> None:
        """The ``|default:`` in the extends tag is the safety net.

        A third-party view rendering one of these by name, or a caller added
        later that forgets the key, must get a page rather than a
        TemplateDoesNotExist for the empty string.
        """
        assert render_to_string(name, CONTEXT)


class TestNoLeakedTemplateSyntax:
    """A multi-line ``{# ... #}`` is not a comment.

    The single-hash form is single-line only, so a multi-line one renders as
    visible text. Caught once by eye on a real page; caught here from now on.
    """

    @pytest.mark.parametrize("name", PAGES)
    @pytest.mark.parametrize("base", [ADMIN_BASE, FALLBACK_BASE])
    def test_no_markers_survive_rendering(self, name: str, base: str) -> None:
        body = render_to_string(name, {**CONTEXT, "base_template": base})
        assert "{#" not in body
        assert "{%" not in body
        assert "{{" not in body


class TestTheViewsPassIt:
    @pytest.mark.usefixtures("sso_configured")
    def test_the_denial_page_looks_like_the_admin(self, client: Client, plain_user) -> None:
        client.force_login(plain_user, backend="bastion.backends.SSOBackend")
        response = client.get("/admin/login/")

        assert response.status_code == 403
        assert b"admin/css/base.css" in response.content

    @pytest.mark.usefixtures("sso_configured")
    def test_the_denial_page_still_names_what_it_must(self, client: Client, plain_user) -> None:
        """Restyling must not quietly drop what the page is for."""
        client.force_login(plain_user, backend="bastion.backends.SSOBackend")
        body = client.get("/admin/login/").content

        assert b"nobody@example.test" in body, "must name the account used"
        assert b"do not have access" in body
        assert b"django-staff" not in body or b"membership of" in body

    @pytest.mark.usefixtures("sso_configured")
    def test_the_callback_failure_page_looks_like_the_admin(self, client: Client) -> None:
        response = client.get("/sso/callback/?state=bogus&code=bogus")

        assert response.status_code == 400
        assert b"admin/css/base.css" in response.content
        assert b"could not sign you in" in response.content

    def test_the_break_glass_page_looks_like_the_admin(self, client: Client, settings) -> None:
        settings.BASTION = {
            "CONNECTIONS": {"corp": {"issuer": "https://idp.example.test", "client_id": "cid"}},
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["bastion.breakglass.service.log_only_sink"],
            },
        }
        response = client.get("/sso/break-glass/")

        assert response.status_code == 200
        assert b"admin/css/base.css" in response.content
        assert b"bypasses single sign-on" in response.content

    def test_break_glass_keeps_its_critical_styles_inline(self, client: Client, settings) -> None:
        """The one page reached *during* an incident.

        Under the admin base its layout comes from a stylesheet, and a
        collectstatic that never ran or a CDN that is also down is a real
        possibility at that moment. The inline block is what keeps the warning
        legible and the fields usable without it.
        """
        settings.BASTION = {
            "CONNECTIONS": {"corp": {"issuer": "https://idp.example.test", "client_id": "cid"}},
            "BREAK_GLASS": {
                "ENABLED": True,
                "ALERT_SINKS": ["bastion.breakglass.service.log_only_sink"],
            },
        }
        body = client.get("/sso/break-glass/").content.decode()

        assert "<style>" in body, "no inline styles survived"
        inline = body.split("<style>", 1)[1].split("</style>")[0]
        assert "errornote" in inline, "the warning would be indistinguishable without CSS"
        assert "min-height" in inline, "the fields would be unusably small on a phone"


class TestNonAdminProjects:
    """The reason the fallback exists at all."""

    @pytest.mark.usefixtures("sso_configured")
    def test_the_failure_page_does_not_500_without_a_routed_admin(
        self, client: Client, settings
    ) -> None:
        settings.ROOT_URLCONF = "tests.urls_no_admin"
        response = client.get("/sso/callback/?state=bogus&code=bogus")

        assert response.status_code == 400, "an error page must not become a 500"
        assert b"admin/css/base.css" not in response.content
        assert b"could not sign you in" in response.content
