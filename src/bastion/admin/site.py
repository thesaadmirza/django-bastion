"""An ``AdminSite`` whose login goes through the identity provider.

The whole problem in one sentence: ``AdminSite.admin_view`` hard-codes
``reverse("admin:login")`` as its redirect target, and ``settings.LOGIN_URL``
appears nowhere in ``django/contrib/admin`` in any version from 5.2 to main. So
the only way to change what happens at login is to change what the view behind
that name does.

**The login view must be a terminal state for every class of request.** That is
the property everything here is arranged around, because getting it wrong
produces a redirect loop rather than an error, and a loop is much harder to
diagnose than a 403. Two loops are easy to write:

1. Wrapping the admin login in ``login_required`` with ``LOGIN_URL`` pointing
   at the admin login. The decorator sends anonymous users to the very view
   that is wrapped, re-encoding ``next`` on each hop.
2. An SSO login view that bounces already-authenticated users to ``next``.
   ``admin_view`` tests *staff*; that view tests *authenticated*. The two
   predicates disagree and neither side terminates.

So: anonymous starts SSO, authorised redirects into the admin, and everything
else renders a page. Never a redirect.
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib.admin import AdminSite
from django.contrib.auth.decorators import login_not_required
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import NoReverseMatch, reverse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache

from bastion.conf import get_setting
from bastion.flows import correlation_id
from bastion.pages import ADMIN_BASE
from bastion.redirects import safe_redirect_url

logger = logging.getLogger(__name__)

REDIRECT_FIELD_NAME = "next"


class SSOAdminSiteMixin:
    """Mix into an existing ``AdminSite`` subclass.

    Use ``SSOAdminSite`` directly unless you already have a custom site.
    """

    #: Which configured connection the admin uses. ``None`` means the single
    #: configured one, and is an error if there is more than one.
    sso_connection: str | None = None

    # ------------------------------------------------------------------ login --

    @method_decorator(never_cache)
    @login_not_required
    def login(
        self, request: HttpRequest, extra_context: dict[str, Any] | None = None
    ) -> HttpResponse:
        """Replace the admin's form login.

        ``login_not_required`` matters: ``LoginRequiredMiddleware`` would
        otherwise bounce anonymous users away from the one endpoint that can
        sign them in. Django's own ``AdminSite.login`` carries it, and
        replacing the attribute drops it unless it is re-applied.
        """
        if not self._sso_enabled():
            stock: HttpResponse = super().login(request, extra_context)  # type: ignore[misc]
            return stock

        if request.user.is_authenticated:
            if not self.has_permission(request):  # type: ignore[attr-defined]
                # Terminal. Not a redirect, because the only place to redirect
                # to is here.
                return self.render_access_denied(request)
            return HttpResponseRedirect(self._success_url(request))

        return HttpResponseRedirect(self._sso_url(request))

    # ----------------------------------------------------------------- logout --

    @method_decorator(never_cache)
    @login_not_required
    def logout(
        self, request: HttpRequest, extra_context: dict[str, Any] | None = None
    ) -> HttpResponse:
        """Send the admin's own Log out button through the provider.

        Without this the button is Django's, which clears the local session and
        stops. The provider's session cookie survives, so the next click on the
        admin is answered with a fresh authorization code and no prompt, and the
        person who pressed Log out on a shared machine is still signed in. That
        is the single most surprising thing about putting an admin behind SSO,
        and the button is where it has to be fixed: telling people to visit a
        different URL to really sign out is not a fix.

        Non-POST is handed to Django's implementation rather than answered here,
        so its 405 and its behaviour when logout is not permitted stay exactly
        as Django defines them.
        """
        if request.method != "POST" or not self._sso_enabled():
            stock: HttpResponse = super().logout(request, extra_context)  # type: ignore[misc]
            return stock

        from bastion.views import logout as sso_logout

        return sso_logout(request)

    # ------------------------------------------------------------------- urls --

    def _success_url(self, request: HttpRequest) -> str:
        """Where an already-authorised person lands.

        Django 6.1 changed ``AdminSite.login`` to honour ``next`` instead of
        always going to the index, using ``RedirectURLMixin.get_redirect_url``
        with a request argument that does not exist on 5.2 or 6.0. Reading the
        parameter directly gives the 6.1 behaviour on every supported version
        without version sniffing.
        """
        requested = request.POST.get(REDIRECT_FIELD_NAME) or request.GET.get(REDIRECT_FIELD_NAME)
        index = reverse("admin:index", current_app=self.name)  # type: ignore[attr-defined]
        return safe_redirect_url(requested, request=request, fallback=index)

    def _sso_url(self, request: HttpRequest) -> str:
        requested = request.GET.get(REDIRECT_FIELD_NAME)
        index = reverse("admin:index", current_app=self.name)  # type: ignore[attr-defined]
        destination = safe_redirect_url(requested, request=request, fallback=index)

        connection = self._connection_name()
        if connection:
            begin = reverse("bastion:begin-connection", kwargs={"connection": connection})
        else:
            begin = reverse("bastion:begin")
        return f"{begin}?{REDIRECT_FIELD_NAME}={destination}"

    # ----------------------------------------------------------------- denial --

    def render_access_denied(self, request: HttpRequest) -> HttpResponse:
        """The page a signed-in person without access actually sees.

        Deliberately specific. Identity is proven at this point, so there is no
        account to enumerate and no reason to withhold anything. Being vague
        here is the most common usability failure in enterprise SSO: the person
        is told "access denied" and cannot tell which account they used, which
        group they are missing, or who to ask. All three are on this page.
        """
        reference = correlation_id()
        logger.info("Admin access denied for %s [ref %s]", request.user.get_username(), reference)

        try:
            logout_url = reverse("admin:logout", current_app=self.name)  # type: ignore[attr-defined]
        except NoReverseMatch:  # pragma: no cover - admin urls are always present
            logout_url = None

        response = render(
            request,
            "bastion/access_denied.html",
            {
                # Always the admin base here: this method is only reachable
                # through AdminSite, so the app is installed and routed.
                "base_template": ADMIN_BASE,
                "reference": reference,
                "identity": getattr(request.user, "email", "") or request.user.get_username(),
                "required_groups": self._required_groups(),
                "logout_url": logout_url,
            },
            status=403,
        )
        response["Referrer-Policy"] = "no-referrer"
        return response

    # ----------------------------------------------------------------- config --

    def _admin_settings(self) -> dict[str, Any]:
        settings: dict[str, Any] = get_setting("ADMIN")
        return settings

    def _sso_enabled(self) -> bool:
        if not self._admin_settings().get("enabled", True):
            return False
        return bool(get_setting("CONNECTIONS"))

    def _connection_name(self) -> str | None:
        configured = self.sso_connection or self._admin_settings().get("connection")
        if configured:
            return str(configured)
        connections: dict[str, Any] = get_setting("CONNECTIONS")
        if len(connections) == 1:
            return str(next(iter(connections)))
        return None

    def _required_groups(self) -> tuple[str, ...]:
        """Group names to name on the denial page, if any are configured."""
        from bastion.connections import get_connection

        name = self._connection_name()
        if not name:
            return ()
        try:
            connection = get_connection(name)
        except Exception:
            return ()
        return connection.staff_groups + connection.superuser_groups


# The ignore is on ``logout`` only. django-stubs types AdminSite.logout as
# returning TemplateResponse, which is narrower than Django's own contract:
# the body is LogoutView.as_view()(request), and for a POST carrying next_page
# that is an HttpResponseRedirect. Our override returns a redirect or a rendered
# page, both HttpResponse, so the conflict is with the stub rather than with
# Django. Same narrowing as SSOBackend.get_user, documented there too.
class SSOAdminSite(SSOAdminSiteMixin, AdminSite):  # type: ignore[misc]
    """Drop-in replacement for ``django.contrib.admin.site``.

    Installed through ``AdminConfig.default_site`` rather than by instantiating
    it in ``urls.py``. The substitution has to happen in ``AppConfig.ready()``,
    before ``autodiscover_modules('admin')`` populates the registry, or every
    registered model is silently lost.
    """
