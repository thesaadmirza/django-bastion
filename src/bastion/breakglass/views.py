"""The emergency login view.

Served at a configurable path, off by default, and reachable only from the
configured networks. Deliberately plain: no branding to phish, no password
reset, no account discovery, and no lockout.

Lockout is the notable omission. Every other login path in this package should
lock out; this one must not, because locking the fire escape is itself the
denial of service. Failures alert instead.
"""

from __future__ import annotations

import logging

from django.contrib.auth import login as auth_login
from django.contrib.auth.decorators import login_not_required
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods

from bastion.breakglass.service import BreakGlassDenied, authenticate_break_glass
from bastion.conf import get_setting
from bastion.flows import correlation_id
from bastion.pages import base_template

logger = logging.getLogger(__name__)


@never_cache
@login_not_required
@sensitive_post_parameters("password")
@require_http_methods(["GET", "POST"])
def break_glass_login(request: HttpRequest) -> HttpResponse:
    config = get_setting("BREAK_GLASS")
    reference = correlation_id()

    if not config.get("ENABLED"):
        # Indistinguishable from a route that does not exist, because a
        # disabled emergency endpoint should not advertise itself.
        return render(
            request,
            "bastion/login_failed.html",
            {"reference": reference, "base_template": base_template()},
            status=404,
        )

    context = {"reference": reference, "error": None, "base_template": base_template()}

    if request.method == "POST":
        try:
            user = authenticate_break_glass(
                username=request.POST.get("username", ""),
                password=request.POST.get("password", ""),
                request=request,
            )
        except BreakGlassDenied:
            # One message for every cause. Which gate was failed is in the
            # audit record, not on the page.
            context["error"] = "Sign-in failed."
            return render(request, "bastion/break_glass.html", context, status=401)

        request.session.flush()
        auth_login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        request.session["bastion_break_glass"] = True

        destination = config.get("SUCCESS_URL") or "/admin/"
        response = HttpResponseRedirect(destination)
        response["Referrer-Policy"] = "no-referrer"
        return response

    return render(request, "bastion/break_glass.html", context)
