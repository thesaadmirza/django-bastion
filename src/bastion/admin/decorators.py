"""The zero-configuration alternative to swapping the admin site.

``AdminConfig.default_site`` is the documented seam and the recommended route.
This exists because it needs no ``INSTALLED_APPS`` edit, works when the project
already has its own ``AdminSite`` instance it would rather not subclass, and is
the pattern django-allauth normalised with ``secure_admin_login``, so people
recognise it.

Apply once, in ``AppConfig.ready()``, after ``admin.autodiscover()``::

    from django.contrib import admin
    from bastion.admin.decorators import sso_admin_login

    admin.site.login = sso_admin_login(admin.site.login)

Two things about that line are easy to get wrong.

It must wrap the **bound** method, as above. Assigning a plain function to
``AdminSite.login`` on the class makes it a bound method and ``self`` lands in
the ``request`` slot, producing ``AttributeError: 'AdminSite' object has no
attribute 'user'`` at the first request.

And it only covers ``admin.site``. A project with several admin sites needs
this applied to each, or the others keep their form login.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps

from django.http import HttpRequest, HttpResponse

Login = Callable[..., HttpResponse]


def sso_admin_login(view: Login) -> Login:
    """Wrap an ``AdminSite.login`` so anonymous users are sent to the provider.

    ``functools.wraps`` copies ``__dict__``, which carries
    ``login_required = False`` from the original view. That is what keeps the
    wrapped view exempt from ``LoginRequiredMiddleware`` without doing anything
    further -- the same accident that makes allauth's decorator work.
    """
    from bastion.admin.site import SSOAdminSiteMixin

    class _Adapter(SSOAdminSiteMixin):
        """Borrows the mixin's URL and denial logic without an AdminSite."""

        name = "admin"

    adapter = _Adapter()

    @wraps(view)
    def wrapper(request: HttpRequest, *args: object, **kwargs: object) -> HttpResponse:
        if not adapter._sso_enabled():
            return view(request, *args, **kwargs)

        if request.user.is_authenticated:
            if not (request.user.is_active and request.user.is_staff):
                return adapter.render_access_denied(request)
            return view(request, *args, **kwargs)

        from django.http import HttpResponseRedirect

        return HttpResponseRedirect(adapter._sso_url(request))

    return wrapper
