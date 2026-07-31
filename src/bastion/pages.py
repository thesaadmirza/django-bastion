"""Which base template the rendered pages extend.

These four pages are reached from two kinds of URL. ``admin/site.py`` renders
one from an ``AdminSite`` method, where ``django.contrib.admin`` is present by
definition. ``views.py`` and ``breakglass/views.py`` render the rest from
``bastion.urls``, which is designed to work in a project that protects a normal
site and has no admin at all.

So the base is resolved per request rather than baked into the templates. A
project with the admin gets pages that look like the admin, which is what the
package is mostly used for; a project without one gets the standalone base and
nothing raises.

The alternative was two copies of every page, one extending each base. That was
built first and thrown away: the pages carry translated prose, so two copies
means two message catalogues that drift, and the drift shows up on a 403 page
nobody looks at until it matters.
"""

from __future__ import annotations

from django.apps import apps
from django.urls import NoReverseMatch, reverse

#: Extended when the admin is available.
ADMIN_BASE = "admin/base_site.html"

#: Extended otherwise. Ships with this package, so it is always loadable.
FALLBACK_BASE = "bastion/base.html"


def admin_base_is_usable() -> bool:
    """Whether ``admin/base_site.html`` can be extended in this project.

    Both halves are load-bearing and neither is sufficient alone.

    Installed, because without the app its template directory is not on the
    loader path and the extends raises ``TemplateDoesNotExist``.

    Routed, because ``base_site.html`` reverses ``admin:index`` in its branding
    block. A project that lists the app but never includes ``admin.site.urls``
    -- which is a normal thing to do when the admin is disabled in one
    environment -- would otherwise get ``NoReverseMatch`` from an error page,
    turning a 403 into a 500.
    """
    if not apps.is_installed("django.contrib.admin"):
        return False
    try:
        reverse("admin:index")
    except NoReverseMatch:
        return False
    return True


def base_template() -> str:
    """The value to pass to the pages as ``base_template``.

    Not cached. It is cheap -- ``reverse`` memoises its own resolver -- and
    caching it would mean a test that installs or removes the admin sees the
    answer from a previous test, which is the failure mode that is order
    dependent and only appears in CI.
    """
    return ADMIN_BASE if admin_base_is_usable() else FALLBACK_BASE
