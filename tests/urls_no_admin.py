"""A URLconf that routes bastion but not the admin.

The shape of a project protecting a normal site, and of one that disables the
admin in a single environment. Both are why the rendered pages resolve their base
template per request instead of extending ``admin/base_site.html`` outright:
``base_site.html`` reverses ``admin:index`` in its branding block, so under this
URLconf extending it would raise ``NoReverseMatch`` from an error page and turn a
403 into a 500.
"""

from __future__ import annotations

from django.urls import include, path

urlpatterns = [
    path("sso/", include("bastion.urls")),
]
