"""URL patterns.

Include under any prefix::

    path("sso/", include("bastion.urls")),

The connection-scoped routes exist so a deployment with more than one provider
can send people at a named one. The unscoped routes work when exactly one
connection is configured, which is the common case and should not require
naming it twice.
"""

from __future__ import annotations

from django.urls import path

from bastion import views
from bastion.breakglass.views import break_glass_login

app_name = "bastion"

urlpatterns = [
    path("login/", views.begin, name="begin"),
    path("callback/", views.callback, name="callback"),
    path("login/<slug:connection>/", views.begin, name="begin-connection"),
    path("callback/<slug:connection>/", views.callback, name="callback-connection"),
    # POST only, and unscoped on purpose: which provider signed this session in
    # is recorded in the session, and a URL that names a different one is
    # either a mistake or someone else's idea.
    path("logout/", views.logout, name="logout"),
    # Off unless BREAK_GLASS["ENABLED"], and it 404s rather than announcing
    # itself when disabled. Deployments that want it somewhere less guessable
    # should include bastion.urls at a normal prefix and route this one
    # separately.
    path("break-glass/", break_glass_login, name="break-glass"),
]
