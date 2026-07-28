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

app_name = "bastion"

urlpatterns = [
    path("login/", views.begin, name="begin"),
    path("callback/", views.callback, name="callback"),
    path("login/<slug:connection>/", views.begin, name="begin-connection"),
    path("callback/<slug:connection>/", views.callback, name="callback-connection"),
]
