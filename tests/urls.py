"""URLconf for the test project."""

from __future__ import annotations

from django.urls import include, path

urlpatterns = [
    path("sso/", include("bastion.urls")),
]
