"""URLconf for the test project."""

from __future__ import annotations

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("sso/", include("bastion.urls")),
    path("admin/", admin.site.urls),
]
