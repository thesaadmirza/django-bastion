"""Admin site substitution.

Put this in INSTALLED_APPS where ``"django.contrib.admin"`` was::

    INSTALLED_APPS = [
        "bastion",
        "bastion.admin.apps.BastionAdminConfig",
        ...
    ]

Do not instantiate an ``AdminSite`` in urls.py instead. That shape appears in
Django's own documentation, but it silently loses every registered model: the
substitution has to happen in ``AppConfig.ready()``, before
``autodiscover_modules('admin')`` populates the registry.
"""

from __future__ import annotations

from django.contrib.admin.apps import AdminConfig


class BastionAdminConfig(AdminConfig):
    default_site = "bastion.admin.site.SSOAdminSite"
