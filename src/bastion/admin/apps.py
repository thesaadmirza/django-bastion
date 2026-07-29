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

from django.contrib.admin import apps as admin_apps


class BastionAdminConfig(admin_apps.AdminConfig):
    # The base is reached through the module rather than imported by name on
    # purpose. Django scans this module for AppConfig subclasses and treats
    # every one with a truthy ``default`` as a candidate; importing the name
    # would bind a second candidate here, and the entry ``"bastion.admin"``
    # would fail with "declares more than one default AppConfig" naming a
    # Django class the reader never configured. A module is not a class, so the
    # scan finds only this one.
    default_site = "bastion.admin.site.SSOAdminSite"
