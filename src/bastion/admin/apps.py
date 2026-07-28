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
    #: Django scans this module for AppConfig subclasses and treats every one
    #: with a truthy ``default`` as a candidate. ``AdminConfig`` sets it, and we
    #: inherit it, so without saying which is ours the entry ``"bastion.admin"``
    #: fails with "declares more than one default AppConfig".
    default = True
    default_site = "bastion.admin.site.SSOAdminSite"


# The base class stays reachable through __bases__; what this removes is the
# module-level name, which is what Django's inspect.getmembers scan walks.
# Without it the scan still sees two candidates and refuses to choose, and the
# error names Django's class rather than anything the reader configured.
del AdminConfig
