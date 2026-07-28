"""App configuration for the package itself.

The admin site replacement lives in ``bastion.admin.apps`` rather than here,
because a module containing two AppConfig subclasses makes Django's default-app
detection ambiguous and it refuses to start. That is also the right structure
anyway: ``bastion.admin.apps.BastionAdminConfig`` is what replaces
``django.contrib.admin`` in INSTALLED_APPS, and keeping it under the admin
package keeps the substitution obvious to whoever reads the settings file.
"""

from __future__ import annotations

from django.apps import AppConfig


class BastionConfig(AppConfig):
    name = "bastion"
    verbose_name = "Bastion"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        # Importing registers the system checks. Anything verifiable without a
        # request is verified at startup, not at first login.
        from bastion import checks  # noqa: F401

        self._register_admin()

    @staticmethod
    def _register_admin() -> None:
        """Register the identity ModelAdmin, if the admin is installed.

        Done here rather than from ``bastion/admin/__init__.py``, which is the
        module Django's autodiscover would normally use. That package is
        imported early -- ``bastion.admin.apps.BastionAdminConfig`` appears in
        INSTALLED_APPS, and importing a submodule imports its parent -- so
        anything in its ``__init__`` runs before the app registry is populated
        and touching a model there raises AppRegistryNotReady.

        ``ready()`` runs after the registry is populated, which makes this the
        correct place and the import order the reason.
        """
        from django.apps import apps

        if not apps.is_installed("django.contrib.admin"):
            return
        from bastion.admin import models  # noqa: F401
