"""Django admin integration.

The admin owns its own login view and ignores ``settings.LOGIN_URL`` entirely:
``grep -rn LOGIN_URL django/contrib/admin/`` returns nothing in every version
from 5.2 through main. ``AdminSite.admin_view()`` hard-codes
``reverse("admin:login")`` as the redirect target, so the only way to change
what happens at login is to change what that name resolves to, or what the view
behind it does.

We subclass ``AdminSite`` and swap it via ``AdminConfig.default_site``. Of the
five approaches available it is the only documented one, and the only one that
preserves the model registry while replacing the class, because
``AdminConfig.ready()`` runs before ``autodiscover_modules('admin')``.
"""
