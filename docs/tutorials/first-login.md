# Your first login

Get a Django admin behind an identity provider, end to end. Around twenty
minutes, most of it at the provider.

You will need an existing Django project and admin access to an OIDC provider.
The examples use Microsoft Entra ID; any provider works, and the
[per-provider guides](../how-to/idp/entra.md) cover the differences.

## 1. Install

```bash
pip install "django-bastion[oidc]"
```

## 2. Register the application

At your provider, create an application and note the client id and secret. For
the redirect URI, use your site plus `/sso/callback/` — the exact value is
printed by `bastion_doctor` in step 5, and it must match to the character.

For Entra specifically, add the `oid` optional claim now. See
[the Entra guide](../how-to/idp/entra.md) for why.

## 3. Configure

```python
# settings.py
INSTALLED_APPS = [
    "bastion",
    "bastion.admin.apps.BastionAdminConfig",   # replaces django.contrib.admin
    ...
]

AUTHENTICATION_BACKENDS = ["bastion.backends.SSOBackend"]

BASTION = {
    "CONNECTIONS": {
        "corp": {
            "provider": "entra",
            "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
            "client_id": env("BASTION_CLIENT_ID"),
            "client_secret": env("BASTION_CLIENT_SECRET"),
            "staff_groups": ["<your-admin-group>"],
        },
    },
    "ADMIN": {"connection": "corp"},
}

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 3600
```

That `INSTALLED_APPS` line replaces `django.contrib.admin`. Do not list both.

```python
# urls.py
urlpatterns = [
    path("sso/", include("bastion.urls")),
    path("admin/", admin.site.urls),
]
```

## 4. Migrate

```bash
python manage.py migrate
```

## 5. Check before you try

```bash
python manage.py bastion_doctor
```

This is the step that saves the afternoon. It fetches the discovery document,
validates the issuer binding, confirms the provider offers an algorithm we
accept, primes the key set, and prints the callback URL to register:

```
warn  urls: Callback URL is http://api.example.com/sso/callback/
      This is http://, not https://, and most providers refuse to register or
      redirect to a plain-http URI outside localhost...
```

The scheme is the part to read. It is assembled from `ALLOWED_HOSTS` and your
TLS settings, and the hint says which setting it came from, because a
deployment behind a load balancer that terminates TLS without
`SECURE_PROXY_SSL_HEADER` builds `http://` redirect URIs while the `https://`
one is registered at the provider. Pass `--base-url https://api.example.com` if
you would rather compare against the address you know you are reached on.

Items marked `?` could not be checked from here and say so. That is deliberate:
whether your redirect URI is registered and whether the group claim actually
arrives cannot be established without a real login.

## 6. Sign in

Visit `/admin/`. You should be redirected to your provider and, after
authenticating, land back in the admin.

If you land on a page saying you are signed in but do not have access, that is
the system working. It will tell you which account you used and which group is
missing.

## 7. Check what actually arrived

This is the step people skip, and it is where the surprises are.

```bash
python manage.py bastion_audit export --since $(date -I)
```

Look at the `login.succeeded` record and confirm:

- `subject` is what you expect — for Entra, an object GUID, not a pairwise value
- no `mapping.incomplete` event appears
- `is_privileged` is true if you expected staff access

If your group claim did not arrive in the format your `staff_groups` expects,
nothing will have failed — you will simply not be staff. Okta omits the claim
unless configured, Entra sends GUIDs rather than names, and Google's ID token
has no group claim at all.

## 8. Before this is production

Two things, in order.

**Set up break-glass.** Right now a provider outage locks out everyone,
including whoever would fix it. See the
[break-glass runbook](../security/break-glass-runbook.md).

**Work through the [deployment checklist](../security/deployment-checklist.md).**
It is short and about a third of it is automated.

## What you have now

An admin behind SSO, an audit trail of every authentication decision, and a
diagnostic command that tells you when the configuration is wrong instead of
letting you discover it at a login.

What you do not have is SAML, SCIM provisioning, or the rule engine — see
[why you might not want this](../explanation/why-you-might-not-want-this.md).
