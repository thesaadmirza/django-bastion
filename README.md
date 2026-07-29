# django-bastion

Enterprise SSO and identity governance for Django. Puts the admin behind your identity provider, maps
claims to roles as reviewable data rather than code, records an audit trail, and gives you a fire escape
for when the IdP is down.

> **Status: pre-alpha.** Nothing is published to PyPI yet. The quickstart below is the working
> configuration, not a sketch of one. Where something is designed but not built, it says so.

## Quickstart

Three edits. Assumes Microsoft Entra ID; every other provider is the same shape with a different
`discovery` URL.

```python
# settings.py
INSTALLED_APPS = [
    "bastion",
    "bastion.admin.apps.BastionAdminConfig",   # replaces "django.contrib.admin"
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
            "staff_groups": ["django-staff"],
            "superuser_groups": ["django-admins"],
        },
    },
    "ADMIN": {"connection": "corp", "require_mfa": True},
}
```

```python
# urls.py
urlpatterns = [
    path("sso/", include("bastion.urls")),
    path("admin/", admin.site.urls),
]
```

```console
$ python manage.py migrate
$ python manage.py bastion_doctor
```

`bastion_doctor` checks the whole path end to end before a user ever hits it: discovery document
reachable, JWKS fetchable, signing algorithms compatible, redirect URI registered, clock skew against the
IdP, group claim actually present, and at least one break-glass account configured. Most SSO debugging is
a config typo three layers down, and nothing else surfaces it.

That is the entire happy path. Everything below is optional.

## What you get that you don't have today

**The admin actually goes through SSO.** Django's admin owns its own login view and ignores `LOGIN_URL`
entirely — `grep -rn LOGIN_URL django/contrib/admin/` returns nothing, in every version from 5.2 to main.
Working around that is a known source of redirect loops and of the "authenticated but not staff" dead end.
We subclass `AdminSite` (the documented seam) and fail with a real 403 page that tells the person which
group they're missing and who to ask.

**Claims map to roles, and in 0.1 that mapping is deliberately small.** Two lists per connection,
`staff_groups` and `superuser_groups`, matched against the group claim. That is all of it. The ordered rule
engine with a serializable condition tree is the 0.2 design and is not built yet;
[the roadmap](docs/explanation/roadmap.md) says what it will look like and which two approaches were
already rejected.

**Break-glass you can actually rely on.** Creating one requires a written reason. Using one alerts a
channel that does not depend on the identity provider, which matters because the outage that sends you
here may be the provider itself. Both outcomes are recorded at critical severity, so a failed attempt is
as visible as a successful one, and the account set can be restricted by network.

The model also refuses to delete the last active account. Deleting your way to zero is the sort of thing
people do while tidying up, and the consequence only appears during the incident that needed it. There is
a drill command for the same reason: an emergency account nobody has ever signed in with is an emergency
account nobody knows works.

**An audit log built for the people who will ask for it.** Append-only, hash-chained, with the field set
that NIST AU-3, PCI 10.2.2 and ISO 27002 8.15 independently converge on, plus a gapless sequence number so
an exported sample can be shown to be complete.

## Why you might not want this

Worth reading before you adopt it.

- **If you only need social login,** use [django-allauth](https://docs.allauth.org/). It is mature, it has
  every provider, and this package is not trying to replace it. We ship an adapter so the two compose.
- **If you're a B2B SaaS and can expense it,** WorkOS or Stytch will get you enterprise SSO faster than
  building will, at around $125 per connection per month. We're the better answer when self-hosting is a
  requirement rather than a preference, when the Django admin itself is the thing you need behind SSO
  (which those products do not solve at all), or when connection count makes per-connection pricing hurt.
- **If you need only OIDC and nothing else,** [mozilla-django-oidc](https://github.com/mozilla/mozilla-django-oidc)
  is about 1,200 lines and you can read all of it in twenty minutes. That legibility is a real feature.
  Come here when you need the governance layer on top.
- **We are pre-1.0 and the bus factor is currently 1.** That should disqualify us from anything you cannot
  afford to fork. See [GOVERNANCE.md](GOVERNANCE.md), which states this plainly rather than burying it.

## Requirements

Python 3.11+, Django 5.2 LTS or newer. PostgreSQL is what we recommend in production, and SQLite and
MySQL both pass the full test suite. MariaDB has not been tested. Oracle is not supported.
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) has the versions each backend was actually run against, and the
version-dropping policy.

SAML support is an opt-in extra (`pip install django-bastion[saml]`) because it pulls in xmlsec, which
needs system packages. The common case does not need it.

## Documentation

Not published to a site yet, but written and in the repository. Start at
[docs/index.md](docs/index.md).

If you are evaluating rather than building, read these four in order:
[threat model](docs/security/threat-model.md),
[why you might not want this](docs/explanation/why-you-might-not-want-this.md),
[data inventory](docs/security/data-inventory.md), and the
[deployment checklist](docs/security/deployment-checklist.md).

If you are integrating, [your first login](docs/tutorials/first-login.md) then
the [Entra guide](docs/how-to/idp/entra.md).

## Security

Report vulnerabilities privately through GitHub, not the issue tracker. [SECURITY.md](SECURITY.md) has the
process, the response times we actually commit to, and an honest list of what we do not do.

## Licence

Apache-2.0. Chosen for the patent grant rather than to match Django, because federated identity has enough
patent history that the defensive-termination clause is worth having.
