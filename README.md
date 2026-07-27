# django-bastion

Enterprise SSO and identity governance for Django. Puts the admin behind your identity provider, maps
claims to roles as reviewable data rather than code, records an audit trail, and gives you a fire escape
for when the IdP is down.

> **Status: pre-alpha.** Nothing works yet. This README describes the target API, and it is a design
> contract: if the quickstart below stops fitting on one screen, the design has gone wrong. See
> [FOUNDATIONS.md](FOUNDATIONS.md) for the decision record behind it.

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
            "protocol": "oidc",
            "discovery": "https://login.microsoftonline.com/<tenant-id>/v2.0",
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

**Claims map to roles as data.** Ordered rules with a serializable condition tree, editable in the admin or
declared in settings, and the same object either way.

```python
from bastion.rules import Claim

BASTION["MAPPING"]["RULES"] = [
    {
        "name": "Engineering admins",
        "order": 10,
        "condition": Claim("groups").contains("eng-admins")
                     & ~Claim("employment", "type").eq("contractor"),
        "effects": [AddGroup("sso-editors"), SetFlag("is_staff", True)],
    },
]
```

**Every decision explains itself.** The question a security review always asks is why a particular person
has admin access. That has a click-through answer here, recorded with the login:

```
rule #10 "Engineering admins"      MATCHED
  groups contains 'eng-admins'        → True  (claim value: ['eng-admins','all-staff'])
  NOT employment.type == 'contractor' → True  (claim value: 'fte')
  → add_group(sso-editors), set_flag(is_staff=True)
rule #20 "Contractors read-only"   no match
final: groups={sso-editors}, is_staff=True, denied=False
```

You can also run the rules against claims you paste in, or against your whole existing user table, before
saving a change.

**Break-glass that is a real feature.** Time-boxed, reason-required, alert-on-use, and exempt from the
directory sync so the nightly job can't delete your fire escape. Nothing else in the Django ecosystem ships
this; we checked, and five plausible PyPI names are all unclaimed.

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

Python 3.11+, Django 5.2 LTS or newer. PostgreSQL is Tier 1 and the only configuration we recommend in
production; SQLite is fully supported for development and evaluation; MySQL and MariaDB are best-effort and
the package will tell you at startup which integrity guarantees it cannot enforce there. Oracle is not
supported. [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) has the dated grid and the version-dropping policy.

SAML support is an opt-in extra (`pip install django-bastion[saml]`) because it pulls in xmlsec, which
needs system packages. The common case does not need it.

## Documentation

Not published yet. When it is: [threat model](docs/security/threat-model.md) and the deployment checklist
first if you are evaluating, per-IdP cookbooks if you are integrating.

## Security

Report vulnerabilities privately through GitHub, not the issue tracker. [SECURITY.md](SECURITY.md) has the
process, the response times we actually commit to, and an honest list of what we do not do.

## Licence

Apache-2.0. Chosen for the patent grant rather than to match Django, because federated identity has enough
patent history that the defensive-termination clause is worth having.
