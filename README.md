# django-bastion

Enterprise SSO and identity governance for Django. Puts the admin behind your identity provider, turns
the group claim into staff and superuser rights, and records who got what and when.

> **Version 0.1.0, and the configuration surface is now frozen.** Every settings key, check id and audit
> event name is covered by a written
> [deprecation policy](docs/reference/deprecation-policy.md): a renamed key is refused at startup with a
> message naming its replacement, and stays refused for two minor versions. What is *not* covered is
> everything else — module paths, function signatures, class layouts — so importing from
> `bastion.protocols` is holding something that moves.
>
> Still pre-1.0, and the bus factor is 1. OIDC works end to end; SAML, SCIM and the rule engine do not
> exist, and the pages that mention them say so.

```bash
pip install django-bastion
```

## Quickstart

Three edits. Assumes Microsoft Entra ID. Another provider is the same shape with a different `issuer` and
a different `provider` name; the [how-to pages](docs/how-to/) cover the ones with quirks worth knowing.

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
    # require_mfa refuses admin access when the assertion showed one factor.
    # Off by default: confirm your provider emits `amr` with a real sign-in
    # first, because several make it opt-in.
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

`bastion_doctor` walks the path before anyone tries to use it. It reaches the provider for the discovery
document, the JWKS and the signing algorithms, compares your clock against theirs, and works through the
local half from the session engine to whether break-glass has anyone to alert.

Add `--check-registration` and it also asks the provider whether your callback URL is registered — one
authorization request, no client secret, no token, because the flow is abandoned before the code is
exchanged. `redirect_uri_mismatch` is the most common way an integration fails and the hardest to see from
inside the app, where the settings are right and the provider still refuses.

Two things it still will not tell you are fine: whether the group claim is emitted and in what shape, and
whether MFA will really be asserted. Neither can be known without a person completing a real login, so
they come back marked unverifiable with the reason attached. A run that quietly skipped them would read
better and help less. Most SSO debugging is a config typo three layers down, and a green tick over an
unasked question is how you lose an afternoon to it.

That is the entire happy path. Everything below is optional.

## What you get that you don't have today

**The admin actually goes through SSO.** Django's admin owns its own login view and ignores `LOGIN_URL`
entirely — `grep -rn LOGIN_URL django/contrib/admin/` returns nothing, in every version from 5.2 to main.
Working around that is a known source of redirect loops and of the "authenticated but not staff" dead end.
We subclass `AdminSite` (the documented seam) and fail with a real 403 page that tells the person which
group they're missing and who to ask.

**Groups map to roles, where your provider sends groups.** Two lists per connection, `staff_groups` and
`superuser_groups`, matched against the group claim. That is all of it. The ordered rule engine with a
serializable condition tree is the 0.2 design and is not built yet; [the
roadmap](docs/explanation/roadmap.md) says what it will look like and which two approaches were already
rejected.

The qualifier is load-bearing. **Google's ID token carries no group claim at all**, so on a Google
connection those two lists cannot match anything and roles are assigned locally instead. That is not a
bug to be fixed by configuration, and finding it out after wiring everything up is the reason
[the provider matrix](docs/reference/providers.md) exists — it says what each profile gives you, and how
far each has actually been proven.

**An answer for the admins you already have.** Keying accounts on `(issuer, subject)` and never on
email is the right default and it strands every existing administrator behind a second account on their
first sign-in. `LINKING_POLICY = "verified_email_once"` adopts the local account instead — once, only on
an address the provider says is verified, only from a domain you pin, only where exactly one local
account holds it and has no federated identity yet, and never onto a break-glass account. After that it
pins to the subject like everything else. Both the adoption and every refusal to adopt are audited.

**An audit log built for the people who will ask for it.** Append-only, hash-chained, with the field set
that NIST AU-3, PCI 10.2.2 and ISO 27002 8.15 independently converge on, plus a gapless sequence number so
an exported sample can be shown to be complete.

**A fake provider, in the package.** Testing an SSO integration means producing assertions no real provider
will produce on demand: an address the provider marks unverified, a group list truncated to a Graph
pointer, a replayed `state`. `bastion.testing` ships a fake that does, with no certificate and no local
HTTPS server — `Connection` takes its transport as a field, so the fake is injected rather than served.

```python
def test_an_unverified_address_is_refused(client):
    rig = harness()
    with rig.installed():
        rig.login(client, email_verified=False)
    assert SESSION_KEY not in client.session
```

[Testing your integration](docs/how-to/testing-your-integration.md) has the rest.

## Advanced: break-glass

**Off by default, and deliberately not part of the quickstart.** It is an unauthenticated credential
endpoint — the most sensitive surface this package has — and a deployment should arrive at it by deciding
it needs one, not by following a getting-started page or by silencing a check.

When you do want one, the design is what you would want from an emergency route. Creating an account
requires a written reason. Using one alerts a channel that does not depend on the identity provider, which
matters because the outage that sent you there may be the provider. Both outcomes are recorded at critical
severity, so a failed attempt is as visible as a successful one, and the account set can be restricted by
network. The model refuses to delete the last active account, and there is a drill command, because an
emergency account nobody has ever signed in with is an emergency account nobody knows works.

Most projects do not need it. A cloud console that can flip a flag, a shell on the box, or a second
provider are all answers to "the IdP is down", and none of them adds a login route. If what you actually
have is a password path serving a portal or an API rather than the admin, say so with
`ADMIN["local_login"] = "elsewhere"` — that is the setting `bastion.E023` is asking about, and enabling
break-glass to satisfy that check is the one reason not to enable it.

[The runbook](docs/security/break-glass-runbook.md) covers setup, the drill, and what to do afterwards.

## Why you might not want this

Worth reading before you adopt it.

- **If you only need social login,** use [django-allauth](https://docs.allauth.org/). It is mature, it has
  every provider, and this package is not trying to replace it.
- **If you're a B2B SaaS and can expense it,** WorkOS or Stytch will get you enterprise SSO faster than
  building will. Check their current per-connection pricing rather than trusting a figure in someone's
  README. We're the better answer when self-hosting is a requirement rather than a preference, when the
  Django admin itself is the thing you need behind SSO, or when connection count makes per-connection
  pricing hurt.
- **If you need only OIDC and nothing else,** [mozilla-django-oidc](https://github.com/mozilla/mozilla-django-oidc)
  is about 1,200 lines and you can read all of it in twenty minutes. That legibility is a real feature.
  Come here when you need the governance layer on top.
- **We are pre-1.0 and the bus factor is currently 1.** That should disqualify us from anything you cannot
  afford to fork. See [GOVERNANCE.md](GOVERNANCE.md), which states this plainly rather than burying it.

## Requirements

Python 3.11+, Django 5.2 LTS or newer. PostgreSQL is what we recommend in production. SQLite, MySQL and
MariaDB all pass the full test suite on every push. Oracle is not supported.
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) has the versions each backend was actually run against, and the
version-dropping policy.

There are no `[saml]`, `[ldap]` or `[scim]` extras. They were declared and shipped no modules, so
installing one pulled in a protocol stack you had nothing to call. They come back one at a time, each with
an implementation and a live tenant behind it.

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
