# Testing your integration

`bastion.testing` ships a fake identity provider so you can test the paths that
matter without one.

Those paths are exactly the ones a real provider will not produce on demand. No
tenant emits a group-overage claim because you asked, none will mark an address
unverified for you, and none will omit `amr` on request — so an unverified
address, incomplete group evidence and a replayed `state` are the cases most
projects end up not testing at all.

## The shape of it

```python
import pytest
from django.contrib.auth import SESSION_KEY
from bastion.testing import harness

pytestmark = pytest.mark.django_db


def test_an_unverified_address_is_refused(client):
    rig = harness()
    with rig.installed():
        rig.login(client, email_verified=False)
    assert SESSION_KEY not in client.session
```

`harness()` builds a provider, a transport and a `Connection` wired together.
`installed()` points bastion's views at it for the duration, and puts them back
afterwards. `login()` drives the begin view, reads the `state` and `nonce` out
of the authorization URL, mints a token carrying that nonce, and answers the
callback.

**No certificate and no local HTTPS server.** bastion refuses a plain-http
issuer with no localhost exemption, which is correct and would otherwise mean
building a self-signed cert and a merged CA bundle before writing a single
test. It does not, because `Connection` takes its transport as a field: the
fake is injected rather than served.

## What you need configured

An ordinary Django test setup, plus one thing worth naming: **a refused login
renders a page**, so `TEMPLATES` has to reach bastion's templates. `APP_DIRS:
True` is enough. Without it a refusal raises `TemplateDoesNotExist` and the
test fails for the wrong reason.

## Shaping the assertion

Keyword arguments override individual claims:

```python
rig.login(client, email_verified=False)      # provider says the address is a lie
rig.login(client, sub=None)                  # no subject at all
rig.login(client, amr=[])                    # no second factor asserted
rig.login(client, aud="somebody-else")       # minted for another client
```

`claims=` takes a whole set instead, for the provider builders that return one:

```python
rig = harness(vendor="entra", staff_groups=("django-staff",))
with rig.installed():
    rig.login(client, claims=rig.idp.with_group_overage())
```

That is Entra above its overage threshold, where the token carries a pointer to
Microsoft Graph instead of the groups. The live nonce is substituted for you.
Overrides are applied last, so `nonce="wrong"` still gets you the mismatch case
deliberately.

## Driving the two halves separately

```python
with rig.installed():
    request = rig.begin(client)
    first = rig.complete(client, request)
    second = rig.complete(client, request)   # replayed state
assert second.status_code != 302
```

`request` carries `state`, `nonce` and the full `url`, all read from the
redirect the begin view issued. Nothing here needs a private attribute.

## Providers

`harness(vendor=...)` takes `generic`, `entra`, `okta`, `google` or `keycloak`,
and each mints what that vendor actually emits — Entra's `oid` and GUID groups,
Google's absent group claim, Keycloak's path-shaped groups. See
[the provider matrix](../reference/providers.md) for what each one gives you.

Test against the profile you deploy. A rule written against Okta's group names
will never match Entra's GUIDs, and that is not a thing a generic fake would
have told you.

## What is deliberately not here

Malformed and hostile tokens — `alg: none`, algorithm confusion, key injection
through `jwk` or `jku`, an unknown `crit`. Those live in bastion's own suite,
because they prove *bastion* refuses them. They say nothing about your
deployment, and publishing them would commit this package to an attack-token
API with no reason to exist.

If you are auditing bastion itself rather than integrating it, that corpus is
in `tests/idp/tokens.py` in the repository.
