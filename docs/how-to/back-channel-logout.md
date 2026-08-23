# Ending a session when the provider says so

Without this, disabling somebody at the identity provider does not end the
Django session they already have. Their next sign-in fails, and everything they
have open keeps working until the cookie expires.

Back-channel logout closes that. The provider posts a signed token to a URL you
register, server to server, and the session named in it stops working.

## Turning it on

The route ships with `bastion.urls`, so if you already included those it is
serving. There is no setting: a URL the provider has not been told about
receives nothing, and one it has been told about is the switch.

```python
# urls.py — unchanged from the quickstart
urlpatterns = [
    path("sso/", include("bastion.urls")),
]
```

Run the migration, then register the URL with your provider:

```console
$ python manage.py migrate
```

| | |
|---|---|
| Register | `https://your-site.example/sso/backchannel-logout/` |
| Entra | *Front-channel logout URL* is a different field. The one you want is the back-channel URI, set through the application manifest |
| Keycloak | Client → Settings → *Backchannel logout URL*, and turn on *Backchannel logout session required* so the token carries a `sid` |
| Okta | Available on the OIDC client, under the sign-out policy |

There is also a connection-scoped route,
`/sso/backchannel-logout/<connection>/`, for deployments whose providers share
an issuer. The unscoped one reads the issuer out of the token to work out which
connection it belongs to, which is enough whenever those differ.

## What it does when a token arrives

The token has to be signed by the same keys your ID tokens are checked with,
name your issuer, be addressed to your client, and carry a `jti` it has not
used before. Anything else gets a `400` and an audit record, and nothing is
told which check refused it.

What gets ended depends on what the token names:

- **A `sid`** ends that one session. The other browsers that person is signed
  in on keep working.
- **A `sub` and no `sid`** ends every session that identity holds. This is the
  broader reading on purpose: the provider is saying the person is signed out,
  not that one of their browsers is.

Both outcomes are recorded as `auth.session.revoked`, with `context.scope` and
a count of the sessions actually ended.

## What it cannot do

**It cannot end a session it never saw.** The mapping from a provider session
to a Django session is written at login, so sessions that existed before you
deployed this are not in it. They expire normally and nothing revokes them.

**It cannot work on the `signed_cookies` session engine.** There is no
server-side session to delete, so there is nothing to end. `bastion.W030`
already warns about that engine for the same reason.

**It cannot end a session by `sid` if your provider does not send one.** Several
do not. A row is still written, so `sub`-scoped logout works; only the
single-session case is unavailable. Keycloak needs *Backchannel logout session
required* switched on before it sends one.

**A token for a session that has already gone still answers `200`.** Nothing to
end is not a failure, and answering `400` would make the provider retry
something that will never succeed.

## Checking it works

There is no way to be sure from configuration alone, the same way there is no
way to be sure the group claim is emitted. Sign in, then end the session at the
provider — in Entra that is *Revoke sessions* on the user, in Keycloak it is
*Sessions → Sign out* — and confirm the Django session stops working.

The audit log is where to look if it does not. There is no filter flag on the
command, so query the model:

```python
from bastion.audit.models import AuditEvent

AuditEvent.objects.filter(event_type="auth.session.revoked")
```

Nothing there means no token arrived, which is a registration problem rather
than a code one. A refusal is recorded as `auth.assertion.rejected` with the
reason attached, so the two cases are easy to tell apart.
