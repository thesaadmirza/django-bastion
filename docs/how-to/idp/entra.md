# Microsoft Entra ID

The hardest of the common providers, because three of its defaults are wrong for
this use and none of them fail loudly.

## Register the application

1. **Entra admin centre → App registrations → New registration**
2. Redirect URI, type **Web**: the exact value from `bastion_doctor`. It must
   match to the character, including the trailing slash.
3. **Certificates & secrets → New client secret.** Record the *value*, not the id.
4. Note the **Directory (tenant) ID** and **Application (client) ID**.

## Emit the claims this needs

### `oid` — required

**Token configuration → Add optional claim → ID → `oid`**

This is the one that matters. Entra's `sub` is **pairwise per application
registration**: two of your own apps see different `sub` values for the same
person. An account keyed on it breaks the moment a second client id exists, and
the failure looks like a duplicate account rather than a bug.

`oid` is stable within the tenant. The package refuses to run without it and
says so.

### `groups` — if you map privileges

**Token configuration → Add groups claim**

Two decisions here that bite later:

**Which groups.** "Security groups" is the usual answer. "Groups assigned to the
application" limits the list, but **drops nested groups entirely** — a silent
authorisation difference, not an error.

**What format.** By default Entra sends **object GUIDs**, not names. A rule
written against `"eng-admins"` will never match, and nothing tells you. Either
configure your rules with GUIDs, or switch the claim to names:

- On-premises synced groups: choose `sAMAccountName` under the group claim's
  advanced options.
- Cloud-only groups: `cloud_displayname`, which works **only** when
  `groupMembershipClaims` is `ApplicationGroup` — which is the option that drops
  nested groups. There is no configuration that gives you names and nesting.

Sign in once and read the audit record before trusting any of this.

### The overage claim

Above **200 groups in a JWT** (150 in SAML), Entra stops sending groups and
sends a pointer to Microsoft Graph instead:

```json
{"_claim_names": {"groups": "src1"},
 "_claim_sources": {"src1": {"endpoint": "https://graph.microsoft.com/..."}}}
```

The package detects this and marks the group list **incomplete**. The login
succeeds; privilege escalation is refused; a `mapping.incomplete` audit event is
recorded.

That is the safe behaviour and it is not a workaround. Resolving the groups
needs a Graph call with admin-consented `GroupMember.Read.All`, which this
version does not make. If your directory has people in more than 200 groups,
either filter the claim or do not derive privileges from it.

Group *filtering* also silently stops applying above 1,000 memberships. A filter
is not a safety net.

## Configure the connection

```python
BASTION = {
    "CONNECTIONS": {
        "corp": {
            "provider": "entra",
            "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
            "client_id": env("ENTRA_CLIENT_ID"),
            "client_secret": env("ENTRA_CLIENT_SECRET"),
            "quirks_kwargs": {"expected_tenant": "<tenant-id>"},
            "staff_groups": ["<group-guid-or-name>"],
            "superuser_groups": ["<group-guid-or-name>"],
        },
    },
    "ADMIN": {"connection": "corp"},
}
```

`expected_tenant` pins `tid`. For a single-tenant issuer the tenant is already
in the URL, so this is belt and braces — but for the `/common` or
`/organizations` endpoints it is the **only** thing stopping any Microsoft
account in the world from authenticating.

Then:

```bash
python manage.py bastion_doctor
```

## Things that will surprise you

**No `email_verified`.** Entra does not emit it. The package reports the address
as `Unknown` rather than guessing, because defaulting to false breaks every
login and defaulting to true is a hole. The nearest analogue is `xms_edov`,
which is opt-in and has different semantics; the package honours it when present.

**No back-channel logout.** Entra supports RP-initiated and front-channel
logout, not back-channel. If you need a provider-initiated session kill, this is
not the provider for it.

**Guests are different people.** `oid` differs per tenant by design, and
Microsoft is explicit that guests should be treated as new users in the resource
tenant. One human can legitimately be several accounts.

**`emit_as_roles` suppresses app roles.** Turning it on to get groups as roles
means you get groups *instead of* your actual application roles, not as well as.

**Developer tenants.** Free Microsoft 365 developer subscriptions were
restricted in 2025 and generally now need a Visual Studio subscription. Plan
test-tenant access accordingly.

## Verifying it worked

```bash
python manage.py bastion_audit export --since $(date -I) | grep login.succeeded
```

Confirm the `subject` looks like an object GUID and not a pairwise identifier,
and that `mapping.incomplete` does not appear.
