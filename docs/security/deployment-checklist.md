# Deployment checklist

Work through this before the first real login, and again when anything in it
changes. Items marked **automated** are verified by `manage.py bastion_doctor`
or by Django's system checks; the rest are things software cannot check for you.

Run both first — they will do a third of this list for you:

```bash
python manage.py check --deploy
python manage.py bastion_doctor
```

## Transport and cookies

- [ ] **automated** `SESSION_COOKIE_SECURE = True`
- [ ] **automated** `CSRF_COOKIE_SECURE = True`
- [ ] **automated** `SESSION_COOKIE_HTTPONLY = True`
- [ ] **automated** `SECURE_HSTS_SECONDS` is set. Start at 3600 and raise it once
      you are confident; a long value is hard to walk back.
- [ ] TLS terminates somewhere you control, and `SECURE_PROXY_SSL_HEADER` matches
      how it terminates. Get this wrong and `request.is_secure()` lies, which
      makes the callback URL wrong and silently disables the https requirement
      on redirect targets.
- [ ] `SECURE_SSL_REDIRECT = True`, or the load balancer does it.

## Identity provider

- [ ] **automated** Discovery document reachable, and its `issuer` matches what
      you configured exactly.
- [ ] **automated** The provider advertises `S256`.
- [ ] **automated** At least one signing algorithm the package accepts. Symmetric
      algorithms are refused; a provider offering only `HS256` fails every login.
- [ ] The redirect URI registered at the provider matches
      `bastion_doctor`'s reported callback path **exactly** — scheme, host, port
      and trailing slash. More first logins fail on this than on everything else
      combined, and nothing can verify it from here.
- [ ] More than one signing key is published, or you accept a brief outage at
      each rotation.
- [ ] Clock skew against the provider is under a few seconds. Skew produces the
      least informative failure in the whole flow: a token that verifies
      perfectly and is then rejected as expired.

## Identity and authorisation

- [ ] `IDENTITY["KEY"]` is `("issuer", "subject")`. **automated** — the startup
      check refuses anything else, and it exists because keying on email is a
      live CVE in two shipping packages.
- [ ] For **Entra**, confirm the `oid` claim is emitted. Its `sub` is pairwise
      per application registration and cannot be used.
- [ ] For **Google Workspace**, `hosted_domain` is set. `hd` is the only tenant
      boundary Google offers; without the check, any personal Google account
      satisfies the login.
- [ ] Sign in once, then read the audit record, and confirm the group claim
      arrived in the format your rules expect. Okta omits `groups` unless
      configured. Entra sends object GUIDs, not names. Google's ID token has no
      group claim at all.
- [ ] Decide what a person with no matching group should see. The default is
      authenticated-but-not-authorised, which is what makes the denial page able
      to say something useful.

## Sessions and deprovisioning

- [ ] **automated** `SESSION_ENGINE` is not `signed_cookies`, or you accept that
      individual sessions cannot be revoked.
- [ ] Any custom auth backend calls `user_can_authenticate()` in `get_user()`.
      **automated** — that one line is the entire reason deactivating a user ends
      their sessions.
- [ ] You know how a leaver is deactivated, and have watched it end a live
      session. Setting `is_active = False` alone is not a session kill; it works
      only as a side effect of the backend check above.

## Break-glass

- [ ] Enabled, or you have written down the out-of-band route you will use
      instead. **automated** — the doctor warns when it is off, because a
      provider outage otherwise locks out everyone including whoever would fix it.
- [ ] **automated** At least two accounts, so losing one is not losing all.
- [ ] **automated** Alert sinks configured. The startup check refuses the
      combination of enabled-and-silent.
- [ ] Alerts arrive through a channel that does **not** depend on the identity
      provider. If they route through an SSO-protected inbox, the outage that
      triggers break-glass also silences the alarm.
- [ ] `ALLOWED_NETWORKS` set, or you have decided the endpoint should be
      reachable from anywhere.
- [ ] Credentials stored where the runbook says, in custody split between people.
- [ ] A drill has been run: `manage.py bastion_breakglass drill --user <name>`.

## Audit

- [ ] Retention set to what your obligations actually require. The default is
      365 days, which satisfies every regime that names a number. See
      [data inventory](data-inventory.md) for which those are.
- [ ] `bastion_audit purge` runs on a schedule. Configured retention that never
      executes is not retention.
- [ ] `bastion_audit verify` runs on a schedule and someone sees the result.
- [ ] Events ship to a system under **different administrative control**. This
      is the strongest tamper control available and it is not the hash chain.
- [ ] The chain head hash is anchored somewhere outside this deployment.
      Verification proves internal consistency; it cannot detect an adversary
      who recomputed the chain after editing it.

## Database

- [ ] PostgreSQL, SQLite or MySQL. Those three are the ones the suite is run
      against; MariaDB is untested and Oracle is unsupported. The uniqueness
      constraints are enforced on all three, confirmed by introspection.
- [ ] On MySQL, you are running a version of this package that retries a
      deadlocked audit append. Without it, InnoDB gap locks on the chain head
      drop audit records under concurrent logins, and chain verification still
      reports the log as clean.
- [ ] The application database user cannot `UPDATE` or `DELETE` the audit tables.
      The append-only guard in the model stops accidents, not intent.

## Supply chain

- [ ] The installed version is the one you meant. Releases carry PEP 740
      attestations; verify them if your process cares.
- [ ] `pip-audit` or equivalent runs in CI. Note it cannot see `libxmlsec1` or
      `libxml2` advisories, which are tracked under OS package names — you need
      an image scanner as well.

## Things nothing on this list can tell you

Stated plainly because a completed checklist should not feel like a completed
threat model:

- Whether your identity provider is configured correctly at its end.
- Whether the people with break-glass credentials still work here.
- Whether anyone reads the alerts.
- Whether your incident response plan survives contact with an outage.

See the [threat model](threat-model.md) for what this package does and does not
defend against.
