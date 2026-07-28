# Break-glass runbook

Emergency access, for when the identity provider is unreachable and every
account is unreachable with it — including the ones that would fix the problem.

Read this before you need it. Nobody reads a runbook well at 3am.

## Setting it up

```python
BASTION = {
    "BREAK_GLASS": {
        "ENABLED": True,
        "ALLOWED_NETWORKS": ["10.0.0.0/8"],
        "ALERT_SINKS": ["myproject.alerts.page_oncall"],
    },
}
```

Then create at least two accounts:

```bash
python manage.py createsuperuser --username breakglass-1
python manage.py bastion_breakglass grant \
    --user breakglass-1 --reason "Primary emergency access, INC runbook"
```

`--reason` is required, and it is read during an incident by someone who was not
here when the account was made. Write it for them.

An alert sink is any callable taking `subject` and `detail`:

```python
def page_oncall(*, subject: str, detail: str) -> None:
    pagerduty.trigger(summary=subject, details=detail, severity="critical")
```

The application refuses to start with break-glass enabled and no sink
configured. That is intentional: emergency access nobody is told about is a
backdoor with paperwork.

## Rules the software enforces

- Only flagged accounts can use the emergency path.
- The path answers only from `ALLOWED_NETWORKS`, when set.
- Every outcome — success, wrong password, unknown account, wrong network —
  is audited at critical severity and fires the alert sinks.
- The last active account cannot be deleted or revoked.
- **There is no lockout.** Every other login path here should lock out; this one
  must not, because locking the fire escape is itself the denial of service.
  Repeated failures alert instead of blocking.

## Rules only you can enforce

Software cannot check any of these, and they are the ones that make the feature
safe rather than merely present.

**Alerts must not depend on the provider.** If they route through an
SSO-protected inbox, the outage that triggers break-glass also silences the
alarm. Use a channel with independent authentication.

**Split custody.** AWS's guidance is that the password and the second factor are
held by different groups, and nobody holds both. Adopt something equivalent.

**Credentials must not expire or be cleaned up.** Exclude these accounts from
password rotation policies, inactivity reaping and directory sync. The package
marks them so your reconciliation can skip them — `bastion.breakglass.is_break_glass(user)`
— but the skipping is yours to implement.

**Keep the count small and known.** Two is the minimum. More than three or four
and it stops being an emergency route.

## Using it

1. Confirm SSO is genuinely down. This path is audited and paged; using it
   because SSO was merely slow generates an incident of its own.
2. Retrieve the credential from wherever the custody split says.
3. Go to `/sso/break-glass/` — adjust for your URL prefix.
4. Sign in. Expect the page to say plainly that this bypasses SSO and raises an
   alert; that banner is there so nobody uses it by accident.
5. Do the minimum needed to restore SSO. This is not a general-purpose admin
   session.
6. Tell whoever received the alert what it was, before they escalate.

## Afterwards

Within 24 hours:

- [ ] Write up what happened, and classify it: **drill**, **genuine emergency**,
      or **misuse**. All three are real outcomes and the third is why the
      classification exists.
- [ ] Rotate the credential used.
- [ ] Pull the audit trail for the session:
      ```bash
      python manage.py bastion_audit export --since 2026-07-28 | grep break_glass
      ```
- [ ] Confirm the alert arrived, and how long it took.
- [ ] If SSO failed in a way this package could have surfaced earlier, say so —
      that is a bug report worth having.

## Drills

Every 90 days, and whenever someone with access leaves.

```bash
python manage.py bastion_breakglass drill --user breakglass-1
```

The drill fires a **real alert** on purpose. A drill that does not confirm the
alarm rings has tested half of what matters, and the untested half is the half
that makes the account safe to have.

Then confirm by hand:

1. The alert arrived, through a channel that does not depend on the provider.
2. Whoever received it knew it was a drill.
3. The credential is still where the runbook says it is.
4. The person who is supposed to be able to retrieve it still works here.

Wire the check into monitoring so the cadence is measured rather than
remembered:

```bash
python manage.py bastion_breakglass check   # non-zero on any problem
```

It reports accounts not validated in 90 days, accounts without a usable
password, a single-account configuration, and an open network allowlist.

## When it does not work

If break-glass fails during a real outage, you are past what this package can
help with. Have a route to the database or the host, and know it. That is
outside this software's scope and stating so is more useful than implying
otherwise.
