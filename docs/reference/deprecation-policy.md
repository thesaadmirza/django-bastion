# Deprecation policy

What a deployment can rely on across an upgrade, and what happens when a name
has to change.

This is the contract from 0.1.0. Below 0.1.0 there is no contract: the versions
are alphas, anything can move, and the changelog is the only record.

## What is covered

Three surfaces, because these are the three a deployment writes down and cannot
discover has moved:

- every key under `BASTION`, global or per-connection
- every check id, because they end up in `SILENCED_SYSTEM_CHECKS`
- every audit event name, because they end up in alerting rules

Anything importable from `bastion.testing` is covered too. The rest of the
package is not: internal module paths, function signatures and class layouts
may change in any release. If you import from `bastion.protocols`, you are
holding something that moves.

A test holds all four lists still. Adding to any of them takes an edit to
`tests/test_settings_surface.py`, so the surface changes in a diff a reviewer
can see rather than as a side effect of adding a dataclass field.

## The rule for a rename

**An old name is refused, never ignored.** Startup fails with a message naming
the replacement.

```
connection 'corp' has unknown keys: 'require_group_match'
(use 'require_privileged_user', which is the same switch under a name that
says what it tests: is_staff or is_superuser, never the group claim)
```

Accepting a renamed key silently, or accepting it with a warning, means a
deployment can be running with a control it believes is on. For
`require_group_match` — the only thing stopping an unprivileged account holding
a session — that is the difference between a locked door and a door with a sign
on it. Failing the boot is the correct outcome, and it is cheap: the deployment
that broke has not started, and the message says what to type.

## How long a refused name stays

**Two minor versions, then it goes.**

A name refused in 0.1.0 is still refused in 0.2.0 and 0.3.0. In 0.4.0 it is
removed from the refusal list, at which point setting it produces the ordinary
unknown-key error, naming the key but not its replacement.

That window is a compromise. Refusals cost nothing to keep, but a list that
only grows becomes the map of every mistake the project has made, and a
deployment more than two minor versions behind has other problems.

The refused names live in `_RENAMED_KEYS` in `connections.py`, and the surface
test counts them, so one cannot quietly outlive its window.

## What a deployment should expect

| Change | Where it shows | What happens on upgrade |
|---|---|---|
| A new setting | changelog, reference | Nothing. Defaults preserve the current behaviour |
| A new check | changelog, check-id table | `manage.py check` may fail. That is the point; the hint says what to fix |
| A renamed key | changelog, refused-key list | Startup fails, naming the replacement |
| A removed key | changelog, **a minor version** | Startup fails with an unknown-key error |
| A changed default | changelog, **explicitly, at the top** | Behaviour changes. Read the entry before upgrading |

The last one is the one to watch. `ADMIN["require_mfa"]` has changed default
once, and the changelog entry said so in bold, because a default that moves is
the only change here that alters a working deployment without anyone editing
its settings.

## Check ids

Ids are stable and never renumbered. An id is retired rather than reused: if
`bastion.E026` stops existing, no future check takes that number, because
somebody's `SILENCED_SYSTEM_CHECKS` still names it and silencing an unrelated
check is worse than silencing nothing.

Severity can change within an id's subject. `bastion.E027` and `bastion.W027`
are the same subject at two severities — a malformed connection that something
can reach, and one that nothing can — and which one fires depends on the
deployment rather than on the version.

## Audit events

Names are stable for the same reason: they end up in alerting rules, and a
renamed event is an alert that stops firing without anyone noticing.

An event reserved but not yet emitted is marked as such in the catalogue. That
distinction is the AU-2 deliverable — what the system *can* log against what it
*does* — and it is tested, so a reserved event that gains an emitter cannot
stay marked reserved.

## Placeholders

There are none, on purpose.

A setting is declared when the code that reads it is written, not before.

Four keys were removed for contradicting that — `BACKEND`,
`MAPPING["STRICT"]`, `MAPPING["MANAGED_GROUPS"]` and
`ADMIN["reauth_max_age"]`. Each had been declared and read by nothing, so a
deployment could set it and get silence, which is the failure mode this whole
page exists to prevent. The changelog names the release.

Names waiting on code are listed under "Not yet implemented" in the
[settings reference](settings.md) instead, where they cost nothing and promise
nothing.
