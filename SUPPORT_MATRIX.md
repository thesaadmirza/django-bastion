# Support matrix

Last reviewed: **2026-07-27**. Reviewed at every minor release against upstream Django and CPython end-of-life
dates.

## Supported combinations

|              | Django 5.2 LTS | Django 6.0 | Django 6.1 | Django `main` |
|--------------|:--------------:|:----------:|:----------:|:-------------:|
| Python 3.11  | ✅              | —          | —          | —             |
| Python 3.12  | ✅              | ✅          | ✅          | —             |
| Python 3.13  | ✅              | ✅          | ✅          | —             |
| Python 3.14  | ⚠️              | ✅          | ✅          | ⚠️ advisory    |

✅ tested in CI, supported. ⚠️ see notes. — combination does not exist upstream (Django 6.x requires Python 3.12+).

**Notes**

- **Python 3.14 on Django 5.2 LTS** is unverified. It depends on whether upstream backported 3.14 support
  into a 5.2.x patch release, which we have not confirmed. Treat as unsupported until this line says
  otherwise.
- **Django `main`** runs nightly and is non-blocking. It exists so that upstream regressions are our problem
  before they are yours, not because we support running against it.

## Why the Python floor is 3.11 and not 3.12

Django 6.x requires 3.12, so pinning our floor there would be simpler. We don't, because RHEL 9 ships
`python3.11` as a supported module and remains common in exactly the public-sector and regulated
environments this package is aimed at. Dropping 3.11 would cost us the constituency we are built for.

The floor rises to 3.12 when we drop Django 5.2, and not before.

## Database support

| Tier | Databases | What it means |
|---|---|---|
| **1** | PostgreSQL 14+ | Recommended for production. The suite passes and nothing had to be worked around to get there. |
| **2** | SQLite 3.37+ | The suite passes. Three concurrency tests skip, because SQLite serialises writes and a lock race cannot be observed either way. Fine for development, CI and single-node evaluation. |
| **3** | MySQL, at whatever version your Django requires | The suite passes, after the deadlock fix described below. |
| **3** | MariaDB, at whatever version your Django requires | The suite passes. Django's MySQL backend drives both, and MariaDB needed nothing MySQL did not. |
| — | Oracle | Not supported. We will not accept Oracle bug reports. |

The floor on those two is Django's, not ours, and Django moves it:

| Django | MySQL | MariaDB |
|---|---|---|
| 5.2 | 8.0.11 | 10.5 |
| 6.0 | 8.0.11 | 10.6 |
| 6.1 | 8.4 | 10.11 |

Below the floor Django refuses to connect at all, so this is not a question of whether the suite passes.

CI runs the whole suite against PostgreSQL 16, MySQL 8.4, MariaDB 10.11 and SQLite on every push. The
three concurrency tests skip on SQLite, which serialises writes and so cannot show a lock race either
way; nothing else is skipped anywhere.

The two are pinned at the floor rather than a current release, because the floor is the version most
likely to break. That has a failure mode worth naming: when Django 6.1 raised MariaDB from 10.6 to 10.11,
every database run started failing on commits that changed nothing, and the breakage looked like whatever
branch happened to be open. A test now compares the pinned images against the floor the installed Django
declares, so the next time this happens it fails with the new number in the message.

### The MySQL deadlock

Appending to the audit chain takes a row lock on the chain head. InnoDB's REPEATABLE READ turns that into
a gap lock, and concurrent appends then deadlock. Not intermittently: twelve threads writing to one chain
reproduced it on every run.

The exception was the smaller half of it. `emit()` catches anything a sink raises, so that a broken sink
can never fail a login, which meant the deadlock never surfaced anywhere. It dropped the event instead.
The sequence number had been assigned inside the transaction that rolled back, so no gap appeared either,
and `verify_chain()` went on reporting a clean log with entries missing from it.

`AuditChain.append()` now reissues the transaction when the server reports lock contention, which is what
both MySQL and PostgreSQL document that you should do. PostgreSQL never showed the problem at all.

### Constraints

Two unique constraints carry integrity guarantees: `(chain, chain_seq)` on audit events, and
`(issuer, subject)` on federated identities. Both are plain constraints over real columns, both were
confirmed present by database introspection on all three backends, and both were confirmed to reject
duplicates there.

Keeping them free of conditions is deliberate. Django accepts `UniqueConstraint(condition=...)` against
MySQL and MariaDB and then quietly does not create it, so a partial constraint would leave the guarantee
missing with nothing at all to indicate it. A test fails if anyone adds one.

PostgreSQL stays the recommendation because it needed no workaround, not because the others enforce less.

One gap worth naming: local MySQL runs used PyMySQL, since the machine had no MySQL C client libraries.
CI uses mysqlclient. Same server, same wire protocol, different driver.

## Version-dropping policy

- A Django series is dropped in the **first minor release after that series leaves upstream extended
  support**.
- A Python version is dropped in the **first minor release after its upstream end-of-life**.
- Adding support for a new Django or Python version is **patch-release-eligible**.
- Dropping support is **never** done in a patch release.
- Every drop is announced in the changelog of the release *before* the one that performs it, and appears
  here with its effective version and date.

## Upstream dates we track

| | End of extended support / EOL |
|---|---|
| Django 5.2 LTS | April 2028 |
| Django 6.0 | with 6.2 (April 2027) |
| Django 6.2 LTS | expected April 2027 release |
| Python 3.11 | October 2027 |
| Python 3.12 | October 2028 |

## Scheduled changes

Nothing scheduled. This section will list pending drops one release ahead of when they happen.
