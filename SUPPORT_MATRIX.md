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
| **1** | PostgreSQL 14+ | Every feature, every test, every integrity guarantee. The only configuration we recommend for production. |
| **2** | SQLite 3.37+ | Full test suite runs. Fine for development, CI and single-node evaluation. Not recommended for production audit workloads. |
| **3** | MySQL 8.0+, MariaDB 10.6+ | Best effort. A documented set of constraint tests is `xfail`ed, and the package raises a startup warning naming the specific guarantees it cannot enforce. |
| — | Oracle | Not supported. We will not accept Oracle bug reports. |

The reason for the tiering is narrow and worth stating precisely: MySQL, MariaDB and Oracle **silently
ignore** conditional constraint options rather than erroring on them. A partial unique constraint enforcing
"one active break-glass grant per tenant" simply does not exist on those backends, and nothing tells you.
So the package tells you, at startup.

The package itself runs anywhere Django runs. The tamper-evidence and uniqueness guarantees documented in
the threat model are enforced only on PostgreSQL.

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
