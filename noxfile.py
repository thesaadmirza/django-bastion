"""Test matrix.

nox rather than tox because the matrix has real exclusions -- Django 6.x
requires Python 3.12+ -- and expressing conditional exclusions in tox factor
syntax produces something nobody can read six months later. Here it is an
``if``.

Strategy: the full Python x Django grid runs on SQLite, which is fast and
catches API breakage. A reduced grid runs across databases on the oldest and
newest supported Django, which is where backend divergence shows up.
"""

from __future__ import annotations

import glob

import nox

nox.options.default_venv_backend = "uv|virtualenv"
nox.options.reuse_existing_virtualenvs = True
nox.options.sessions = ["lint", "typecheck", "tests", "migrations"]

PYTHONS = ["3.11", "3.12", "3.13", "3.14"]
DJANGOS = ["5.2", "6.0", "6.1"]
DATABASES = ["sqlite", "postgres", "mysql"]

# Django 6.x dropped Python 3.11.
EXCLUDED = {(py, dj) for py in ["3.11"] for dj in ["6.0", "6.1"]}


def _django_spec(version: str) -> str:
    if version == "main":
        return "https://github.com/django/django/archive/main.tar.gz"
    major, minor = version.split(".")
    return f"Django>={major}.{minor},<{major}.{int(minor) + 1}"


@nox.session(python=PYTHONS)
@nox.parametrize("django", DJANGOS)
def tests(session: nox.Session, django: str) -> None:
    if (session.python, django) in EXCLUDED:
        session.skip(f"Django {django} does not support Python {session.python}")
    session.install("-e", ".[oidc]", "--group", "dev")
    session.install(_django_spec(django))
    session.run("pytest", "--cov=bastion", "--cov-report=term-missing", *session.posargs)


@nox.session(python=PYTHONS[-1])
@nox.parametrize("database", DATABASES)
def tests_db(session: nox.Session, database: str) -> None:
    """Cross-database run. Every backend runs the whole suite and is expected
    to pass it; nothing here is xfailed.

    The concurrency tests skip on SQLite, which serialises writes and so cannot
    show a lock race either way. That is a skip, not a tolerated failure.
    """
    session.install("-e", ".[oidc]", "--group", "dev")
    if database == "postgres":
        session.install("psycopg[binary]>=3.2")
    elif database == "mysql":
        session.install("mysqlclient>=2.2")
    session.env["BASTION_TEST_DB"] = database
    session.run("pytest", *session.posargs)


@nox.session(python=PYTHONS[-1])
def coverage_core(session: nox.Session) -> None:
    """The security core carries a 100% gate, not the repository-wide 95%."""
    session.install("-e", ".[oidc]", "--group", "dev")
    session.run(
        "pytest",
        "--cov=bastion.rules",
        "--cov=bastion.claims",
        "--cov=bastion.protocols",
        "--cov=bastion.audit",
        "--cov=bastion.breakglass",
        "--cov-fail-under=100",
    )


@nox.session(python=PYTHONS[-1])
def lint(session: nox.Session) -> None:
    session.install("ruff>=0.9")
    session.run("ruff", "check", "src", "tests", "noxfile.py")
    session.run("ruff", "format", "--check", "src", "tests", "noxfile.py")


@nox.session(python=PYTHONS[-1])
def typecheck(session: nox.Session) -> None:
    """mypy is the merge gate."""
    session.install("-e", ".[oidc]", "--group", "dev")
    session.run("mypy", "src")


@nox.session(python=PYTHONS[-1])
def typecheck_pyright(session: nox.Session) -> None:
    """Advisory. Pyright does not load the mypy plugin, so this proves our
    public API is usable by the pyright/Pylance population, who see only the
    static stubs. If pyright cannot see it, neither can they."""
    session.install("-e", ".[oidc]", "--group", "dev")
    session.run("pyright", "src", success_codes=[0, 1])


@nox.session(python=PYTHONS[-1])
def migrations(session: nox.Session) -> None:
    """A missing migration in an auth package is a production outage."""
    session.install("-e", ".", "--group", "dev")
    session.run(
        "python",
        "-m",
        "django",
        "makemigrations",
        "--check",
        "--dry-run",
        env={"DJANGO_SETTINGS_MODULE": "tests.settings"},
    )


@nox.session(python=PYTHONS[-1])
def audit(session: nox.Session) -> None:
    """Advisory scan. Note this cannot see libxmlsec1/libxml2 CVEs, which are
    tracked under OS package names -- the container scan covers those."""
    session.install("-e", ".[oidc,saml]", "pip-audit>=2.7")
    session.run("pip-audit", "--strict")


@nox.session(python=PYTHONS[-1])
def wheel_sanity(session: nox.Session) -> None:
    """Build the wheel and exercise it as an installed package.

    Installs *with* dependency resolution, on purpose. The previous version
    passed --no-deps, which meant the declared dependency set was never
    exercised and a base install that could not run `manage.py check` went
    unnoticed. The point of this session is to be the one place we find out
    what `pip install django-bastion` actually gives someone.
    """
    session.install("build", "hatchling", "twine")
    session.run("python", "-m", "build", "--outdir", "dist")

    # Metadata has to be valid before PyPI will take it, and --strict turns
    # README rendering warnings into failures.
    session.run("twine", "check", "--strict", *glob.glob("dist/*"))

    session.install("--force-reinstall", *session.posargs or glob.glob("dist/*.whl"))
    session.run("python", "tests/smoke_installed.py")
