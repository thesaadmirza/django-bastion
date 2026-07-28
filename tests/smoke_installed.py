"""Prove the built wheel works when installed, with nothing from the repo.

Deliberately not a pytest module. It runs as a standalone script against a
clean environment containing only the wheel and its *declared* dependencies, so
it answers a question the main suite structurally cannot: does what we ship
work for someone who runs ``pip install django-bastion``?

The main suite always runs with the dev group installed, so every optional
dependency is present whether or not the metadata says so. That gap is exactly
how a base install came to crash on ``manage.py check`` with a missing
``cryptography``: the import chain runs checks -> connections -> oidc -> jose,
and only an environment built from the metadata alone can catch it.

Run via ``nox -s wheel_sanity``. Prints a line per check and exits non-zero on
the first failure.
"""

import contextlib
import io

import django
from django.conf import settings

settings.configure(
    DEBUG=False,
    SECRET_KEY="smoke-test-only-never-a-real-secret",
    ALLOWED_HOSTS=["testserver"],
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
    INSTALLED_APPS=[
        "django.contrib.contenttypes",
        "django.contrib.auth",
        "django.contrib.sessions",
        "django.contrib.messages",
        "django.contrib.admin",
        "bastion",
    ],
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    TEMPLATES=[
        {
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "APP_DIRS": True,
            "OPTIONS": {
                "context_processors": [
                    # request is here to satisfy admin.W411, so that a genuine
                    # check failure is not buried under an expected warning.
                    "django.template.context_processors.request",
                    "django.contrib.auth.context_processors.auth",
                    "django.contrib.messages.context_processors.messages",
                ]
            },
        }
    ],
    ROOT_URLCONF="bastion.urls",
    AUTHENTICATION_BACKENDS=["bastion.backends.SSOBackend"],
    USE_TZ=True,
)
django.setup()

import importlib.resources as resources

from django.core.management import call_command
from django.template.loader import get_template

import bastion

print("version:", bastion.__version__)

# PEP 561. Without this marker downstream type checkers silently treat the
# whole package as untyped, which is worse than an error because nobody notices.
if not resources.files("bastion").joinpath("py.typed").is_file():
    raise SystemExit("py.typed missing from the wheel")
print("py.typed: present")

# Every module must import with only the declared dependencies available.
# Importing the protocol packages explicitly, because the failure that
# motivated this file was an import-time one several levels down.
import bastion.checks
import bastion.connections
import bastion.diagnostics
import bastion.protocols.oidc

print("imports: base install is self-sufficient")

call_command("migrate", run_syncdb=True, verbosity=0)
print("migrations: applied from the installed package")

for name in ("access_denied.html", "break_glass.html", "login_failed.html"):
    get_template(f"bastion/{name}")
print("templates: all three load from the wheel")

# System checks run on every manage.py invocation, so a package whose checks
# raise is a package that bricks the project's command line.
call_command("check", verbosity=0)
print("system checks: clean")

# The management commands must at least be loadable and runnable. Their help
# text is swallowed so a real failure further down stays visible.
for command in ("bastion_doctor", "bastion_audit", "bastion_breakglass"):
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            call_command(command, "--help")
    except SystemExit:
        pass  # --help exits 0 through argparse
print("management commands: all three load")

from bastion.audit.events import Event
from bastion.audit.models import verify_chain
from bastion.audit.recorder import emit

emit(Event.LOGIN_SUCCEEDED)
emit(Event.LOGIN_FAILED)
verified, problems = verify_chain()
if not verified:
    raise SystemExit(f"audit chain did not verify: {problems}")
print("audit chain: verifies end to end")

print("SMOKE OK")
