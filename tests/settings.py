"""Minimal settings so contributors can run `pytest` with no arguments."""

from __future__ import annotations

import os

# Long enough to satisfy security.W009, and written so nobody has to wonder.
# A random-looking string here would read as a leaked key in a public
# repository and would trip secret scanners that cannot know any better.
SECRET_KEY = "not-a-secret-this-is-the-test-suite-" + "x" * 24
DEBUG = False
ALLOWED_HOSTS = [
    "testserver",
    "localhost",
    # Used by the redirect tests. Note these being here does NOT make them
    # valid redirect targets: ALLOWED_HOSTS governs which hosts Django serves,
    # not where it is safe to send an authenticated session. That distinction
    # is the subject of tests/test_redirects.py.
    "app.example.test",
    "other.example.test",
    "evil.example.test",
]
USE_TZ = True

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "bastion",
    # Replaces "django.contrib.admin". This is the substitution the quickstart
    # asks for, exercised here so that a regression in it fails the suite.
    "bastion.admin.apps.BastionAdminConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "tests.urls"

CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]


def _database() -> dict[str, object]:
    """Pick a backend from BASTION_TEST_DB, defaulting to in-memory SQLite.

    Connection details are overridable so that these sessions can be run
    locally without stopping whatever already owns the default port. The
    defaults are the CI service containers, so CI needs none of the overrides.
    """
    backend = os.environ.get("BASTION_TEST_DB", "sqlite")

    def connection(engine: str, user: str, port: str) -> dict[str, object]:
        return {
            "ENGINE": engine,
            "NAME": os.environ.get("BASTION_TEST_DB_NAME", "bastion"),
            "USER": os.environ.get("BASTION_TEST_DB_USER", user),
            "PASSWORD": os.environ.get("BASTION_TEST_DB_PASSWORD", "bastion"),
            "HOST": os.environ.get("BASTION_TEST_DB_HOST", "127.0.0.1"),
            "PORT": os.environ.get("BASTION_TEST_DB_PORT", port),
        }

    if backend == "postgres":
        return connection("django.db.backends.postgresql", "postgres", "5432")
    if backend == "mysql":
        return connection("django.db.backends.mysql", "root", "3306")
    return {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}


DATABASES = {"default": _database()}

# Secure by default in the test suite too, so that the deploy checks pass and
# a regression in them is visible rather than masked.
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SECURE_HSTS_SECONDS = 3600

# SSO only, with no password fallback. That is the shape the package is built
# for, and it keeps `check --deploy` clean on these settings: enabling
# ModelBackend alongside it without configuring break-glass trips E023.
AUTHENTICATION_BACKENDS = ["bastion.backends.SSOBackend"]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# The break-glass tests exercise real password checking, including the dummy
# hash that equalises timing on the unknown-account path. At default work
# factors that costs seconds per test for no added confidence.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
