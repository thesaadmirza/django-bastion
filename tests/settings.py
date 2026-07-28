"""Minimal settings so contributors can run `pytest` with no arguments."""

from __future__ import annotations

import os

# Long enough to satisfy security.W009. Still not a secret; this is the suite.
SECRET_KEY = "wQ7k2LpZ9vXn4RtY8mHbF3sJdA6cE1gU5oI0yTqNxVwPzKrMlBhGjSfDaCeZ"
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
    backend = os.environ.get("BASTION_TEST_DB", "sqlite")
    if backend == "postgres":
        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": "bastion",
            "USER": "postgres",
            "PASSWORD": "bastion",
            "HOST": "127.0.0.1",
            "PORT": "5432",
        }
    if backend == "mysql":
        return {
            "ENGINE": "django.db.backends.mysql",
            "NAME": "bastion",
            "USER": "root",
            "PASSWORD": "bastion",
            "HOST": "127.0.0.1",
            "PORT": "3306",
        }
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
