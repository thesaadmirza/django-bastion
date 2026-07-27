"""Demonstrate the startup checks firing on a deliberately bad configuration.

Run: python tests/manual_check_demo.py
Not part of the automated suite; tests/test_checks.py covers the same ground.
"""

from __future__ import annotations

import django
from django.conf import settings

import tests.settings as base

config = {k: getattr(base, k) for k in dir(base) if k.isupper()}
config["SESSION_COOKIE_SECURE"] = False
config["SECURE_HSTS_SECONDS"] = 0
config["SESSION_ENGINE"] = "django.contrib.sessions.backends.signed_cookies"
config["AUTHENTICATION_BACKENDS"] = [
    "bastion.backends.SSOBackend",
    "django.contrib.auth.backends.ModelBackend",
]
config["BASTION"] = {"IDENTITY": {"KEY": ("email",)}}

settings.configure(**config)
django.setup()

from django.core.checks import run_checks

for message in run_checks(include_deployment_checks=True):
    if str(message.id).startswith("bastion"):
        print(f"{message.id:<16} {message.msg[:70]}")
