"""Safe return-URL handling.

Django ships the hard part. What this module adds is the policy: which hosts
count as allowed, and that the answer defaults to "only this one".

The trap worth naming is that ``ALLOWED_HOSTS`` is **not** the allowlist here.
A host being in ``ALLOWED_HOSTS`` means Django will serve requests for it, not
that we should redirect a freshly-authenticated session to it.
``LoginView.get_success_url_allowed_hosts`` uses ``{request.get_host()}`` plus
an explicit per-view set, and we follow that.
"""

from __future__ import annotations

from collections.abc import Iterable

from django.http import HttpRequest
from django.utils.http import url_has_allowed_host_and_scheme


def safe_redirect_url(
    url: str | None,
    *,
    request: HttpRequest,
    extra_allowed_hosts: Iterable[str] = (),
    fallback: str,
) -> str:
    """Return ``url`` if it is safe to redirect to, else ``fallback``.

    Silently substituting the fallback rather than raising is deliberate and
    matches Django's own behaviour: a hostile ``next`` is usually a link
    someone was sent, and the person clicking it has done nothing wrong. They
    should land somewhere sensible, not on an error page.

    The rejection is still worth recording, which the caller does.
    """
    if not url:
        return fallback

    allowed = {request.get_host(), *extra_allowed_hosts}
    if url_has_allowed_host_and_scheme(
        url=url, allowed_hosts=allowed, require_https=request.is_secure()
    ):
        return url
    return fallback


def is_safe_redirect_url(
    url: str | None,
    *,
    request: HttpRequest,
    extra_allowed_hosts: Iterable[str] = (),
) -> bool:
    """Predicate form, for callers that want to log the rejection."""
    if not url:
        return False
    allowed = {request.get_host(), *extra_allowed_hosts}
    return url_has_allowed_host_and_scheme(
        url=url, allowed_hosts=allowed, require_https=request.is_secure()
    )
