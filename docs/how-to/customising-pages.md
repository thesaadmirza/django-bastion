# Customising the pages

This package renders four pages: the access-denied page, the sign-in failure
page, the signed-out page, and the emergency-access form. They look like the
Django admin wherever the admin is available, and fall back to a plain
self-contained layout where it is not.

## How the base is chosen

Each page begins with

```django
{% extends base_template|default:"bastion/base.html" %}
```

and the views pass `base_template` per request, resolved by
[`bastion/pages.py`](../../src/bastion/pages.py):

| Condition | Base |
|---|---|
| `django.contrib.admin` installed **and** `admin:index` reverses | `admin/base_site.html` |
| Either is false | `bastion/base.html` |

Both halves of that check are load-bearing. Without the app installed its
template directory is not on the loader path and the `extends` raises
`TemplateDoesNotExist`. Without the URLs routed, `base_site.html` reverses
`admin:index` in its branding block and raises `NoReverseMatch` — which would
turn a 403 page into a 500. A project that lists the app but disables the admin
in one environment is a normal thing, so both are checked.

The denial page rendered from `SSOAdminSiteMixin.render_access_denied` always
gets the admin base without checking, because that method is only reachable
through `AdminSite`.

## Overriding a page

Add a directory to `TEMPLATES["DIRS"]`:

```python
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        ...
    },
]
```

Then create the file at the same name. The filesystem loader runs before app
directories, so yours wins:

```
templates/bastion/access_denied.html
```

To keep the packaged content and change only the chrome, extend a different base
and leave the blocks alone. The block names are the admin's — `title`,
`extrastyle`, `bodyclass`, `content_title`, `content` — so a page works under
either base, and admin-only blocks like `usertools` become no-ops under
`bastion/base.html` because Django ignores a child block with no matching parent
block.

### Forcing the plain layout

To opt one page out of the admin styling, override it and pin the base:

```django
{# templates/bastion/break_glass.html #}
{% extends "bastion/base.html" %}
{% block content %}{{ block.super }}{% endblock %}
```

That is worth considering for `break_glass.html` specifically if your static
assets share a failure domain with your identity provider. Under the admin base
the layout comes from `admin/css/base.css`, and this is the one page reached
*during* an incident. The packaged template keeps its critical rules in an inline
`{% block extrastyle %}` for exactly that reason, so the warning stays legible
and the fields stay usable when the stylesheet does not arrive. Do not remove
that block.

## The context each page gets

| Template | Variables |
|---|---|
| `access_denied.html` | `identity`, `required_groups`, `reference`, `logout_url`, `base_template` |
| `login_failed.html` | `reference`, `base_template` |
| `logged_out.html` | `reference`, `provider_session_ended`, `base_template` |
| `break_glass.html` | `reference`, `error`, `base_template` |

None of them receive `AdminSite.each_context()`, so `site_header`, `title`,
`has_permission`, `available_apps` and `is_nav_sidebar_enabled` are absent. The
admin templates default `site_header` and treat the rest as falsey, which is why
the user tools and the nav sidebar do not appear. That is the right outcome for
someone with no access, and the pages suppress those blocks explicitly rather
than relying on it.

## What not to change

Three of these carry a security or safety policy in their content, not only in
their markup.

**`login_failed.html` says nothing useful on purpose.** It is served for every
pre-authentication failure with one body and one status. Varying it by cause
tells whoever is probing which of their guesses was closer. It is also what the
break-glass route returns as a 404 when break-glass is disabled, so it must read
as an ordinary failure page rather than hinting that something exists behind it.
Restyle it; do not add a reason.

**`access_denied.html` is specific on purpose**, which is the opposite policy for
the opposite reason: identity is already proven, so there is no account to
enumerate. If your organisation treats group names as sensitive, replacing the
`required_groups` block with a generic phrase is a supported change. Everything
else is what stops the person filing a ticket that says only "access denied".

**`logged_out.html` must keep saying the provider session survived** when
`provider_session_ended` is false. Someone on a shared machine who believes they
have signed out, and has not, is the reason the page exists instead of a redirect
to the home page.

**Every sign-out control must be a POST.** Django's `LogoutView` is POST-only, so
an `<a href>` to it is a dead link.

## Two template-language traps

A multi-line `{# ... #}` is **not** a comment. The single-hash form is
single-line only, and a multi-line one renders as visible text on the page. Use
`{% comment %}`.

`{% extends %}` takes a filter expression, which is why
`base_template|default:"bastion/base.html"` works. It also means the variable is
resolved before inheritance, so `base_template` cannot be set from inside a
block.
