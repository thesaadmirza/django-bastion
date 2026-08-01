# Why you might not want this

Written because the alternative is you finding out later, and because a project
that cannot describe when it is the wrong choice has usually not thought hard
about when it is the right one.

## Use django-allauth instead if you need social login

[django-allauth](https://docs.allauth.org/) is mature, covers every social
provider, has MFA, and does roughly 4.6 million downloads a month. If your
requirement is "let people sign in with Google", it is the answer and this is
not.

The two are not really competitors. allauth is account management with
federation attached; this is federation with governance attached. They compose,
and an adapter to run them together is on the roadmap.

## Use mozilla-django-oidc instead if you only need OIDC

[mozilla-django-oidc](https://github.com/mozilla/mozilla-django-oidc) is about
1,200 lines across five files. You can read all of it in twenty minutes and
understand exactly what your authentication does.

That legibility is a real feature and this package does not have it. There is
more here — a claims layer, provider quirks, an audit chain, break-glass — and
all of it is code you would be trusting.

Come here when you need the governance layer. Do not come here to avoid reading
1,200 lines.

## Buy it instead if you are a B2B SaaS with a budget

WorkOS and Stytch charge around $125 per connection per month and will get you
enterprise SSO faster than building will. They also give you the per-customer
self-service onboarding portal that this package does not have and is not close
to having.

This is the better answer when self-hosting is a requirement rather than a
preference, when the **Django admin itself** is what needs to go behind SSO —
which those products do not address at all — or when connection count makes
per-connection pricing hurt.

## Do not use this if you cannot afford to fork it

The bus factor is 1. One maintainer, stated at the top of
[GOVERNANCE.md](../../GOVERNANCE.md) rather than buried, because a vendor risk
assessment will find it anyway.

If this project stopped tomorrow, could you maintain the authentication path of
your application yourself? If the answer is no, weigh that above any feature
listed anywhere else in these docs.

## Do not use this expecting a compliance certificate

It produces evidence for controls that *you* operate. It is not SOC 2, ISO
27001, HIPAA, FedRAMP or PCI compliant, because no software is — those regimes
assess entities, management systems and systems, not libraries.

Specifically, it cannot:

- evidence that access was *authorised*, only that it was *granted*
- perform an access review
- set your retention period or your lawful basis
- make deprovisioning instant, only make its latency measurable

See [data inventory](../security/data-inventory.md) for the full list.

## Things that are missing right now

At version 0.0.1a4:

- **SAML.** Planned, not built. If you need it today, use
  [djangosaml2](https://github.com/IdentityPython/djangosaml2) or allauth.
- **SCIM.** Planned, not built. No automated deprovisioning from your directory.
- **The rule engine.** Group mapping is currently two lists per connection. The
  predicate tree with `explain()` and dry-run — the thing that makes "why does
  this person have admin?" answerable — is v0.2.
- **Multi-tenancy.** The model supports it; there is no self-service onboarding.
- **Time-boxed privilege elevation.** Break-glass exists; JIT elevation does not.
- **`entitlement.snapshot`** is defined and nothing emits it, so point-in-time
  entitlement reporting is not available yet.

## What it is genuinely good at

For balance, and because the list is short and specific:

- Putting the Django admin behind an identity provider without a redirect loop.
- Not getting the identity-linking wrong. Keying on `(issuer, subject)` with
  Entra's pairwise `sub` handled correctly is a mistake with live CVEs attached,
  and this gets it right by construction.
- Refusing to escalate privileges on incomplete group data. Nothing else in the
  ecosystem draws that distinction.
- An audit log that survives an erasure request without breaking.
- Telling you what it cannot verify instead of showing green.
