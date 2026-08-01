# Roadmap

What exists, what does not, and what would change the answer. Dated 2026-07-28
at version 0.0.1a5.

## Now

OIDC login end to end, the Django admin behind it, an identity table, an audit
log with retention and export, break-glass, and a diagnostic command.

## v0.2 — the rule engine

Group mapping is currently two lists per connection. That covers the common case
and nothing else.

The replacement is an ordered rule table whose condition is a serializable
predicate tree over normalised claims, with:

- **`explain()` on every evaluation**, persisted with the audit record. "Why
  does this person have admin?" gets a click-through answer. Nothing in the
  ecosystem can answer it today
- **Dry run** against pasted claims or against the whole existing user table,
  before saving a change
- **Per-rule sync mode** — whether a rule re-applies on every login or only at
  provisioning. Every system that hardcodes one answer gets bug reports
- **Managed-group scoping**, so reconciliation never touches a locally created
  group

The design is settled. Two approaches were considered and rejected: arbitrary
Python stored in the database, which makes the mapping rules a remote code
execution surface administered through a web form, and JMESPath as the primary
language, which reads well for extraction but cannot express the precedence
rules that group-to-role mapping needs.

## v0.3 — SAML

Behind the `[saml]` extra, since it pulls in xmlsec and its system packages.

Gated on one piece of research: whether lxml, xmlsec1 and pysaml2 exhibit the
parser-differential behaviour PortSwigger demonstrated against Ruby and PHP
libraries. Nothing about the technique is language-specific, so assuming
immunity would be wishful. That test corpus has to exist before the adapter
ships.

## v0.4 — SCIM

A SCIM 2.0 service provider, so directory changes reach the application without
a login.

The interesting part is not the RFC, it is the dialects: Entra sends capitalised
`op` values and expects `excludedAttributes=members`; Okta requires
`filter=userName eq` and **never sends DELETE**, only `active:false`. RFC
conformance is necessary and nowhere near sufficient.

Deprovisioning must kill live sessions synchronously, which the machinery
already supports.

## v0.5 — multi-tenancy

The organisation foreign key exists and is nullable and swappable. What does not
exist is per-organisation self-service connection onboarding, which is a product
rather than a module and only matters for B2B SaaS.

## Not scheduled

- **Time-boxed privilege elevation.** Break-glass is emergency access; JIT
  elevation is a different feature and needs its own design
- **`entitlement.snapshot` emission.** The event type is defined and nothing
  emits it, so point-in-time entitlement reporting does not work yet
- **SSF/CAEP events.** The standards-track answer to cross-domain session
  revocation. No Django package emits them, and it is unclear whether that is an
  opportunity or an absence of demand
- **LDAP and trusted-proxy adapters.** The seam exists; the adapters do not

## Before 1.0, regardless of features

**A second maintainer.** Bus factor 1 disqualifies this from anything that
cannot be forked, and no amount of test coverage changes that.

**An independent security audit**, published in full including unfixed findings.
The unfixed ones are what make it credible.

**OpenID Foundation RP certification.** In this domain it is worth more than
most generic trust signals, and it is a forcing function for correctness.

## What would change these priorities

Real usage. Every ordering above is a guess about what people need, made by
someone who has read a great deal about the problem and deployed this exactly
zero times in anger. Tell us what breaks.
