# django-bastion

Enterprise SSO and identity governance for Django.

> **Pre-alpha.** OIDC works end to end; SAML and SCIM do not exist yet. Read
> [why you might not want this](explanation/why-you-might-not-want-this.md)
> before adopting it.

These docs follow [Diátaxis](https://diataxis.fr/): four sections, each
answering a different kind of question. If you are evaluating rather than
building, start with the security pages.

## Evaluating

Read in this order:

1. [Threat model](security/threat-model.md) — what this defends against, and the
   out-of-scope section that makes the rest checkable
2. [Why you might not want this](explanation/why-you-might-not-want-this.md)
3. [Cryptographic inventory](security/crypto-inventory.md)
4. [Data inventory](security/data-inventory.md) — what is stored, for how long,
   and how erasure works
5. [Deployment checklist](security/deployment-checklist.md)

## Tutorials

Learning-oriented, start to finish.

- [Your first login](tutorials/first-login.md)

## How-to guides

Task-oriented. Assume you know what you are doing.

- [Microsoft Entra ID](how-to/idp/entra.md)
- Okta — not written yet
- Google Workspace — not written yet
- Keycloak — not written yet
- [Customising the pages](how-to/customising-pages.md) — how the base template is
  chosen, how to override a page, and which content is load-bearing

## Reference

- [Settings](reference/settings.md)
- [Provider matrix](reference/providers.md) — what each provider gives you, and how far each profile has
  actually been proven
- [Audit event catalogue](reference/audit-events.md)

## Security operations

- [Deployment checklist](security/deployment-checklist.md)
- [Break-glass runbook](security/break-glass-runbook.md)
- [Threat model](security/threat-model.md)

## Explanation

Background and design reasoning.

- [Why you might not want this](explanation/why-you-might-not-want-this.md)
- [Roadmap](explanation/roadmap.md) — what is deliberately not built yet, and why

## Reporting a vulnerability

Privately, through GitHub. See [SECURITY.md](../SECURITY.md), which also states
plainly what we do **not** do — there is no private advance-notification list,
and pretending otherwise would be worse than saying so.
