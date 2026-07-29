# Security policy

## Reporting a vulnerability

**Do not open a public issue.** Report privately through
[GitHub Private Vulnerability Reporting](../../security/advisories/new).

We will acknowledge your report within **3 working days** and aim to ship a fix within **90 days** of the
initial report. If we cannot meet 90 days we will tell you why and agree a revised date with you.

## What is in scope

A report needs to meet all three of these:

1. It reproduces against a supported version of this package, on a supported version of Django and Python.
   See [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md).
2. It applies to a deployment that follows our [deployment checklist](docs/security/deployment-checklist.md).
3. It does not depend on the operator configuring the package in a way we document as unsafe.

We publish a [threat model](docs/security/threat-model.md) with an explicit out-of-scope section. Please
read it first — it says what this package defends against and, more usefully, what it does not.

Not in scope: anything premised on the application failing to sanitise its own input, anything requiring
`DEBUG = True`, and resource exhaustion below the limits we document.

## AI-assisted reports

If you used an AI tool to find or write up the issue, say so and say which. Verify the vulnerability is
real and reproducible before sending it. We close unverified machine-generated reports without a
substantive response.

## Severity

We classify using the same scheme as the Django project, with one deviation.

- **High.** Remote code execution, SQL injection, authentication bypass, privilege escalation across
  tenants.
- **Moderate.** XSS, CSRF, session fixation.
- **Low.** Denial of service, information disclosure, issues requiring uncommon configuration.

The deviation: because this package performs authentication and authorisation, we treat **authentication
bypass and incorrect role assignment as High**. Upstream Django classifies broken authentication as
Moderate. A package whose entire job is deciding who gets to be staff should hold itself to the stricter
line.

## What happens next

1. We confirm and classify the report, and agree a disclosure date with you.
2. We develop the fix in a private fork and request a CVE from GitHub's CNA.
3. **48 hours before release** we post the date, the severity and the affected versions — and nothing else
   — to GitHub Discussions and the release feed.
4. On the day, in this order: releases for every supported series go to PyPI, signed tags are pushed, the
   GitHub Security Advisory is published, the advisory page goes up in our docs, and we notify
   `oss-security@lists.openwall.com`.
5. A week later we publish a post-mortem naming the test that would have caught it. We write that test
   first.
6. We credit reporters by name unless you ask us not to.

## What we do not do

We do **not** operate a private advance-notification list for distributors or downstream users. Django runs
one, and it works because Django has the people to vet membership. We do not. An embargo list nobody has
capacity to vet is a leak with extra steps, not a control. Everyone finds out at the same time, 48 hours
after the heads-up in step 3.

If that changes, we will amend this document and announce it rather than quietly starting one.

We also do not couple our disclosure date to the publication of the GitHub advisory. The Advisory Database
has been running multi-week publication delays; we request the CVE early and ship on our own schedule.

## Supported versions

See [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md). We ship security fixes for the current minor series and the
previous one. Before 1.0, only the latest release gets fixes.

## Our own supply chain

Releases are published through PyPI Trusted Publishing, so no long-lived API token exists to be stolen:
the workflow exchanges a short-lived OIDC identity with PyPI directly. Distributions carry PEP 740
attestations, signed with that same identity and verifiable against this repository and
[`.github/workflows/release.yml`](.github/workflows/release.yml).

A CycloneDX SBOM is generated from a clean environment holding the wheel and nothing else, and is attached
to the corresponding [GitHub release](https://github.com/thesaadmirza/django-bastion/releases). It is not
inside the wheel: PyPI accepts distributions only, and the standard for carrying one in a wheel
([PEP 770](https://peps.python.org/pep-0770/)) has no build-backend support we can rely on yet.

A release is cut only from a tag whose name matches the version in `pyproject.toml`, and only after the
suite passes on the oldest and newest supported interpreters. Nothing on that path restores a build cache,
because a cache is writable from any branch and an attestation would faithfully certify a poisoned wheel.

Every GitHub Action is pinned to a full commit SHA, with the tag kept in a trailing comment.

Git tags are not signed yet, so do not treat a tag as evidence of anything. The attestation on the
distribution is the artefact to check, and it is verifiable today against this repository and that
workflow. [MAINTAINERS.md](MAINTAINERS.md) says the same thing and will carry a key fingerprint when there
is one.

If you find a way to get code into a release that does not go through that path, that is a High severity
report and we want to hear about it.
