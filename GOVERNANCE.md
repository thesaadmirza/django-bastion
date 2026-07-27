# Governance

## Bus factor: 1

One maintainer. If they stop, this project stops.

We state that at the top rather than burying it, because it is the first thing anyone evaluating an
authentication dependency should know, and because a vendor risk assessment will find it anyway. If you are
considering depending on this package for something you cannot afford to fork, weigh that above any
feature in the README.

Raising this number is a tracked deliverable, not an aspiration. The target is a second maintainer with
commit and release rights, from a different organisation, before 1.0. Progress is tracked in the
[roadmap](docs/explanation/roadmap.md).

## Who decides what

Until there is a second maintainer, decisions are made by the maintainer, in public, on the issue tracker.
Design decisions of any significance go in [FOUNDATIONS.md](FOUNDATIONS.md) with the reasoning and the
sources, so that a future maintainer can tell what was decided deliberately and what was an accident.

When there is a second maintainer:

- Changes to `src/bastion/protocols/`, `rules/`, `audit/` and `breakglass/` need review from a maintainer
  who did not write them. This is enforced through `CODEOWNERS`, not convention.
- A maintainer may not merge their own change to those paths.
- Everything else needs one approving review.
- Disagreement that survives discussion goes to a simple majority. There is no tie-break mechanism yet
  because with two people there is no tie worth automating.

## Becoming a maintainer

There is no fixed contribution count. What we are looking for is sustained, unsupervised judgement in this
domain: reviews that catch real problems, issues triaged accurately, and a demonstrated instinct for when
a change to the authorisation path is riskier than it looks.

If you work at an organisation that runs this in production, that is a strong signal rather than a conflict
of interest. Every long-lived package in this space is maintained by people who need it to work.

Ask by opening an issue. We will say yes or no with reasons.

## Contributions

DCO sign-off (`git commit -s`), not a CLA. A contributor licence agreement on a security package reads as
"we are reserving the right to relicense," which is exactly the doubt this project cannot afford, and it
puts a signup wall in front of drive-by security fixes — the contributions we most want. See
[CONTRIBUTING.md](CONTRIBUTING.md).

If the project ever needs copyright aggregation to move under a foundation, we will negotiate that then,
with a known contributor set, rather than pre-emptively collecting rights we do not need.

## Funding

GitHub Sponsors is open. Nothing is behind it — there is no paid tier, no early access, and no
private advisory list for sponsors.

If commercial support ever exists, it will cover operational work: managed connectors, migration
assistance, response-time commitments. It will not cover correctness. The moment SAML signature validation
or the audit log lives in a paid tier, there is an incentive to under-secure the free one, and every
reviewer will notice.

## Ending the project

If the maintainer can no longer continue and no successor is found, we will:

1. Announce it in the README, in a release, and on `oss-security`.
2. Mark the PyPI project as inactive rather than deleting it.
3. Leave the repository and its history public and archived.
4. Ship a final release with a deprecation warning naming the last version we believe to be secure.

We will not silently stop. An abandoned authentication package that still looks maintained is worse than
one that says so.
