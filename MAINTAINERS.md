# Maintainers

| Name | GitHub | Areas | Key fingerprint |
|---|---|---|---|
| Saad Mirza | [@thesaadmirza](https://github.com/thesaadmirza) | everything | not yet published |

Release tags are signed. Until a fingerprint appears above, treat tag signatures
as unverified — an unverifiable signature is worse than none, because it invites
the assumption that someone checked.

## Bus factor: 1

One maintainer. If they stop, the project stops.

Recruiting a second, from a different organisation, with commit and release
rights, is a tracked deliverable before 1.0. See
[GOVERNANCE.md](GOVERNANCE.md) for what that changes and how to ask.

## Areas needing a second pair of eyes

Changes under these paths should not be merged by their own author once there is
more than one maintainer, and `CODEOWNERS` will enforce it:

- `src/bastion/protocols/` — signature verification and claim validation
- `src/bastion/audit/` — the evidence trail
- `src/bastion/breakglass/` — the path that bypasses SSO by design
- `src/bastion/backends.py` — identity resolution
