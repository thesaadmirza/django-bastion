# Cryptographic inventory

Every algorithm, key and library this package touches. Public-sector and
regulated reviewers ask for this and almost nobody has it ready.

Last reviewed: 2026-07-30, against version 0.0.1a2.

## Libraries

| Purpose | Library | Notes |
|---|---|---|
| All asymmetric signature verification | `cryptography` | The only cryptographic dependency on the OIDC path |
| Hashing, HMAC, random | Python standard library (`hashlib`, `hmac`, `secrets`) | |
| Session and signing infrastructure | Django | `SECRET_KEY`-derived |
| SAML (optional extra) | `pysaml2`, and `xmlsec1` beneath it | Not yet implemented |

There is deliberately **no JOSE or OAuth library**. Every policy decision such a
library would make on our behalf is one this package overrides — algorithm
pinning, key resolution, header key material, `crit` handling — and their CVE
records sit almost entirely in that policy layer. See
[the OIDC package docstring](../../src/bastion/protocols/oidc/__init__.py) for
the reasoning.

## Signature verification

| Item | Value |
|---|---|
| Accepted algorithms | `RS256` `RS384` `RS512` `PS256` `PS384` `PS512` `ES256` `ES384` `ES512` `EdDSA` |
| Rejected | Every symmetric algorithm, and `none` |
| Curves | P-256, P-384, P-521, Ed25519 |
| RSA padding | PKCS#1 v1.5 for `RS*`, PSS with MGF1 and digest-length salt for `PS*` |
| Minimum key size | Whatever the provider publishes; not enforced locally |

Symmetric algorithms are refused rather than guarded. Signing an ID token with
the client secret is the substrate of the algorithm-confusion class, where an
attacker signs with HMAC using the provider's *public* key. Excluding the family
removes the class instead of defending against it.

Expressing the list as an allowlist is what makes `alg: none` unreachable
without a special case for it.

## Keys we hold

| Key | Where | Rotation |
|---|---|---|
| `SECRET_KEY` | Django settings | Yours. Rotating it invalidates every session and every signed audit manifest |
| OIDC client secret | Connection config | Yours, at the provider's cadence |
| SCIM bearer tokens | Not yet implemented | |

## Keys we fetch

| Key | Source | Cache |
|---|---|---|
| Provider signing keys | JWKS URI from the discovery document, https only | In memory, refetched on unknown `kid`, rate limited to 1/minute and 5/hour |

Rate limiting exists because an attacker who can post tokens carrying arbitrary
`kid` values must not be able to drive one outbound request per token.

## Random values

All from `secrets`, which uses the OS CSPRNG.

| Value | Bits | Purpose |
|---|---|---|
| `state` | 128 | Transaction lookup key and CSRF defence |
| `nonce` | 128 | ID token replay defence |
| PKCE `code_verifier` | 256 | Authorization code injection defence |
| Audit actor pseudonym | 192 | Opaque token; deleting its mapping is the erasure mechanism |
| Correlation reference | 32 | Human-readable, discloses nothing by itself |

## Hashes

| Use | Algorithm |
|---|---|
| PKCE challenge | SHA-256, `S256` only. `plain` is refused |
| `at_hash` | Derived from the pinned token algorithm. Cannot-compute is a rejection |
| Audit record hash | SHA-256 over a fixed, explicitly ordered payload |
| Session identifier in audit records | SHA-256, truncated to 32 hex characters |
| Passwords (break-glass only) | Django's configured hasher |
| Export manifest | Django signing, HMAC-SHA-256 from `SECRET_KEY` |

The audit digest payload has a **fixed field order written out by hand** rather
than derived from the model, so that adding a field does not silently change the
hash of records already written.

Two things this table used to list and should not have. `c_hash` is not
validated: it belongs to the hybrid flow, and this package only implements the
authorization code flow, so the claim never arrives. And `kid` is read from the
provider's JWKS rather than computed, so no RFC 7638 thumbprint is taken
anywhere. A key set whose `kid` values are wrong would be the provider's
problem to notice, not ours.

## What is not encrypted

Stated because omissions are what get missed:

- **Audit records at rest.** Database-level encryption is yours to configure.
- **Encrypted ID tokens (JWE) are refused outright.** Partly because the
  compressed variant is a decompression bomb.
- **Refresh tokens are not stored at all** in this version.
- **Client secrets in settings** are as protected as your settings are.

## FIPS

Untested. `cryptography` can be built against a FIPS-validated OpenSSL, and
nothing here uses an algorithm outside FIPS 140-3 except Ed25519, which is
approved under FIPS 186-5 but whose validation status depends on your module. If
you need a FIPS claim, restrict the algorithm allowlist per connection and
validate it yourself — we do not make that claim.
