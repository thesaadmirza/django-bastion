# Data inventory

What this package stores, for how long, and how to get rid of it. Written as
input to a DPIA rather than as a compliance claim — see
[what we cannot claim](#what-this-package-cannot-do-for-you) at the bottom.

## Tables

### `FederatedIdentity`

The link between a person at a provider and a local user.

| Field | Personal data | Why |
|---|---|---|
| `issuer` | no | The provider |
| `subject` | **yes** — an identifier | The provider's stable id for a person |
| `subject_source` | no | Which claim it came from |
| `connection`, `created_at`, `last_seen_at` | no / behavioural | |

Lawful basis is normally legitimate interests or contract: without this row the
application cannot tell who is signing in. Deleted by cascade when the user is.

### `AuditEvent`

**Contains no direct identifier.** This is deliberate and is what makes erasure
possible without rewriting records.

| Field | Personal data | Notes |
|---|---|---|
| `actor_pseudonym` | pseudonymous | Opaque token. Personal data while the mapping exists |
| `source_ip` | **yes** | Personal data in the EU. Nullable |
| `subject` | **yes** | The provider's identifier, for reconciliation against their log |
| `auth_methods`, `session_id` | no | Session id is hashed |
| `changes`, `reason`, `context` | depends | Whatever the caller put there |

### `AuditActor`

The only mapping from token to user. Deleting a row here is the erasure
mechanism.

### `BreakGlassAccount`

A flag, a reason, and timestamps. The password lives on the user model.

## What is deliberately not stored

- **Raw tokens, assertions or ID tokens.** Never written anywhere.
- **Access or refresh tokens.** Not persisted in this version.
- **Passwords for SSO users.** `set_unusable_password()` on provisioning.
- **Claim payloads.** `IdentityClaims.raw` exists in memory during a request and
  is not written to the audit log.

## Retention

Default 365 days for audit events, enforced by `bastion_audit purge`.

| Regime | What it actually requires |
|---|---|
| PCI DSS 10.5.1 | 12 months, 3 immediately available |
| FedRAMP (AU-11) | 1 year, 90 days online |
| CNIL Délib. 2021-122 | 6 months to 1 year; up to 3 years for documented internal-control needs |
| NIST AU-11, ISO 27001, SOC 2 | Organisation-defined. No number |
| **HIPAA** | **No audit-log retention period at all** |

That last row is worth dwelling on, because it is widely misstated. HIPAA's
six-year rule (§164.316(b)(2)(i)) covers required *documentation* — policies,
procedures, records of actions and assessments — not application logs. If
someone tells you HIPAA requires six years of audit logs, ask them which
provision.

365 days satisfies every regime that names a number. It is a default, not a
requirement, and choosing a different one is a decision to record rather than a
setting to leave alone.

## Erasure

```python
from bastion.audit.models import forget_actor
forget_actor(user, reason="subject access request 41")
```

This deletes the token-to-user mapping. Events survive, the hash chain stays
intact, and re-identification becomes impossible.

That last word is load-bearing. EDPB guidance is clear that pseudonymised data
remains personal data for as long as anyone holds the additional information,
and that the Article 11 route — where a controller who genuinely cannot
re-identify is relieved of some obligations — is only open to a controller who
**cannot**. Keeping a recoverable mapping and claiming Article 11 are mutually
exclusive. Deleting the row is what makes the claim true rather than
aspirational.

The erasure is itself recorded, with the reason.

### Why not redact the records instead

Rewriting records would break the hash chain, and a permanently broken
integrity check is one nobody reads. Pseudonymising from the first write avoids
the trade entirely.

### What survives an erasure

The events, including `source_ip` and `subject`. Those are arguably still
personal data in isolation, and whether retaining them is justified is a
field-by-field necessity assessment under Art. 17(3)(b)/(e) that only you can
make. If your assessment says they should go too, purge by date or narrow what
the caller passes.

Note that **CNIL Délibération 2021-122 §12** is the only regulator text found
that squarely blesses an audit log outliving the record it describes, calling
the overlap "often unavoidable and acceptable" given the security role logs
play. It also recommends timestamping and signing logs at creation, which is
what the chain does.

## A claim to never make

Crypto-shredding — destroying a key and calling the ciphertext erased — is
**not endorsed by any EU or UK regulator** as satisfying Art. 17. There is a
claim circulating in AI-written material that the EDPB, ICO and CNIL all
recognise it; a full-text search of EDPB Guidelines 5/2019 finds zero mentions
of encryption, and CNIL's blockchain paper says key deletion moves "closer to
the effects of data erasure" and then that it does "not, strictly speaking,
result in an erasure."

If that claim appears in anything you write about this package, remove it.

## What this package cannot do for you

- It is not GDPR, SOC 2, ISO 27001, HIPAA or PCI **compliant**. No software is.
  These regimes assess entities and systems, not libraries.
- It cannot set your retention period or your lawful basis.
- It cannot perform an access review, or evidence that access was *authorised*
  rather than merely granted.
- It cannot make deprovisioning instant. It can make its latency measurable,
  which is what auditors now sample on.
