# Audit event catalogue

Every event type this package defines, with what it means and why it is
recorded.

Publishing this list is the NIST **AU-2(a)/(c)/(d)** deliverable: identify what
the system can log, specify what it does log, and give a rationale for why that
selection supports after-the-fact investigation. Without it, customers write it
by hand from source, badly.

Those first two are different questions, and this page used to answer only the
first while claiming to answer both. **Twelve of the thirty names below are
reserved and no code path emits them yet**, and each is marked. It matters
because an auditor reading an unmarked `auth.mfa.satisfied` row would go looking
for MFA records, and there are none. The rest of the vocabulary is here because
renaming an event later breaks every SIEM rule written against it, so the names
are fixed before the emitters land.

Three tests hold this page to it: every name in `bastion.audit.events.Event`
has to appear here, every event with no emitter has to be marked reserved, and
every event that gains one has to lose the marker. Wiring up an emitter without
updating this page fails the suite.

Event names are **stable public API**. Renaming one breaks anyone whose SIEM
rules or compliance evidence reference it.

## Authentication

| Event | Recorded when | Why it matters |
|---|---|---|
| `auth.login.succeeded` | A session is established | The baseline population for an access review |
| `auth.login.failed` | Authentication did not complete | Emitted on the failure path too — a failed login is the event most worth having |
| `auth.login.denied` | Authenticated, then refused | **Kept distinct from failure.** An authorisation denial and an authentication failure are different detections under SOC 2 CC7.2; collapsing them loses the signal that someone's credentials work but their access does not |
| `auth.logout` | A session was ended deliberately | `context.rp_initiated` says whether the provider's own session was ended too. False means only the local session went, so the person can be signed straight back in without a prompt, and an investigation into "they said they logged out" needs to know which happened |
| `auth.session.revoked` | **Reserved, not emitted yet.** Session ended by an administrator or the provider | |
| `auth.assertion.rejected` | Signature, issuer, audience, nonce, replay or clock validation failed | High signal. This is what a token forgery attempt looks like |
| `auth.protocol.fallback` | Break-glass was used or attempted | Rare by design, critical severity, always alerts |
| `auth.mfa.required` | **Reserved, not emitted yet.** A connection requires a second factor | |
| `auth.mfa.satisfied` | **Reserved, not emitted yet.** The assertion showed one | The only durable evidence an MFA requirement was met at the moment of access |
| `auth.mfa.missing` | The admin required a second factor and the session's assertion showed none | Distinguishes the person who needs a group from the person who needs to re-authenticate properly. Both are refused at the same page, and a service desk that cannot tell them apart adds the first to a group and changes nothing |

## Identity lifecycle

| Event | Recorded when |
|---|---|
| `user.provisioned` | A local account is created by a first login |
| `user.updated` | **Reserved, not emitted yet.** Attributes changed from claims |
| `user.deactivated` | **Reserved, not emitted yet.** An account was disabled |
| `user.reactivated` | **Reserved, not emitted yet.** An account was re-enabled |
| `user.identity_linked` | A provider identity was attached to a local user |
| `user.identity_unlinked` | **Reserved, not emitted yet.** It was detached |
| `user.identity_source_conflict` | The provider asserted a subject under a different claim than the link was made with |

`identity_linked` is frequently missing from packages and frequently the root
cause when an account takeover is investigated afterwards.

`identity_source_conflict` is critical severity and refuses the login. It almost
always means a configuration change — an Entra deployment switching from `sub`
to `oid`, say — and accepting it silently would create a duplicate account while
stranding the original's permissions.

## Authorisation

| Event | Recorded when |
|---|---|
| `role.granted` / `role.revoked` | A privilege flag changed |
| `mapping.evaluated` | **Reserved, not emitted yet.** Claims were mapped to roles |
| `mapping.incomplete` | Group data arrived truncated, so escalation was refused |
| `entitlement.snapshot` | **Reserved, not emitted yet.** Point-in-time record of who holds what |

`mapping.incomplete` is the one to alert on. Entra above its overage threshold
sends a pointer to Microsoft Graph rather than the groups themselves; the login
proceeds and privilege escalation does not. If you see these regularly, your
group filtering needs attention.

`entitlement.snapshot` is what lets an auditor answer "who had admin on 14
March" without reconstructing state from a change stream. Nothing emits it
automatically yet — that is a gap.

## Configuration and trust anchors

| Event | Recorded when |
|---|---|
| `idp.connection.changed` | **Reserved, not emitted yet.** A connection's configuration changed |
| `idp.jwks.refreshed` | **Reserved, not emitted yet.** The signing key set was refetched |
| `idp.metadata.refreshed` | **Reserved, not emitted yet.** The discovery document was refetched |

## The audit log's own operations

| Event | Recorded when |
|---|---|
| `audit.export.generated` | Evidence was exported, and by whom, covering what range |
| `audit.integrity.verified` / `.failed` | The chain was checked |
| `audit.retention.purged` | Records were removed by the retention policy |
| `audit.actor.forgotten` | A token-to-user mapping was destroyed |

`audit.retention.purged` exists so that a gap in the sequence has an
explanation. A hole with nothing accounting for it is indistinguishable from
evidence destruction, and a retention job should not resemble that.

`audit.export.generated` is the one regulators like more than auditors do.

## Severity

`info`, `notice`, `warning`, `critical`. These are alert-routing hints, not a
regime's classification.

Critical is reserved for: any break-glass outcome, `identity_source_conflict`,
and `audit.integrity.failed`.

## Record fields

See [the audit models](../../src/bastion/audit/models.py) for the full schema.
The six that every regime converges on — NIST AU-3, PCI 10.2.2, ISO 27002 8.15
are rewordings of the same list — are:

| Element | Field |
|---|---|
| What happened | `event_type` |
| When | `occurred_at` |
| Where | `source_ip` |
| Source | `issuer`, `connection` |
| Outcome | `outcome` |
| Who | `actor_pseudonym` |

Plus `chain_seq`, which is not required by anything and is the field auditors
end up caring most about: a gapless sequence is what lets a sampled export be
shown to be complete.
