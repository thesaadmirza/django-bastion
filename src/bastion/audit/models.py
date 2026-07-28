"""Audit storage.

Three tables, each with a job.

``AuditActor`` maps an opaque token to a user. It is the only place the two are
associated, which is what makes erasure possible without touching the events.

``AuditEvent`` is append-only. Both ``save`` on an existing row and ``delete``
raise, so a mistake is a traceback rather than a silent rewrite. That is not a
security control by itself -- anyone with database access bypasses it -- but it
does stop the accidental case, which is the common one.

``AuditChain`` holds the head sequence number and hash. It is locked for the
duration of a write, which serialises event insertion. That is a real cost and
a deliberate one: a gapless sequence is what lets an exported sample be shown
to be complete, and auditors challenge completeness far more often than they
challenge content.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import secrets
import time
from typing import Any, NoReturn

from django.conf import settings
from django.db import OperationalError, models, transaction
from django.utils import timezone

from bastion.audit.events import Event, Outcome, Severity

#: Bumped when the field set changes. Retention spans multi-year windows and
#: the schema will move inside a single audit period; without this, old records
#: become uninterpretable and the evidence dies with them.
SCHEMA_VERSION = 1

DEFAULT_CHAIN = "default"


class AuditActor(models.Model):
    """The only link between an opaque token and a person.

    Deleting a row here makes every event that references its token
    permanently unattributable. That is the erasure mechanism, and it is why
    events never store a user id directly.
    """

    pseudonym = models.CharField(max_length=64, unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_actor",
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        verbose_name = "audit actor"

    def __str__(self) -> str:
        return self.pseudonym

    @classmethod
    def for_user(cls, user: Any) -> AuditActor:
        actor, _ = cls.objects.get_or_create(
            user=user, defaults={"pseudonym": secrets.token_urlsafe(24)}
        )
        return actor


#: How many times an append may be reissued after the server aborted it to
#: break a deadlock. Small on purpose: contention here is short-lived, and a
#: long retry loop holding a request thread is its own availability problem.
_APPEND_ATTEMPTS = 4

#: Base delay, doubled each attempt. Without a pause the retry re-enters the
#: same contention it just lost.
_APPEND_BACKOFF = 0.02

#: Server-side codes meaning "you lost a lock race, try again", as opposed to
#: anything else OperationalError covers. Matching on these rather than
#: retrying every OperationalError keeps a genuinely broken connection or a
#: full disk from being retried three times before it is reported.
#:
#: MySQL 1213 deadlock, 1205 lock wait timeout. PostgreSQL 40001 serialization
#: failure, 40P01 deadlock detected.
_MYSQL_LOCK_ERRORS = frozenset({1205, 1213})
_POSTGRES_LOCK_STATES = frozenset({"40001", "40P01"})


def _is_lock_contention(exc: OperationalError) -> bool:
    """Whether the server aborted this transaction over a lock, not a fault."""
    cause = exc.__cause__ or exc

    sqlstate = getattr(cause, "sqlstate", None)
    if sqlstate in _POSTGRES_LOCK_STATES:
        return True

    args = getattr(cause, "args", ())
    if args and isinstance(args[0], int) and args[0] in _MYSQL_LOCK_ERRORS:
        return True

    # psycopg exposes the state under a different attribute depending on
    # version, so fall back to it before giving up.
    diag = getattr(cause, "diag", None)
    return getattr(diag, "sqlstate", None) in _POSTGRES_LOCK_STATES


class AuditEventQuerySet(models.QuerySet["AuditEvent"]):
    def in_order(self) -> AuditEventQuerySet:
        return self.order_by("chain", "chain_seq")

    def for_actor(self, pseudonym: str) -> AuditEventQuerySet:
        return self.filter(actor_pseudonym=pseudonym)


class AppendOnly(Exception):
    """Raised on any attempt to modify or remove a recorded event."""


class AuditEvent(models.Model):
    """One recorded thing that happened."""

    # -- AU-3's six elements ------------------------------------------------
    event_type = models.CharField(max_length=64, db_index=True)
    occurred_at = models.DateTimeField(db_index=True)
    #: The gap between this and occurred_at makes clock skew visible, which is
    #: what makes occurred_at trustworthy. Not mandated by anything.
    recorded_at = models.DateTimeField(default=timezone.now, editable=False)
    outcome = models.CharField(max_length=16, db_index=True)
    actor_pseudonym = models.CharField(max_length=64, blank=True, db_index=True)
    actor_type = models.CharField(max_length=16, default="user")
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    target_type = models.CharField(max_length=64, blank=True)
    target_id = models.CharField(max_length=255, blank=True)

    # -- identity domain ----------------------------------------------------
    #: The provider's subject. Lets an auditor reconcile this log against the
    #: provider's own, and the reconciliation is the evidence.
    subject = models.CharField(max_length=255, blank=True)
    issuer = models.CharField(max_length=255, blank=True)
    connection = models.CharField(max_length=100, blank=True, db_index=True)
    #: Impersonation. AC-6(9) and CC7.2 both fail silently without it: a
    #: support engineer acting as a customer must not be indistinguishable
    #: from the customer.
    on_behalf_of = models.CharField(max_length=64, blank=True)
    auth_protocol = models.CharField(max_length=32, blank=True)
    #: The only durable evidence that an MFA requirement was met at the moment
    #: of access. A screenshot of a policy page is weaker.
    auth_methods = models.JSONField(default=list, blank=True)
    session_id = models.CharField(max_length=64, blank=True)
    correlation_id = models.CharField(max_length=32, blank=True, db_index=True)

    # -- change and justification -------------------------------------------
    #: {field: {from, to}}. Structurally diffable, never prose.
    changes = models.JSONField(default=dict, blank=True)
    reason = models.TextField(blank=True)
    is_privileged = models.BooleanField(default=False, db_index=True)
    severity = models.CharField(max_length=16, default=Severity.INFO)
    context = models.JSONField(default=dict, blank=True)

    # -- integrity ----------------------------------------------------------
    chain = models.CharField(max_length=64, default=DEFAULT_CHAIN, db_index=True)
    #: The completeness field. Gapless, so an export can be shown to be whole.
    #: Higher evidentiary value than the hash chain, and cheaper.
    chain_seq = models.BigIntegerField()
    prev_hash = models.CharField(max_length=64, blank=True)
    record_hash = models.CharField(max_length=64, editable=False)
    schema_version = models.PositiveSmallIntegerField(default=SCHEMA_VERSION)

    objects = AuditEventQuerySet.as_manager()

    class Meta:
        verbose_name = "audit event"
        ordering = ("-occurred_at", "-chain_seq")
        constraints = [
            models.UniqueConstraint(
                fields=["chain", "chain_seq"], name="bastion_audit_chain_seq_unique"
            )
        ]
        indexes = [
            models.Index(fields=["event_type", "occurred_at"]),
            models.Index(fields=["actor_pseudonym", "occurred_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.chain_seq} {self.event_type} {self.outcome}"

    # -- append-only --------------------------------------------------------

    def save(self, *args: Any, **kwargs: Any) -> None:
        if self.pk is not None:
            raise AppendOnly(
                "Audit events cannot be modified. If a correction is needed, "
                "record a new event describing it."
            )
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise AppendOnly(
            "Audit events cannot be deleted individually. Use the retention "
            "policy, which records what it removed."
        )

    # -- integrity ----------------------------------------------------------

    def digest_payload(self) -> str:
        """The canonical bytes the record hash covers.

        Field order is fixed and explicit rather than derived from the model,
        so that adding a field does not silently change the hash of records
        already written.
        """
        return json.dumps(
            {
                "chain": self.chain,
                "seq": self.chain_seq,
                "prev": self.prev_hash,
                "type": str(self.event_type),
                "at": self.occurred_at.isoformat(),
                "outcome": str(self.outcome),
                "actor": self.actor_pseudonym,
                "actor_type": self.actor_type,
                "ip": self.source_ip or "",
                "target": [self.target_type, self.target_id],
                "subject": self.subject,
                "issuer": self.issuer,
                "connection": self.connection,
                "changes": self.changes,
                "reason": self.reason,
                "privileged": self.is_privileged,
                "schema": self.schema_version,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    def compute_hash(self) -> str:
        return hashlib.sha256(self.digest_payload().encode()).hexdigest()


class AuditChain(models.Model):
    """Head of one append-only chain.

    Locked for the duration of a write. That serialises event insertion, which
    is a genuine throughput cost, and it buys a gapless sequence: the property
    that makes a sampled export defensible.
    """

    name = models.CharField(max_length=64, primary_key=True)
    last_seq = models.BigIntegerField(default=0)
    last_hash = models.CharField(max_length=64, blank=True)
    #: Everything at or below this was removed by the retention policy. Without
    #: it, the first purge makes verification report a gap for the rest of the
    #: chain's life, and a permanently failing integrity check is one nobody
    #: reads.
    purged_through_seq = models.BigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "audit chain"

    def __str__(self) -> str:
        return f"{self.name}@{self.last_seq}"

    @classmethod
    def append(cls, event: AuditEvent) -> AuditEvent:
        """Assign the next sequence number and link the hash, retrying on
        lock contention.

        Both MySQL and PostgreSQL document that an application must be prepared
        to reissue a transaction that the server aborted to break a deadlock,
        and on MySQL this is not hypothetical: InnoDB under REPEATABLE READ
        takes gap locks around the ``select_for_update`` here, so concurrent
        first-writes to a chain deadlock reliably.

        Retrying matters more than it looks. ``emit`` catches everything a sink
        raises so that a sink can never fail a login, which means an
        unretried deadlock does not surface as an error -- it silently drops the
        record. The sequence number was assigned inside the transaction that
        rolled back, so no gap appears either, and ``verify_chain`` still passes
        over a log that is missing entries.

        Caveat: if the caller has already opened an atomic block, the outer
        transaction is broken by the deadlock and no retry can succeed. The
        exception propagates in that case, which is correct -- the caller's
        transaction has to be the thing that restarts.
        """
        last: OperationalError | None = None
        for attempt in range(_APPEND_ATTEMPTS):
            try:
                return cls._append_once(event)
            except OperationalError as exc:
                if not _is_lock_contention(exc):
                    raise
                last = exc
                # Fresh instance state: the failed save left a primary key on
                # the event, and reusing it would turn the retry into an UPDATE
                # of a row that no longer exists.
                event.pk = None
                event._state.adding = True
                if attempt < _APPEND_ATTEMPTS - 1:
                    time.sleep(_APPEND_BACKOFF * (2**attempt))
        raise last  # type: ignore[misc]

    @classmethod
    @transaction.atomic
    def _append_once(cls, event: AuditEvent) -> AuditEvent:
        head, _ = cls.objects.select_for_update().get_or_create(name=event.chain)
        event.chain_seq = head.last_seq + 1
        event.prev_hash = head.last_hash
        event.record_hash = event.compute_hash()
        event.save()

        head.last_seq = event.chain_seq
        head.last_hash = event.record_hash
        head.save(update_fields=["last_seq", "last_hash", "updated_at"])
        return event


def verify_chain(chain: str = DEFAULT_CHAIN) -> tuple[bool, list[str]]:
    """Walk a chain and report what does not add up.

    Detects a rewritten record, a removed one, and a resequenced one. Does not
    detect an adversary who recomputed the whole chain after editing it, which
    is why the head hash needs anchoring somewhere they do not control.

    Verification starts after the retention watermark. Records removed by the
    policy are accounted for; records removed any other way are not.
    """
    problems: list[str] = []
    head = AuditChain.objects.filter(name=chain).first()
    watermark = head.purged_through_seq if head else 0

    previous_hash = ""
    expected_seq = watermark + 1
    first = True

    for event in (
        AuditEvent.objects.filter(chain=chain, chain_seq__gt=watermark)
        .order_by("chain_seq")
        .iterator()
    ):
        if event.chain_seq != expected_seq:
            problems.append(f"sequence gap: expected {expected_seq}, found {event.chain_seq}")
            expected_seq = event.chain_seq
        # The first surviving record after a purge legitimately links to a
        # predecessor that no longer exists.
        if not (first and watermark) and event.prev_hash != previous_hash:
            problems.append(f"broken link at {event.chain_seq}")
        if event.record_hash != event.compute_hash():
            problems.append(f"record {event.chain_seq} does not match its hash")
        previous_hash = event.record_hash
        expected_seq += 1
        first = False

    return not problems, problems


def purge_before(cutoff: dt.datetime, *, chain: str = DEFAULT_CHAIN) -> int:
    """Apply the retention policy, recording what was removed.

    Uses a queryset delete, which does not go through the model's append-only
    guard. That is the one legitimate way records leave, and it is why the
    guard lives on the instance rather than in a database trigger.

    The watermark and the recorded event exist so the resulting gap has an
    explanation. A hole in an audit sequence with nothing accounting for it
    looks exactly like evidence destruction, and a retention job should not be
    indistinguishable from that.
    """
    from bastion.audit.recorder import emit

    doomed = AuditEvent.objects.filter(chain=chain, occurred_at__lt=cutoff)
    highest = doomed.order_by("-chain_seq").values_list("chain_seq", flat=True).first()
    if highest is None:
        return 0

    count = doomed.count()
    doomed.delete()
    AuditChain.objects.filter(name=chain).update(purged_through_seq=highest)

    emit(
        Event.AUDIT_PURGED,
        outcome=Outcome.SUCCESS,
        severity=Severity.NOTICE,
        chain=chain,
        context={"removed": count, "through_seq": highest, "cutoff": cutoff.isoformat()},
    )
    return count


def export_manifest(
    *, chain: str = DEFAULT_CHAIN, since: dt.datetime | None = None
) -> dict[str, Any]:
    """Describe an export so its completeness can be checked.

    Row count, sequence range and head hash, signed with the project secret.
    This answers the question auditors actually ask about a sampled export,
    which is not "is this record true" but "is this all of them".
    """
    from django.core import signing

    events = AuditEvent.objects.filter(chain=chain)
    if since is not None:
        events = events.filter(occurred_at__gte=since)

    aggregate = events.aggregate(
        count=models.Count("pk"),
        lowest=models.Min("chain_seq"),
        highest=models.Max("chain_seq"),
    )
    head = AuditChain.objects.filter(name=chain).first()

    body: dict[str, Any] = {
        "chain": chain,
        "count": aggregate["count"],
        "first_seq": aggregate["lowest"],
        "last_seq": aggregate["highest"],
        "chain_head_seq": head.last_seq if head else 0,
        "chain_head_hash": head.last_hash if head else "",
        "purged_through_seq": head.purged_through_seq if head else 0,
        "since": since.isoformat() if since else None,
        "generated_at": dt.datetime.now(tz=dt.UTC).isoformat(),
    }
    body["signature"] = signing.dumps(body, salt="bastion.audit.manifest")
    return body


def forget_actor(user: Any, *, reason: str = "") -> int:
    """Sever the link between a person and their recorded events.

    The events remain and the chain stays intact, because the events never
    contained an identifier in the first place. What is destroyed is the only
    mapping back, which is what makes the residual data genuinely
    unattributable rather than merely pseudonymous.

    Returns the number of events that became unattributable.
    """
    from bastion.audit.recorder import emit

    actors = list(AuditActor.objects.filter(user=user))
    if not actors:
        return 0

    affected = AuditEvent.objects.filter(actor_pseudonym__in=[a.pseudonym for a in actors]).count()

    for actor in actors:
        actor.delete()

    emit(
        Event.ACTOR_FORGOTTEN,
        outcome=Outcome.SUCCESS,
        reason=reason,
        context={"events_affected": affected},
    )
    return affected
