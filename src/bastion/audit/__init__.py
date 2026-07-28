"""Audit.

Nothing in the Django ecosystem ships an identity audit log, so this is written
against what the regimes actually ask for rather than against prior art.

The field set comes from NIST SP 800-53 AU-3, whose six elements -- what
happened, when, where, from what source, with what outcome, and to whom -- turn
out to be the canonical minimum across every regime in scope. PCI DSS 10.2.2
and ISO 27002 8.15 are rewordings of the same list.

Two design decisions are worth reading before using this.

**Actors are pseudonymous from the start.** An event never stores a user id, an
email or a name. It stores an opaque token, and a separate table maps that
token to a user. Erasure deletes the mapping row, which leaves the events
intact and the chain unbroken while making re-identification genuinely
impossible. That last word is doing real work: EDPB guidance is clear that
pseudonymised data stays personal data while anyone holds the mapping, and the
Article 11 route is only available to a controller that cannot re-identify.
Keeping a recoverable mapping and claiming Article 11 are mutually exclusive.

**The hash chain is tamper *evidence*, not immutability.** An adversary with
write access to the database recomputes the whole chain in seconds. It has real
value only when the head hash is periodically anchored somewhere that adversary
does not control -- shipped to a SIEM, emailed, signed offline. The strongest
practical control here is not this module at all; it is sending events to a
system under different administrative control. Say so to auditors rather than
overselling the chain.
"""

from bastion.audit.events import Event
from bastion.audit.recorder import emit
from bastion.audit.sinks import AuditSink, DatabaseSink, LoggingSink

__all__ = ["AuditSink", "DatabaseSink", "Event", "LoggingSink", "emit"]
