"""Concurrent appends to the audit chain.

The gapless sequence and the hash link both depend on ``select_for_update()``
in ``AuditChain.append``. Under SQLite that guarantee is untestable: writes
serialise at the file level, so the lock is redundant and a version of the code
without it would pass every other test in this suite.

These tests therefore only mean something on a backend with real row locking.
They are skipped elsewhere rather than silently passing, because a skipped test
is honest and a vacuous one is not.

``transaction=True`` is required. The default pytest-django fixture wraps each
test in a transaction that is never committed, which other threads cannot see.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from django.db import connection, connections

from bastion.audit.events import Event
from bastion.audit.models import AuditChain, AuditEvent, verify_chain
from bastion.audit.recorder import emit

pytestmark = pytest.mark.skipif(
    connection.vendor == "sqlite",
    reason="row locking is not observable on SQLite; run with BASTION_TEST_DB=postgres",
)

WRITERS = 12
PER_WRITER = 5


def write_events(count: int) -> None:
    """Emit from a worker thread, then hand the connection back.

    Django opens a connection per thread and does not close it, so a pool the
    size of this test would leak one per worker without the explicit close.
    """
    try:
        for _ in range(count):
            emit(Event.LOGIN_SUCCEEDED)
    finally:
        connections.close_all()


@pytest.mark.django_db(transaction=True)
class TestConcurrentAppend:
    def test_the_sequence_stays_gapless_under_contention(self) -> None:
        with ThreadPoolExecutor(max_workers=WRITERS) as pool:
            for future in [pool.submit(write_events, PER_WRITER) for _ in range(WRITERS)]:
                future.result()

        expected = WRITERS * PER_WRITER
        sequence = list(
            AuditEvent.objects.order_by("chain_seq").values_list("chain_seq", flat=True)
        )

        assert len(sequence) == expected, "an append was lost"
        assert sequence == list(range(1, expected + 1)), (
            "sequence numbers were duplicated or skipped, which is what the "
            "row lock exists to prevent"
        )

    @pytest.mark.django_db(transaction=True)
    def test_the_hash_chain_survives_contention(self) -> None:
        with ThreadPoolExecutor(max_workers=WRITERS) as pool:
            for future in [pool.submit(write_events, PER_WRITER) for _ in range(WRITERS)]:
                future.result()

        verified, problems = verify_chain()
        assert verified, f"chain broke under concurrent writes: {problems}"

    @pytest.mark.django_db(transaction=True)
    def test_the_head_matches_the_last_event(self) -> None:
        """A head that drifts from the table is worse than a broken chain: it
        verifies today and refuses the next legitimate append."""
        with ThreadPoolExecutor(max_workers=WRITERS) as pool:
            for future in [pool.submit(write_events, PER_WRITER) for _ in range(WRITERS)]:
                future.result()

        head = AuditChain.objects.get()
        last = AuditEvent.objects.order_by("chain_seq").last()

        assert last is not None
        assert head.last_seq == last.chain_seq
        assert head.last_hash == last.record_hash
