"""Ledger immutability and provenance (design paper Sections 5.3, 10;
audit finding: "decaying state cannot replace forensic evidence")."""

import dataclasses

import pytest

from swarmdefence.model import Event, EventLedger, LedgerTamperedError, Relation


def _ev(i: int, t: float = 1.0) -> Event:
    return Event(
        event_id=f"ev-{i}",
        source="A",
        target="B",
        relation=Relation.AUTH,
        event_time=t,
        arrival_time=t + 0.01,
        attributes={"anomaly": 0.5},
        producer="sensor:B",
    )


def test_append_and_verify():
    ledger = EventLedger()
    for i in range(20):
        ledger.append(_ev(i, t=float(i)))
    assert len(ledger) == 20
    assert ledger.verify() is True


def test_duplicate_event_id_rejected():
    ledger = EventLedger()
    ledger.append(_ev(1))
    with pytest.raises(ValueError):
        ledger.append(_ev(1))


def test_tampering_detected():
    ledger = EventLedger()
    for i in range(5):
        ledger.append(_ev(i, t=float(i)))
    # simulate post-hoc tampering with a stored event
    rec = list(ledger)[2]
    rec.event = dataclasses.replace(rec.event, attributes={"anomaly": 0.0})
    with pytest.raises(LedgerTamperedError):
        ledger.verify()


def test_hash_chain_links_records():
    ledger = EventLedger()
    r0 = ledger.append(_ev(0))
    r1 = ledger.append(_ev(1))
    assert r1.prev_hash == r0.record_hash
    assert r0.prev_hash == EventLedger.GENESIS
