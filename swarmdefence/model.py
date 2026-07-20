"""Typed temporal events and the immutable forensic event ledger.

Design paper Section 6.1: an event is a tuple
(id, source, relation, target, event_time, arrival_time, attributes,
producer, model_version).  The graph over these events is a temporal
multigraph; event time is used for causal ordering while arrival time
models logging and transport delay.

Design paper Sections 5.3 / 6.4 and audit finding "Decaying state cannot
replace forensic evidence": the raw event ledger is append-only and
integrity-protected (hash chained).  Decayed operational scores are
derived views elsewhere; they never replace this record.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, Mapping, Optional, Tuple


class EntityType(str, Enum):
    HOST = "host"
    IDENTITY = "identity"
    SERVICE = "service"
    EXTERNAL = "external"


class Relation(str, Enum):
    """Typed relations between entities (Section 6.1, typed multigraph)."""

    AUTH = "auth"              # remote authentication / logon
    SESSION = "session"        # interactive or service session
    PROCESS = "process"        # remote process / service execution
    FLOW = "flow"              # network flow
    ADMIN = "admin"            # administrative management action


@dataclass(frozen=True)
class Entity:
    """A typed entity (Section 6.1)."""

    entity_id: str
    entity_type: EntityType
    role: str = "workstation"  # role drives sensor-delay adjustment in ranking
    instrumented: bool = True  # False models missing telemetry (Section 6.2)

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.entity_id


@dataclass(frozen=True)
class Event:
    """A typed temporal event (Section 6.1).

    ``anomaly`` inside ``attributes`` is the raw detector observation in
    [0, 1] attached by the producing sensor; it is detector evidence, not
    a probability (claim boundary, Section 6.2).
    """

    event_id: str
    source: str
    relation: Relation
    target: str
    event_time: float          # hours since simulation epoch (causal order)
    arrival_time: float        # hours; models logging/transport delay
    attributes: Mapping[str, float]
    producer: str              # sensor identity that reported the event
    model_version: str = "detector-v1"

    def canonical(self) -> str:
        """Stable serialization used for hash chaining."""
        return json.dumps(
            {
                "event_id": self.event_id,
                "source": self.source,
                "relation": self.relation.value,
                "target": self.target,
                "event_time": round(self.event_time, 9),
                "arrival_time": round(self.arrival_time, 9),
                "attributes": {k: round(v, 9) for k, v in sorted(self.attributes.items())},
                "producer": self.producer,
                "model_version": self.model_version,
            },
            sort_keys=True,
        )


class LedgerTamperedError(RuntimeError):
    pass


@dataclass
class LedgerRecord:
    index: int
    event: Event
    prev_hash: str
    record_hash: str


class EventLedger:
    """Append-only, hash-chained forensic event ledger (Section 5.3).

    The ledger exposes no mutation API besides ``append``.  ``verify``
    recomputes the hash chain and raises on any tampering, satisfying the
    audit requirement that incident reconstruction rests on an immutable
    record with integrity metadata.
    """

    GENESIS = "0" * 64

    def __init__(self) -> None:
        self._records: list[LedgerRecord] = []
        self._seen_ids: set[str] = set()

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[LedgerRecord]:
        return iter(self._records)

    @property
    def head_hash(self) -> str:
        return self._records[-1].record_hash if self._records else self.GENESIS

    def contains_event(self, event_id: str) -> bool:
        return event_id in self._seen_ids

    def append(self, event: Event) -> LedgerRecord:
        """Append an event; idempotency is enforced upstream, duplicate
        event ids are rejected here as defence in depth (Section 10)."""
        if event.event_id in self._seen_ids:
            raise ValueError(f"duplicate event id {event.event_id!r}")
        prev = self.head_hash
        digest = hashlib.sha256((prev + event.canonical()).encode()).hexdigest()
        record = LedgerRecord(len(self._records), event, prev, digest)
        self._records.append(record)
        self._seen_ids.add(event.event_id)
        return record

    def verify(self) -> bool:
        """Recompute the full hash chain; raise LedgerTamperedError on any
        mismatch, return True otherwise."""
        prev = self.GENESIS
        for rec in self._records:
            expected = hashlib.sha256((prev + rec.event.canonical()).encode()).hexdigest()
            if rec.prev_hash != prev or rec.record_hash != expected:
                raise LedgerTamperedError(f"ledger record {rec.index} failed verification")
            prev = rec.record_hash
        return True

    def events(self) -> Tuple[Event, ...]:
        return tuple(r.event for r in self._records)
