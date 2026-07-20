"""Typed temporal graph views and decayed edge evidence.

Design paper Section 5.3: the replicated evidence service derives two
views from the immutable ledger -- a typed temporal multigraph of
observed relations, and a decayed operational evidence graph.

Equation 4 (bounded elapsed-time edge-evidence update)::

    P_uv(t_e) = 1 - (1 - P_uv(t_prev) * exp(-kappa_p * (t_e - t_prev)))
                    * (1 - q_uv(e))

The update is a noisy-OR reinforcement over an exponentially decayed
prior, so P stays in [0, 1], decays with elapsed event time (not
scheduler ticks -- audit finding on the original tick-based accumulator),
and saturates rather than diverging under continuous reinforcement.

q_uv(e) scores each event against a benign edge baseline (Section 6.4):
repeated use alone must not accumulate attack evidence, because backup,
monitoring and administration reuse the same routes.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .model import Event, Relation

EdgeKey = Tuple[str, str]


@dataclass
class TemporalEdgeInstance:
    """One observed typed relation instance (temporal multigraph edge)."""

    source: str
    target: str
    relation: Relation
    event_time: float
    event_id: str


@dataclass
class EdgeEvidenceState:
    value: float = 0.0
    last_time: Optional[float] = None
    contributing_events: List[str] = field(default_factory=list)


class BenignBaseline:
    """Edge-frequency baseline learned on a training window that excludes
    test campaigns (Section 6.2 / 9.6 parameter hygiene)."""

    def __init__(self) -> None:
        self.edge_counts: Dict[EdgeKey, int] = defaultdict(int)
        self.frozen = False

    def observe(self, source: str, target: str) -> None:
        if self.frozen:
            raise RuntimeError("baseline is frozen; training window has ended")
        self.edge_counts[(source, target)] += 1

    def freeze(self) -> None:
        self.frozen = True

    def novelty(self, source: str, target: str) -> float:
        """1 for never-seen routes, approaching 0 for heavily used ones."""
        return 1.0 / (1.0 + float(self.edge_counts.get((source, target), 0)))


class TemporalGraph:
    """Typed temporal multigraph plus decayed operational edge evidence.

    ``temporal_decay=False`` gives the static-graph baseline of Section
    9.4 (identical node evidence, non-decaying structural edges, ranking
    without time-respecting constraints).
    """

    def __init__(
        self,
        kappa_p: float = 0.35,
        baseline: Optional[BenignBaseline] = None,
        temporal_decay: bool = True,
    ) -> None:
        self.kappa_p = kappa_p
        self.baseline = baseline or BenignBaseline()
        self.temporal_decay = temporal_decay
        self._out: Dict[str, List[TemporalEdgeInstance]] = defaultdict(list)
        self._evidence: Dict[EdgeKey, EdgeEvidenceState] = {}
        self._nodes: Set[str] = set()

    # -- construction -----------------------------------------------------

    def event_contribution(self, event: Event) -> float:
        """q_uv(e): anomaly scored against the benign edge baseline."""
        anomaly = float(event.attributes.get("anomaly", 0.0))
        q = anomaly * self.baseline.novelty(event.source, event.target)
        return _clip01(q)

    def add_event(self, event: Event) -> float:
        """Append the typed relation and apply Equation 4; returns new P_uv."""
        inst = TemporalEdgeInstance(
            event.source, event.target, event.relation, event.event_time, event.event_id
        )
        self._out[event.source].append(inst)
        self._nodes.add(event.source)
        self._nodes.add(event.target)

        st = self._evidence.setdefault((event.source, event.target), EdgeEvidenceState())
        q = self.event_contribution(event)
        prior = st.value
        if self.temporal_decay and st.last_time is not None:
            dt = max(0.0, event.event_time - st.last_time)
            prior = prior * math.exp(-self.kappa_p * dt)
        st.value = 1.0 - (1.0 - prior) * (1.0 - q)
        st.last_time = (
            event.event_time
            if st.last_time is None
            else max(st.last_time, event.event_time)
        )
        if q > 0.05:
            st.contributing_events.append(event.event_id)
            del st.contributing_events[:-64]
        return st.value

    # -- queries -----------------------------------------------------------

    def nodes(self) -> Set[str]:
        return set(self._nodes)

    def out_edges(self, node: str) -> Tuple[TemporalEdgeInstance, ...]:
        return tuple(self._out.get(node, ()))

    def edge_evidence(self, source: str, target: str, t: Optional[float] = None) -> float:
        st = self._evidence.get((source, target))
        if st is None or st.last_time is None:
            return 0.0
        if not self.temporal_decay or t is None:
            return st.value
        return st.value * math.exp(-self.kappa_p * max(0.0, t - st.last_time))

    def edge_provenance(self, source: str, target: str) -> Tuple[str, ...]:
        st = self._evidence.get((source, target))
        return tuple(st.contributing_events) if st else ()

    # -- time-respecting path reasoning (Sections 6.6 / 8) -----------------

    def best_paths(
        self,
        origin: str,
        t_start: float,
        t_end: float,
        min_edge_evidence: float = 0.02,
        eval_time: Optional[float] = None,
    ) -> Dict[str, Tuple[float, float, Tuple[str, ...]]]:
        """Best time-respecting bottleneck paths from ``origin``.

        Returns {node: (bottleneck_evidence, arrival_event_time, path_nodes)}
        over paths whose successive edge event times are non-decreasing and
        lie within [t_start, t_end].  With ``temporal_decay=False`` the
        time-respecting constraint is dropped (static-graph baseline).

        Complexity: label-correcting search over the bounded incident
        window; the design's O(|V|+|E|) bound holds per candidate on the
        time-ordered acyclic incident subgraph (Section 8).
        """
        import heapq

        if not self.temporal_decay:
            return self._best_paths_static(origin, min_edge_evidence)

        # state: (-bottleneck, last_edge_time, node, path)
        best: Dict[str, Tuple[float, float, Tuple[str, ...]]] = {}
        heap: List[Tuple[float, float, str, Tuple[str, ...]]] = [
            (-1.0, t_start, origin, (origin,))
        ]
        visited: Dict[Tuple[str, float], float] = {}
        pops = 0
        while heap and pops < 50_000:  # bounded incident subgraph (Section 8)
            neg_b, last_t, node, path = heapq.heappop(heap)
            pops += 1
            bottleneck = -neg_b
            key = (node, round(last_t, 6))
            if visited.get(key, -1.0) >= bottleneck:
                continue
            visited[key] = bottleneck
            if node != origin:
                cur = best.get(node)
                if cur is None or bottleneck > cur[0] or (
                    bottleneck == cur[0] and last_t < cur[1]
                ):
                    best[node] = (bottleneck, last_t, path)
            if len(path) > 12:
                continue
            for inst in self._out.get(node, ()):  # typed temporal edges
                if inst.event_time < last_t or not (t_start <= inst.event_time <= t_end):
                    continue
                ev = self.edge_evidence(inst.source, inst.target, eval_time)
                if ev < min_edge_evidence:
                    continue
                nb = min(bottleneck, ev)
                nxt = inst.target
                if nxt in path:
                    continue
                cur = best.get(nxt)
                if cur is not None and cur[0] >= nb and cur[1] <= inst.event_time:
                    continue
                heapq.heappush(heap, (-nb, inst.event_time, nxt, path + (nxt,)))
        return best

    def _best_paths_static(
        self, origin: str, min_edge_evidence: float
    ) -> Dict[str, Tuple[float, float, Tuple[str, ...]]]:
        """Static-graph baseline (Section 9.4 B2): classic max-bottleneck
        search over the collapsed structural graph -- no time-respecting
        constraint, no decay, arrival time reported as the earliest
        instance time of the final edge."""
        import heapq

        # collapse the multigraph to unique (u, v) pairs
        pair_time: Dict[Tuple[str, str], float] = {}
        for node, insts in self._out.items():
            for inst in insts:
                key = (inst.source, inst.target)
                if key not in pair_time or inst.event_time < pair_time[key]:
                    pair_time[key] = inst.event_time
        best: Dict[str, Tuple[float, float, Tuple[str, ...]]] = {}
        seen: Dict[str, float] = {}
        heap: List[Tuple[float, str, Tuple[str, ...]]] = [(-1.0, origin, (origin,))]
        while heap:
            neg_b, node, path = heapq.heappop(heap)
            bottleneck = -neg_b
            if seen.get(node, -1.0) >= bottleneck:
                continue
            seen[node] = bottleneck
            if node != origin:
                arrival = pair_time.get((path[-2], node), 0.0)
                best[node] = (bottleneck, arrival, path)
            if len(path) > 12:
                continue
            for inst in self._out.get(node, ()):
                key = (inst.source, inst.target)
                ev = self.edge_evidence(inst.source, inst.target, None)
                if ev < min_edge_evidence or inst.target in path:
                    continue
                nb = min(bottleneck, ev)
                if seen.get(inst.target, -1.0) >= nb:
                    continue
                heapq.heappush(heap, (-nb, inst.target, path + (inst.target,)))
        return best


def _clip01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x
