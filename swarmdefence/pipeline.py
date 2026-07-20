"""The Section 8 processing procedure, wired for baselines and ablations.

Steps (design paper Section 8):
  1. Ingest and validate events (schema, producer, idempotency; retain
     event and arrival time).
  2. Update local evidence (Equation 1) with provenance.
  3. Apply controlled cooperation (Equations 2-3) behind the secure
     signal plane; never re-emit from peer-only threshold crossings.
  4. Update graph views: immutable ledger + typed temporal edges with
     decayed operational edge evidence (Equation 4).
  5. Detect stable evidence (first-alert and stable times separately).
  6. Rank origins (Equation 5) with top-k and abstention.
  7. Produce an explainable incident package.

``SystemConfig`` selects the baseline systems B0-B5 and the safety
ablations of Section 9.4 by toggling components of the same pipeline, so
all comparisons share identical telemetry and detector features.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field, replace
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .attribution import (
    AttributionResult,
    OriginRanker,
    RankingWeights,
    StableEvidenceTracker,
)
from .evidence import CooperativeEvidence, LocalEvidence, Signal, SignalPlane
from .graph import BenignBaseline, TemporalGraph
from .model import Entity, Event, EventLedger


@dataclass(frozen=True)
class SystemConfig:
    """Frozen parameterization (Section 7).  Baselines/ablations toggle
    booleans; numeric parameters stay identical across compared systems
    except where a baseline definition requires otherwise."""

    name: str = "full"
    # component toggles (Section 9.4)
    cooperation: bool = True          # Equations 2-3 active
    graph_ranking: bool = True        # Equation 5 active (else earliest-stable)
    temporal_decay: bool = True       # False -> static-graph baseline B2
    central_correlation: bool = False # B1: centralized neighbour correlation
    # safety ablations (Section 9.4)
    enforce_budget: bool = True
    enforce_gate: bool = True
    enforce_dedupe: bool = True
    enforce_freshness: bool = True
    enforce_diversity: bool = True
    # Equation parameters (Section 7)
    kappa_s: float = 0.25             # local-memory decay rate, 1/h (half-life ~2.8h)
    eta: float = 0.4                  # peer influence scale
    mu: float = 1.0                   # signal staleness decay rate, 1/h
    kappa_p: float = 0.35             # edge-evidence decay rate, 1/h
    theta_g: float = 0.2              # local evidence gate
    budget: float = 0.6               # rolling peer influence budget B_j
    budget_window: float = 6.0        # W, hours
    theta_emit: float = 0.45          # local threshold for emitting a signal
    emit_min_interval: float = 0.25   # per-sensor emission rate limit, hours
    theta_alert: float = 0.55         # operational alert threshold (calibrated)
    theta_s: float = 0.55             # stable-evidence threshold (=(matched) alert)
    tau_stable: float = 0.3           # stability duration, hours
    incident_window: float = 12.0     # bounded incident window for attribution (S8)
    central_boost: float = 0.18       # B1 per-anomalous-neighbour boost
    central_window: float = 2.0       # B1 correlation window, hours
    top_k: int = 3

    def stable_threshold(self) -> float:
        return self.theta_s


BASELINES: Dict[str, SystemConfig] = {
    # Section 9.4 baseline grid
    "B0_local_only": SystemConfig(
        name="B0_local_only", cooperation=False, graph_ranking=False
    ),
    "B1_central_streaming": SystemConfig(
        name="B1_central_streaming", cooperation=False, graph_ranking=False,
        central_correlation=True,
    ),
    "B2_static_graph": SystemConfig(
        name="B2_static_graph", cooperation=False, graph_ranking=True,
        temporal_decay=False,
    ),
    "B3_temporal_graph_only": SystemConfig(
        name="B3_temporal_graph_only", cooperation=False, graph_ranking=True
    ),
    "B4_cooperation_only": SystemConfig(
        name="B4_cooperation_only", cooperation=True, graph_ranking=False
    ),
    "B5_full": SystemConfig(name="B5_full"),
    # Safety ablations
    "A_no_budget": SystemConfig(
        name="A_no_budget", enforce_budget=False, enforce_diversity=False
    ),
    "A_no_gate": SystemConfig(name="A_no_gate", enforce_gate=False),
    "A_no_dedupe": SystemConfig(
        name="A_no_dedupe", enforce_dedupe=False, enforce_freshness=False
    ),
    "A_no_all_safeguards": SystemConfig(
        name="A_no_all_safeguards", enforce_budget=False, enforce_gate=False,
        enforce_dedupe=False, enforce_freshness=False, enforce_diversity=False,
    ),
}


@dataclass
class AlertRecord:
    entity: str
    time: float
    combined: float
    local: float


class DetectionPipeline:
    """One incident-processing run over a time-ordered event/signal stream."""

    def __init__(
        self,
        config: SystemConfig,
        entities: Mapping[str, Entity],
        baseline: BenignBaseline,
        role_sensor_delay: Optional[Mapping[str, float]] = None,
    ) -> None:
        self.config = config
        self.entities = dict(entities)
        self.ledger = EventLedger()
        self.local = LocalEvidence(kappa_s=config.kappa_s)
        self.graph = TemporalGraph(
            kappa_p=config.kappa_p,
            baseline=baseline,
            temporal_decay=config.temporal_decay,
        )
        self.plane = SignalPlane(
            enforce_dedupe=config.enforce_dedupe,
            enforce_freshness=config.enforce_freshness,
        )
        for eid, ent in self.entities.items():
            if ent.instrumented:
                self.plane.enroll(f"sensor:{eid}")
        self.coop = CooperativeEvidence(
            eta=config.eta,
            mu=config.mu,
            budget=config.budget,
            window=config.budget_window,
            theta_g=config.theta_g,
            enforce_budget=config.enforce_budget,
            enforce_gate=config.enforce_gate,
            enforce_diversity=config.enforce_diversity,
        )
        # Component-wise decay bounds for the analytic stability hold: the
        # local part decays at kappa_s; the effective cooperative part
        # (after gate and proportional cap) decays no faster than mu +
        # kappa_s (message staleness plus the gate shrinking with local
        # evidence), so using that rate for the coop component is a sound
        # conservative bound.  See StableEvidenceTracker._hold.
        self.stability = StableEvidenceTracker(
            theta_s=config.stable_threshold(),
            tau=config.tau_stable,
            kappa_hold=config.kappa_s,
            kappa_coop=config.mu + config.kappa_s,
        )
        self.ranker = OriginRanker(
            weights=RankingWeights(),
            role_sensor_delay=role_sensor_delay,
            top_k=config.top_k,
        )
        self.alerts: List[AlertRecord] = []
        self._alerted: set[str] = set()
        self._last_emit: Dict[str, float] = {}
        # broker-side store of accepted signals by scope: relevance can
        # materialize later, when a new edge involving the scoped entity
        # appears (Section 5.2 topic authorization / causal relevance)
        self._signal_store: Dict[str, List[Tuple[float, Signal]]] = {}
        self._contributed: set[Tuple[str, str]] = set()  # (recipient, signal_id)
        self._emit_seq = itertools.count(1)
        self._seq_by_sender: Dict[str, int] = {}
        self._recent_anomalous_neighbors: Dict[str, List[Tuple[str, float]]] = {}
        self._recent_in_edges: Dict[str, List[Tuple[str, float]]] = {}
        self.combined_scores: Dict[str, float] = {}
        # (entity, time, combined score) samples; used by the experiment
        # harness for offline threshold calibration at a matched
        # false-alert budget (Section 9.6) without re-running dynamics.
        self.score_samples: List[Tuple[str, float, float]] = []

    # -- helpers ------------------------------------------------------------

    def _combined(self, entity: str, t: float) -> float:
        local = self.local.decayed(entity, t)
        if self.config.central_correlation:
            # B1: identical telemetry, centralized neighbour correlation.
            neighbors = self._recent_anomalous_neighbors.get(entity, [])
            fresh = [n for n, ts in neighbors if t - ts <= self.config.central_window]
            boost = self.config.central_boost * min(len(set(fresh)), 3)
            return min(1.0, local + boost)
        if self.config.cooperation:
            return self.coop.combined(entity, local, t)
        return local

    def _record_score(self, entity: str, t: float) -> None:
        s = self._combined(entity, t)
        local = self.local.decayed(entity, t)
        self.combined_scores[entity] = s
        self.score_samples.append((entity, t, s))
        self.stability.observe(entity, s, t, local=local, coop=max(0.0, s - local))
        if s >= self.config.theta_alert and entity not in self._alerted:
            self._alerted.add(entity)
            self.alerts.append(
                AlertRecord(entity, t, s, self.local.decayed(entity, t))
            )

    def _maybe_emit_signal(
        self, entity: str, t: float, prev_local: float = 0.0
    ) -> Optional[Signal]:
        """Section 5.1 no-re-emission rule: a sensor emits only when its
        LOCAL evidence crosses theta_emit from below (rising edge);
        combined/peer-raised scores never trigger emission, and decayed
        memory of an already-signalled observation is not re-broadcast."""
        ent = self.entities.get(entity)
        if ent is None or not ent.instrumented or not self.config.cooperation:
            return None
        local = self.local.decayed(entity, t)
        if local < self.config.theta_emit or prev_local >= self.config.theta_emit:
            return None
        last = self._last_emit.get(entity)
        if last is not None and t - last < self.config.emit_min_interval:
            return None
        self._last_emit[entity] = t
        sender = f"sensor:{entity}"
        seq = self._seq_by_sender.get(sender, 0) + 1
        self._seq_by_sender[sender] = seq
        return Signal(
            signal_id=f"sig:{entity}:{seq}",
            sender=sender,
            sequence=seq,
            scope=entity,
            incident_key="incident-0",
            evidence_weight=local,
            event_time=t,
            expiry=t + 2.0,
        )

    def deliver_signal(self, sig: Signal, now: float) -> bool:
        """Steps 1+3: validate at the signal plane, store the accepted
        signal, then contribute bounded cooperative evidence to currently
        relevant recipients (recent graph neighbours of the scoped
        entity).  Later edges involving the scope pull the stored signal
        via :meth:`_pull_relevant_signals`."""
        ok, _reason = self.plane.validate(sig, now)
        if not ok:
            return False
        store = self._signal_store.setdefault(sig.scope, [])
        store.append((now, sig))
        del store[:-64]
        recipients: Dict[str, float] = {}
        novelty = self.graph.baseline.novelty
        for peer, ts in self._recent_in_edges.get(sig.scope, []):
            if now - ts <= 2.0:
                recipients[peer] = max(recipients.get(peer, 0.0),
                                       novelty(peer, sig.scope))
        for inst in self.graph.out_edges(sig.scope):
            if now - inst.event_time <= 2.0:
                recipients[inst.target] = max(recipients.get(inst.target, 0.0),
                                              novelty(sig.scope, inst.target))
        for r, relevance in recipients.items():
            self._contribute_signal(r, sig, relevance, now)
        return True

    def _contribute_signal(
        self, recipient: str, sig: Signal, relevance: float, now: float
    ) -> None:
        if recipient == sig.scope:
            return
        if (recipient, sig.signal_id) in self._contributed:
            return  # each message influences a recipient at most once
        self._contributed.add((recipient, sig.signal_id))
        trust = 1.0  # enrolled senders start fully trusted (Section 7)
        # staleness of the signal itself decays its influence (Equation 2)
        age = max(0.0, now - sig.event_time)
        relevance = relevance * math.exp(-self.config.mu * age)
        self.coop.contribute(recipient, sig, trust, relevance, now)
        self._record_score(recipient, now)

    def _pull_relevant_signals(self, event: Event) -> None:
        """Causal-relevance routing: a new typed edge makes recent stored
        signals about one endpoint relevant to the other (Section 5.2).
        The forward direction (signal about the connection source applies
        to the target it contacted) carries full relevance; the backward
        direction is weaker.  Relevance is scaled by the edge's novelty
        against the benign baseline: routine administrative routes are
        weak propagation vectors, so signals travelling along them carry
        little influence (typed-graph relevance rule, Section 7)."""
        if not self.config.cooperation:
            return
        t = event.event_time
        edge_novelty = self.graph.baseline.novelty(event.source, event.target)
        for scope, recipient, rel in (
            (event.source, event.target, 1.0 * edge_novelty),
            (event.target, event.source, 0.5 * edge_novelty),
        ):
            for stored_t, sig in self._signal_store.get(scope, ()):  # recent only
                if t - sig.event_time <= self.plane.freshness_window or (
                    not self.plane.enforce_freshness
                ):
                    self._contribute_signal(recipient, sig, rel, t)

    # -- main entry points ----------------------------------------------------

    def ingest_event(self, event: Event) -> List[Signal]:
        """Steps 1, 2, 4, 5 for one event; returns any signal the local
        sensors chose to emit (to be routed by the caller through
        :meth:`deliver_signal`, possibly with transport effects)."""
        if self.ledger.contains_event(event.event_id):
            return []  # idempotent ingestion (Section 8 step 1)
        self.ledger.append(event)
        t = event.event_time
        anomaly = float(event.attributes.get("anomaly", 0.0))

        # Track recent inbound edges for cooperation relevance routing.
        self._recent_in_edges.setdefault(event.target, []).append((event.source, t))
        del self._recent_in_edges[event.target][:-32]

        # Causal relevance: recent stored signals about either endpoint
        # become relevant to the other along this new typed edge.
        self._pull_relevant_signals(event)

        # Step 2: local evidence at instrumented endpoints.  An endpoint's
        # local evidence L_n is derived from its OWN sensor's observations
        # (Section 5.1): it updates only when the event was produced by that
        # endpoint's sensor, or by the counterpart's sensor for activity the
        # endpoint's own sensor corroborates (attributes["corroborated"]).
        # A forged single-sensor report therefore never raises the other
        # endpoint's local evidence (audit: signed false telemetry is not
        # trustworthy).  The target observes inbound activity at full
        # strength; the source observes its outbound side more weakly.
        emitted: List[Signal] = []
        tgt_producer = event.producer == f"sensor:{event.target}"
        src_producer = event.producer == f"sensor:{event.source}"
        corroborated = float(event.attributes.get("corroborated", 1.0)) >= 0.5
        tgt = self.entities.get(event.target)
        if tgt is not None and tgt.instrumented and (
            tgt_producer or (src_producer and corroborated)
        ):
            prev = self.local.decayed(event.target, t)
            self.local.update(event.target, anomaly, t, event.event_id)
            self._record_score(event.target, t)
            sig = self._maybe_emit_signal(event.target, t, prev)
            if sig:
                emitted.append(sig)
        src = self.entities.get(event.source)
        if src is not None and src.instrumented and (
            src_producer or (tgt_producer and corroborated)
        ):
            prev = self.local.decayed(event.source, t)
            self.local.update(event.source, 0.6 * anomaly, t, event.event_id)
            self._record_score(event.source, t)
            sig = self._maybe_emit_signal(event.source, t, prev)
            if sig:
                emitted.append(sig)

        # B1 central correlation bookkeeping (identical telemetry).
        if self.config.central_correlation and anomaly >= 0.4:
            for n_entity, peer in ((event.target, event.source), (event.source, event.target)):
                lst = self._recent_anomalous_neighbors.setdefault(n_entity, [])
                lst.append((peer, t))
                del lst[:-32]
            self._record_score(event.target, t)
            self._record_score(event.source, t)

        # Step 4: graph views (ledger already appended above).
        self.graph.add_event(event)
        return emitted

    def attribute(self, now: float) -> AttributionResult:
        """Step 6: rank origins over the bounded incident window
        (Section 8), or fall back to the earliest-alert heuristic for
        configurations without graph ranking (Section 9.4: B0/B1/B4 use
        the earliest-alert baseline the design compares against)."""
        window_start = now - self.config.incident_window
        roles = {e: ent.role for e, ent in self.entities.items()}
        instrumented = {e: ent.instrumented for e, ent in self.entities.items()}
        if self.config.graph_ranking:
            suspicious = {
                e: t_n
                for e, t_n in self.stability.suspicious().items()
                if window_start <= t_n <= now
            }
            return self.ranker.rank(self.graph, suspicious, roles, instrumented, now)
        alerts = {
            a.entity: a.time
            for a in self.alerts
            if window_start <= a.time <= now
        }
        if not alerts:
            return AttributionResult([], True, "no_alerts_in_window", {}, {})
        ordered = sorted(alerts.items(), key=lambda kv: kv[1])
        from .attribution import OriginCandidate

        ranking = [
            OriginCandidate(e, 1.0 / (1 + idx), 1.0, 0.0, 0.0, 0.0, 0.0, t_n)
            for idx, (e, t_n) in enumerate(ordered[: self.config.top_k])
        ]
        return AttributionResult(ranking, False, "earliest_alert", dict(alerts), {})

    def incident_package(self, now: float) -> Dict[str, object]:
        """Step 7: explainable incident package (Section 5.4)."""
        result = self.attribute(now)
        return {
            "top_k": [
                {
                    "entity": c.entity,
                    "score": round(c.score, 4),
                    "earliness": round(c.earliness, 4),
                    "coverage": round(c.coverage, 4),
                    "path_quality": round(c.path_quality, 4),
                    "contradictions": round(c.contradictions, 4),
                    "missingness": round(c.missingness, 4),
                    "stable_time": c.stable_time,
                    "explained": list(c.explained),
                    "evidence_events": list(c.evidence_events)[:16],
                }
                for c in result.ranking
            ],
            "abstained": result.abstained,
            "abstain_reason": result.abstain_reason,
            "suspicious_entities": {k: round(v, 4) for k, v in result.suspicious.items()},
            "parameters": result.parameters,
            "config": self.config.name,
            "ledger_head": self.ledger.head_hash,
            "signal_plane_stats": self.plane.stats.as_dict(),
            "sender_concentration": round(self.coop.sender_concentration(), 4),
        }
