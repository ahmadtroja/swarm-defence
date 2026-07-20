"""Stable-evidence detection and candidate-origin ranking.

Design paper Section 6.5: for each entity n, T_n is the earliest event
time at which the combined evidence S_n stays above theta_s for duration
tau.  Both first-alert time and stable-evidence time are reported,
because the stability window adds attribution delay.

Design paper Section 6.6, Equation 5 (candidate-origin evidence score)::

    R(o) = w_t * E(o) + w_c * C(o) + w_q * Q(o) - w_v * V(o) - w_m * M(o)

E rewards earlier stable evidence after role-specific sensor-delay
adjustment; C is time-respecting coverage of the suspicious set; Q
aggregates best independent edge evidence along those paths; V penalizes
temporal contradictions; M penalizes missing telemetry and unexplained
suspicious nodes.  The candidate set always includes an unknown/external
origin, output is top-k, and the ranker abstains on low score, small
margin, or absent coverage.  R is an evidence score, NOT a probability
(claim boundary, Section 6.6).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .graph import TemporalGraph

UNKNOWN_ORIGIN = "<unknown-or-external>"


# --------------------------------------------------------------------------
# Section 6.5 -- first alert and stable evidence
# --------------------------------------------------------------------------

@dataclass
class EntityTimeline:
    first_alert: Optional[float] = None
    stable_since: Optional[float] = None   # start of the current hold
    stable_time: Optional[float] = None    # T_n, once confirmed
    peak: float = 0.0


class StableEvidenceTracker:
    """Tracks first-alert times and stable-evidence times T_n.

    Between updates S decays monotonically, so S stayed >= theta_s over
    an interval iff its decayed value at the interval end is >= theta_s.
    After each update we additionally credit the analytic hold time
    ln(S/theta_s)/kappa_hold, using the FASTEST decay rate among the
    evidence components; this under-estimates the hold and therefore
    never declares stability early (documented approximation).
    """

    def __init__(
        self,
        theta_s: float,
        tau: float,
        kappa_hold: float,
        kappa_coop: Optional[float] = None,
        gap_tolerance: float = 1.0,
        max_hold: float = 8.0,
    ) -> None:
        self.theta_s = theta_s
        self.tau = tau
        self.kappa_hold = max(kappa_hold, 1e-9)   # local-evidence decay rate
        self.kappa_coop = max(kappa_coop or kappa_hold, 1e-9)
        self.gap_tolerance = gap_tolerance  # documented gap tolerance (S6.5)
        self.max_hold = max_hold
        self.timelines: Dict[str, EntityTimeline] = {}
        self._last_above: Dict[str, float] = {}

    def _hold(self, s_value: float, local: Optional[float], coop: Optional[float]) -> float:
        """Largest h such that the evidence provably stays >= theta_s for
        h hours under pure decay.  With component values available, solve
        local*e^(-kappa_hold*h) + coop*e^(-kappa_coop*h) >= theta_s by
        bisection (each component decays no faster than its bound rate);
        otherwise fall back to the single conservative rate."""
        if local is None or coop is None:
            return math.log(max(s_value, self.theta_s) / self.theta_s) / max(
                self.kappa_hold, self.kappa_coop
            )

        def f(h: float) -> float:
            return (
                local * math.exp(-self.kappa_hold * h)
                + coop * math.exp(-self.kappa_coop * h)
                - self.theta_s
            )

        if f(self.max_hold) >= 0:
            return self.max_hold
        lo, hi = 0.0, self.max_hold
        for _ in range(30):
            mid = 0.5 * (lo + hi)
            if f(mid) >= 0:
                lo = mid
            else:
                hi = mid
        return lo

    def observe(
        self,
        entity: str,
        s_value: float,
        t: float,
        local: Optional[float] = None,
        coop: Optional[float] = None,
    ) -> None:
        tl = self.timelines.setdefault(entity, EntityTimeline())
        tl.peak = max(tl.peak, s_value)
        if s_value >= self.theta_s:
            hold = self._hold(s_value, local, coop)
            last_above = self._last_above.get(entity)
            if tl.stable_since is not None and last_above is not None:
                if t - last_above > self.gap_tolerance:
                    tl.stable_since = None  # gap too large to bridge
            if tl.first_alert is None:
                tl.first_alert = t
            if tl.stable_since is None:
                tl.stable_since = t
            if tl.stable_time is None and (t + hold) - tl.stable_since >= self.tau:
                tl.stable_time = tl.stable_since + self.tau
            self._last_above[entity] = t + hold
        else:
            tl.stable_since = None  # hold broken before tau elapsed

    def suspicious(self) -> Dict[str, float]:
        """Entities with confirmed stable evidence -> T_n."""
        return {
            e: tl.stable_time
            for e, tl in self.timelines.items()
            if tl.stable_time is not None
        }

    def first_alerts(self) -> Dict[str, float]:
        return {
            e: tl.first_alert
            for e, tl in self.timelines.items()
            if tl.first_alert is not None
        }


# --------------------------------------------------------------------------
# Section 6.6 -- candidate-origin ranking (Equation 5)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class RankingWeights:
    """Pre-registered Equation 5 weights (Section 7: nonnegative; the
    positive weights sum to 1)."""

    w_t: float = 0.35
    w_c: float = 0.35
    w_q: float = 0.30
    w_v: float = 0.15
    w_m: float = 0.15

    def __post_init__(self) -> None:
        pos = self.w_t + self.w_c + self.w_q
        if abs(pos - 1.0) > 1e-9:
            raise ValueError("positive origin-ranking weights must sum to 1")


@dataclass
class OriginCandidate:
    entity: str
    score: float
    earliness: float
    coverage: float
    path_quality: float
    contradictions: float
    missingness: float
    stable_time: Optional[float]
    explained: Tuple[str, ...] = ()
    evidence_events: Tuple[str, ...] = ()


@dataclass
class AttributionResult:
    """SOC output package (Section 5.4): top-k candidates, abstention
    state, propagation subgraph, contributing evidence ids, parameters."""

    ranking: List[OriginCandidate]
    abstained: bool
    abstain_reason: str
    suspicious: Dict[str, float]
    parameters: Dict[str, float]

    def top(self, k: int = 3) -> List[OriginCandidate]:
        return self.ranking[:k]

    @property
    def top1(self) -> Optional[str]:
        return self.ranking[0].entity if self.ranking else None


class OriginRanker:
    def __init__(
        self,
        weights: RankingWeights = RankingWeights(),
        role_sensor_delay: Optional[Mapping[str, float]] = None,
        detection_lead: float = 1.0,     # how far before T_o attack edges may start
        arrival_slack: float = 0.75,     # tolerated gap between path arrival and T_v
        theta_r: float = 0.30,           # abstain below this best score
        min_margin: float = 0.02,        # abstain when top-2 margin is smaller
        min_edge_evidence: float = 0.02,
        earliness_horizon: float = 1.0,  # hours over which earliness advantage decays
        top_k: int = 3,
    ) -> None:
        self.weights = weights
        self.role_sensor_delay = dict(role_sensor_delay or {})
        self.detection_lead = detection_lead
        self.arrival_slack = arrival_slack
        self.theta_r = theta_r
        self.min_margin = min_margin
        self.min_edge_evidence = min_edge_evidence
        self.earliness_horizon = max(earliness_horizon, 1e-9)
        self.top_k = top_k

    def _adjusted_time(self, entity: str, t: float, roles: Mapping[str, str]) -> float:
        return t - self.role_sensor_delay.get(roles.get(entity, ""), 0.0)

    def rank(
        self,
        graph: TemporalGraph,
        suspicious: Mapping[str, float],
        roles: Mapping[str, str],
        instrumented: Mapping[str, bool],
        now: float,
    ) -> AttributionResult:
        params = {
            "w_t": self.weights.w_t, "w_c": self.weights.w_c,
            "w_q": self.weights.w_q, "w_v": self.weights.w_v,
            "w_m": self.weights.w_m, "theta_r": self.theta_r,
            "min_margin": self.min_margin, "top_k": self.top_k,
        }
        if not suspicious:
            return AttributionResult([], True, "no_stable_evidence", {}, params)

        adj = {
            e: self._adjusted_time(e, t, roles) for e, t in suspicious.items()
        }
        t_min = min(adj.values())
        candidates: List[OriginCandidate] = []

        for o, t_o in suspicious.items():
            others = [e for e in suspicious if e != o]
            window_start = t_o - self.detection_lead
            paths = graph.best_paths(
                o, window_start, now,
                min_edge_evidence=self.min_edge_evidence, eval_time=now,
            )
            explained: List[str] = []
            contradicted = 0
            qualities: List[float] = []
            unmonitored_on_path = 0
            path_nodes_seen: set[str] = set()
            evidence_ids: List[str] = []
            for v in others:
                hit = paths.get(v)
                if hit is None:
                    continue
                bottleneck, arrival, path_nodes = hit
                if arrival > suspicious[v] + self.arrival_slack:
                    contradicted += 1     # path cannot explain earlier evidence
                    continue
                explained.append(v)
                qualities.append(bottleneck)
                path_nodes_seen.update(path_nodes)
                for a, b in zip(path_nodes, path_nodes[1:]):
                    evidence_ids.extend(graph.edge_provenance(a, b)[-4:])
            for n in path_nodes_seen:
                if not instrumented.get(n, True):
                    unmonitored_on_path += 1

            n_others = max(len(others), 1)
            # Exponential earliness over a fixed horizon: near-simultaneous
            # stable times score near-equally instead of being amplified by
            # spread normalization (supports margin-based abstention).
            earliness = math.exp(-(adj[o] - t_min) / self.earliness_horizon)
            # A lone suspicious entity explains no propagation at all; the
            # design abstains "when required evidence coverage is absent"
            # (Section 6.6), so a singleton must not score full coverage.
            coverage = len(explained) / n_others if others else 0.0
            quality = sum(qualities) / len(qualities) if qualities else 0.0
            contradictions = contradicted / n_others
            unexplained = (
                max(0.0, 1.0 - (len(explained) + contradicted) / n_others)
                if others else 0.0
            )
            unmonitored_frac = (
                unmonitored_on_path / max(len(path_nodes_seen), 1)
            )
            missingness = 0.5 * unexplained + 0.5 * unmonitored_frac
            score = (
                self.weights.w_t * earliness
                + self.weights.w_c * coverage
                + self.weights.w_q * quality
                - self.weights.w_v * contradictions
                - self.weights.w_m * missingness
            )
            candidates.append(
                OriginCandidate(
                    o, score, earliness, coverage, quality,
                    contradictions, missingness, t_o,
                    tuple(explained), tuple(dict.fromkeys(evidence_ids)),
                )
            )

        # Unknown/external origin hypothesis (Sections 6.6 and 10): strong
        # when no observed candidate explains the suspicious set and when
        # telemetry around it is missing.
        best_cov = max((c.coverage for c in candidates), default=0.0)
        uninstrumented_susp = sum(
            1 for e in suspicious if not instrumented.get(e, True)
        )
        missing_rate = uninstrumented_susp / max(len(suspicious), 1)
        unknown_score = 0.6 * (1.0 - best_cov) + 0.4 * missing_rate
        candidates.append(
            OriginCandidate(
                UNKNOWN_ORIGIN, unknown_score, 0.0, 0.0, 0.0, 0.0,
                missing_rate, None,
            )
        )

        candidates.sort(key=lambda c: (-c.score, c.stable_time or math.inf))
        abstained = False
        reason = "confident"
        if candidates[0].score < self.theta_r:
            abstained, reason = True, "score_below_threshold"
        elif len(candidates) > 1 and (
            candidates[0].score - candidates[1].score
        ) < self.min_margin:
            abstained, reason = True, "insufficient_margin"

        return AttributionResult(
            candidates[: self.top_k], abstained, reason, dict(suspicious), params
        )
