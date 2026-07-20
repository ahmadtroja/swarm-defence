"""Execute simulated runs through configured pipelines and score them.

Implements the measurement side of the Section 9 protocol:

* identical telemetry per (scenario, seed) across all configurations
  (paired comparisons, Section 9.6);
* offline threshold calibration at a matched false-alert budget
  (detection thresholds are frozen before test runs);
* detection, attribution, cooperation-safety and systems metrics
  (Section 9.5);
* percentile bootstrap confidence intervals for paired differences.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field, replace
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .attribution import UNKNOWN_ORIGIN
from .graph import BenignBaseline
from .pipeline import DetectionPipeline, SystemConfig
from .simulation import Scenario, SimulatedRun, generate_run

ROLE_SENSOR_DELAY = {
    "workstation": 0.05,
    "server": 0.10,
    "jump": 0.10,
    "backup": 0.10,
    "monitor": 0.05,
}


@dataclass
class RunResult:
    config: str
    scenario: str
    seed: int
    # detection (Section 9.5)
    detected: bool
    latency: Optional[float]              # first useful alert - first attack event
    false_alert_episodes: int
    host_days: float
    # attribution
    attributed: bool                      # produced a non-abstained ranking
    abstained: bool
    abstain_reason: str
    top1: Optional[str]
    unknown_top1: bool                    # ranker chose the unknown/external origin
    truth_rank: Optional[int]             # rank of true origin in top-k (1-based)
    observable_rank: Optional[int]        # rank of earliest observable origin
    hop_error: Optional[int]
    n_suspicious: int
    # cooperation safety
    benign_elevated: int
    benign_elevations_per_host_hour: float
    scapegoat_framed: bool
    scapegoat_in_topk: bool
    saturation_rate: float
    sender_concentration: float
    plane_stats: Dict[str, int]
    # systems
    events_processed: int
    signals_emitted: int
    wall_seconds: float
    events_per_second: float
    ledger_ok: bool

    def fa_per_host_day(self) -> float:
        return self.false_alert_episodes / self.host_days if self.host_days else 0.0


def count_alert_episodes(
    samples: Sequence[Tuple[str, float, float]],
    theta: float,
    t_start: float,
    exclude: Optional[set] = None,
    hysteresis: float = 0.8,
) -> int:
    """Episode-based alert counting on score samples: an entity re-arms
    only after its score falls below hysteresis * theta.  Used both for
    calibration and for false-alert measurement, so the budget definition
    is identical across systems."""
    exclude = exclude or set()
    armed: Dict[str, bool] = {}
    episodes = 0
    for entity, t, s in samples:
        if t < t_start or entity in exclude:
            continue
        if s >= theta and armed.get(entity, True):
            episodes += 1
            armed[entity] = False
        elif s < hysteresis * theta:
            armed[entity] = True
    return episodes


def execute_run(
    run: SimulatedRun,
    config: SystemConfig,
    transport_delay: float = 0.02,
) -> Tuple[DetectionPipeline, RunResult]:
    sc = run.scenario
    baseline = BenignBaseline()
    for ev in run.events:
        if ev.event_time < sc.baseline_hours:
            baseline.observe(ev.source, ev.target)
    baseline.freeze()

    pipeline = DetectionPipeline(config, run.entities, baseline, ROLE_SENSOR_DELAY)
    # Adversarial senders are enrolled sensors by definition (they are
    # compromised, not unauthenticated -- Section 4.1).
    t0 = time.perf_counter()
    signals_emitted = 0
    inj = list(run.injected_signals)
    ptr = 0
    for ev in run.events:
        while ptr < len(inj) and inj[ptr][0] <= ev.event_time:
            deliver_at, sig = inj[ptr]
            pipeline.deliver_signal(sig, deliver_at)
            ptr += 1
        emitted = pipeline.ingest_event(ev)
        for sig in emitted:
            signals_emitted += 1
            pipeline.deliver_signal(sig, ev.event_time + transport_delay)
    while ptr < len(inj):
        deliver_at, sig = inj[ptr]
        pipeline.deliver_signal(sig, deliver_at)
        ptr += 1
    wall = time.perf_counter() - t0

    truth = run.truth
    compromised = set(truth.compromised)
    test_start = sc.baseline_hours
    test_hours = sc.total_hours - test_start
    n_instr = sum(1 for e in run.entities.values() if e.instrumented)
    host_days = n_instr * test_hours / 24.0

    # -- detection metrics -------------------------------------------------
    detected, latency = False, None
    if truth.first_event_time is not None:
        useful = [
            a for a in pipeline.alerts
            if a.entity in compromised and a.time >= truth.first_event_time
        ]
        if useful:
            detected = True
            latency = min(a.time for a in useful) - truth.first_event_time
    fa = count_alert_episodes(
        pipeline.score_samples, config.theta_alert, test_start, exclude=compromised
    )

    # -- attribution metrics ------------------------------------------------
    attribution_time = (
        (truth.last_event_time or sc.total_hours) + 2.0
        if truth.first_event_time is not None
        else sc.total_hours
    )
    result = pipeline.attribute(min(attribution_time, sc.total_hours))
    ranked = [c.entity for c in result.ranking]
    truth_rank = (
        ranked.index(truth.origin) + 1 if truth.origin in ranked else None
    )
    observable = truth.first_instrumented
    observable_rank = (
        ranked.index(observable) + 1 if observable in ranked else None
    )
    hop_error = None
    if not result.abstained and ranked and truth.origin is not None:
        top1 = ranked[0]
        if top1 != UNKNOWN_ORIGIN:
            hop_error = run.hop_distance.get((truth.origin, top1))

    # -- cooperation-safety metrics -----------------------------------------
    peaks: Dict[str, float] = {}
    for entity, t, s in pipeline.score_samples:
        if t >= test_start:
            peaks[entity] = max(peaks.get(entity, 0.0), s)
    theta_s = config.stable_threshold()
    benign_elevated = sum(
        1 for e, p in peaks.items() if e not in compromised and p >= theta_s
    )
    saturation = (
        sum(1 for p in peaks.values() if p >= 0.95) / len(peaks) if peaks else 0.0
    )
    # "framed" means the scapegoat entered the STABLE suspicious set (and
    # so became an origin candidate); transient peak elevations are
    # captured separately by benign_elevated.
    sg = truth.scapegoat
    framed = bool(sg and sg in result.suspicious)
    sg_topk = bool(sg and sg in ranked)

    ledger_ok = pipeline.ledger.verify()

    return pipeline, RunResult(
        config=config.name,
        scenario=sc.name,
        seed=run.seed,
        detected=detected,
        latency=latency,
        false_alert_episodes=fa,
        host_days=host_days,
        attributed=not result.abstained and bool(ranked),
        abstained=result.abstained,
        abstain_reason=result.abstain_reason,
        top1=ranked[0] if ranked else None,
        unknown_top1=bool(ranked) and ranked[0] == UNKNOWN_ORIGIN,
        truth_rank=truth_rank,
        observable_rank=observable_rank,
        hop_error=hop_error,
        n_suspicious=len(result.suspicious),
        benign_elevated=benign_elevated,
        benign_elevations_per_host_hour=benign_elevated / (n_instr * test_hours),
        scapegoat_framed=framed,
        scapegoat_in_topk=sg_topk,
        saturation_rate=saturation,
        sender_concentration=pipeline.coop.sender_concentration(),
        plane_stats=pipeline.plane.stats.as_dict(),
        events_processed=len(pipeline.ledger),
        signals_emitted=signals_emitted,
        wall_seconds=wall,
        events_per_second=len(pipeline.ledger) / wall if wall > 0 else 0.0,
        ledger_ok=ledger_ok,
    )


# --------------------------------------------------------------------------
# Threshold calibration at a matched false-alert budget (Section 9.6)
# --------------------------------------------------------------------------

def calibrate_threshold(
    config: SystemConfig,
    seeds: Sequence[int],
    target_fa_per_host_day: float,
    scenario: Optional[Scenario] = None,
    theta_grid: Optional[Sequence[float]] = None,
) -> Tuple[float, Dict[float, float]]:
    """Pick the smallest alert threshold whose mean false-alert rate on
    attack-free calibration runs stays within the budget.  Score dynamics
    do not depend on theta_alert, so each calibration run is executed once
    and thresholds are evaluated offline on the recorded score samples."""
    sc = scenario or Scenario(name="calibration", attack=False)
    grid = list(theta_grid or [round(0.40 + 0.025 * i, 3) for i in range(21)])
    per_theta: Dict[float, List[float]] = {th: [] for th in grid}
    for seed in seeds:
        run = generate_run(sc, seed)
        pipeline, _ = execute_run(run, config)
        n_instr = sum(1 for e in run.entities.values() if e.instrumented)
        host_days = n_instr * (sc.total_hours - sc.baseline_hours) / 24.0
        for th in grid:
            fa = count_alert_episodes(pipeline.score_samples, th, sc.baseline_hours)
            per_theta[th].append(fa / host_days)
    means = {th: sum(v) / len(v) for th, v in per_theta.items()}
    feasible = [th for th in grid if means[th] <= target_fa_per_host_day]
    theta = min(feasible) if feasible else max(grid)
    return theta, means


# --------------------------------------------------------------------------
# Statistics (Section 9.6)
# --------------------------------------------------------------------------

def mean(xs: Sequence[float]) -> Optional[float]:
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def median(xs: Sequence[float]) -> Optional[float]:
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    n = len(xs)
    return xs[n // 2] if n % 2 else 0.5 * (xs[n // 2 - 1] + xs[n // 2])


def bootstrap_ci(
    values: Sequence[float],
    n_boot: int = 2000,
    seed: int = 7,
    alpha: float = 0.05,
) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    """Percentile bootstrap CI for the mean of ``values`` (paired
    differences are passed in already paired by seed)."""
    vals = [v for v in values if v is not None]
    if not vals:
        return None, None, None
    rng = random.Random(seed)
    n = len(vals)
    boots = []
    for _ in range(n_boot):
        sample = [vals[rng.randrange(n)] for _ in range(n)]
        boots.append(sum(sample) / n)
    boots.sort()
    lo = boots[int(alpha / 2 * n_boot)]
    hi = boots[min(n_boot - 1, int((1 - alpha / 2) * n_boot))]
    return sum(vals) / n, lo, hi
