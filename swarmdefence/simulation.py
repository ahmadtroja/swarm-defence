"""Controlled campaign simulator for the Section 9 evaluation protocol.

The design paper prescribes controlled campaigns with exact start times,
origins, path events and sensor state (Section 9.2; a cyber range with
CALDERA or LANL/DARPA data in a full study).  This module provides the
simulation analogue: a synthetic enterprise with benign administration,
backup, monitoring and peer traffic; low-rate lateral-movement campaigns
defined by the Section 9.3 grid parameters (inter-hop dwell, events per
hop, anomaly amplitude, path length); missing telemetry; and
compromised-sensor adversaries (flooding, collusion, replay) for RQ3.

Everything is deterministic given a seed.  Event streams are generated
independently of any system configuration so that all baselines and
ablations are compared on identical telemetry (Section 9.6, paired
comparisons).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .evidence import Signal
from .model import Entity, EntityType, Event, Relation


# --------------------------------------------------------------------------
# Scenario definition (Section 9.3 operational grid)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Scenario:
    name: str = "fast"
    # topology
    n_departments: int = 4
    workstations_per_dept: int = 10
    n_jump_hosts: int = 2
    uninstrumented_fraction: float = 0.10
    # timeline (hours)
    baseline_hours: float = 24.0
    total_hours: float = 60.0
    # benign rates (events/hour)
    rate_wk_to_server: float = 0.5
    rate_wk_peer: float = 0.15
    rate_admin: float = 1.2
    rate_backup: float = 0.4
    rate_monitor: float = 2.0
    benign_spike_prob: float = 0.015
    # attack grid (Section 9.3)
    attack: bool = True
    hops: int = 5
    dwell_mean: float = 0.5            # inter-hop dwell, hours
    events_per_hop: int = 3
    amplitude: float = 0.5             # anomaly amplitude of attack events
    foothold_events: int = 3           # initial-access trace at the origin
    foothold_boost: float = 0.05       # initial access is slightly noisier
    silenced_origin: bool = False      # origin sensor missing (Section 10)
    # adversarial sensors (RQ3)
    n_flooders: int = 0                # compromised sensors framing a scapegoat
    flood_interval: float = 0.05       # hours between forged messages
    flood_duration: float = 6.0        # hours of flooding
    replay: bool = False               # replay captured genuine signals
    replay_copies: int = 50


@dataclass
class GroundTruth:
    origin: Optional[str]
    first_instrumented: Optional[str]
    hop_edges: List[Tuple[str, str, float]]
    compromised: List[str]
    first_event_time: Optional[float]
    last_event_time: Optional[float]
    scapegoat: Optional[str] = None
    flooders: List[str] = field(default_factory=list)


@dataclass
class SimulatedRun:
    scenario: Scenario
    seed: int
    entities: Dict[str, Entity]
    events: List[Event]                     # time-ordered telemetry
    # adversarial cooperative messages as (delivery_time, signal); replayed
    # copies keep identical content but arrive at later delivery times
    injected_signals: List[Tuple[float, Signal]]
    truth: GroundTruth
    hop_distance: Dict[Tuple[str, str], int] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------

def build_entities(sc: Scenario, rng: random.Random) -> Tuple[Dict[str, Entity], Dict[str, List[str]]]:
    entities: Dict[str, Entity] = {}
    depts: Dict[str, List[str]] = {}
    for d in range(sc.n_departments):
        dept = f"dept{d}"
        depts[dept] = []
        for w in range(sc.workstations_per_dept):
            hid = f"wk-{d}-{w}"
            entities[hid] = Entity(hid, EntityType.HOST, role="workstation")
            depts[dept].append(hid)
        srv = f"srv-{d}"
        entities[srv] = Entity(srv, EntityType.HOST, role="server")
        depts[dept].append(srv)
    for j in range(sc.n_jump_hosts):
        jid = f"jump-{j}"
        entities[jid] = Entity(jid, EntityType.HOST, role="jump")
    entities["backup-0"] = Entity("backup-0", EntityType.HOST, role="backup")
    entities["monitor-0"] = Entity("monitor-0", EntityType.HOST, role="monitor")

    # Missing telemetry: a seeded subset of workstations is uninstrumented.
    workstations = [e for e in entities.values() if e.role == "workstation"]
    n_dark = int(len(workstations) * sc.uninstrumented_fraction)
    dark = rng.sample(sorted(w.entity_id for w in workstations), n_dark)
    for hid in dark:
        entities[hid] = Entity(hid, EntityType.HOST, role="workstation", instrumented=False)
    return entities, depts


def _poisson_times(rng: random.Random, rate: float, t0: float, t1: float) -> List[float]:
    times, t = [], t0
    if rate <= 0:
        return times
    while True:
        t += rng.expovariate(rate)
        if t >= t1:
            return times
        times.append(t)


def _benign_anomaly(sc: Scenario, rng: random.Random, low: bool = False) -> float:
    if low:
        return min(1.0, rng.betavariate(1.2, 30))
    if rng.random() < sc.benign_spike_prob:
        # rare unusual-but-legitimate administration (Section 11)
        return min(1.0, rng.betavariate(5.0, 5.0))
    return min(1.0, rng.betavariate(1.5, 14.0))


def _mk_event(
    eid: int,
    src: str,
    dst: str,
    rel: Relation,
    t: float,
    anomaly: float,
    entities: Dict[str, Entity],
    rng: random.Random,
    producer: Optional[str] = None,
    corroborated: Optional[bool] = None,
) -> Optional[Event]:
    """Build a telemetry record for underlying activity src->dst.

    The canonical record is produced by the target's sensor when it is
    instrumented, otherwise by the source's sensor; if neither endpoint
    is instrumented, the activity is unobserved (returns None).
    ``corroborated`` marks whether both endpoint sensors agree.
    """
    # entities outside the managed inventory (e.g. external endpoints)
    # have no sensor at all
    src_ok = src in entities and entities[src].instrumented
    dst_ok = dst in entities and entities[dst].instrumented
    if producer is None:
        if dst_ok:
            producer = f"sensor:{dst}"
        elif src_ok:
            producer = f"sensor:{src}"
        else:
            return None
    if corroborated is None:
        corroborated = src_ok and dst_ok
    return Event(
        event_id=f"ev-{eid}",
        source=src,
        target=dst,
        relation=rel,
        event_time=t,
        arrival_time=t + rng.uniform(0.001, 0.02),
        attributes={"anomaly": round(anomaly, 6), "corroborated": 1.0 if corroborated else 0.0},
        producer=producer,
    )


def generate_run(sc: Scenario, seed: int) -> SimulatedRun:
    rng = random.Random(seed * 1_000_003 + 17)
    entities, depts = build_entities(sc, rng)
    events: List[Event] = []
    eid = 0

    def emit(src, dst, rel, t, anomaly, **kw):
        nonlocal eid
        ev = _mk_event(eid, src, dst, rel, t, anomaly, entities, rng, **kw)
        if ev is not None:
            events.append(ev)
            eid += 1
        return ev

    servers = [f"srv-{d}" for d in range(sc.n_departments)]
    jumps = [f"jump-{j}" for j in range(sc.n_jump_hosts)]
    all_hosts = sorted(entities)

    # ---- benign background over the whole timeline ----------------------
    for d in range(sc.n_departments):
        dept_hosts = [h for h in depts[f"dept{d}"] if h.startswith("wk-")]
        srv = f"srv-{d}"
        for h in dept_hosts:
            for t in _poisson_times(rng, sc.rate_wk_to_server, 0.0, sc.total_hours):
                emit(h, srv, Relation.AUTH, t, _benign_anomaly(sc, rng))
            for t in _poisson_times(rng, sc.rate_wk_peer, 0.0, sc.total_hours):
                peer = rng.choice([x for x in dept_hosts if x != h])
                emit(h, peer, Relation.FLOW, t, _benign_anomaly(sc, rng))
    for j in jumps:
        for t in _poisson_times(rng, sc.rate_admin, 0.0, sc.total_hours):
            emit(j, rng.choice(all_hosts), Relation.ADMIN, t, _benign_anomaly(sc, rng))
    for srv in servers:
        for t in _poisson_times(rng, sc.rate_backup, 0.0, sc.total_hours):
            emit(srv, "backup-0", Relation.SESSION, t, _benign_anomaly(sc, rng))
    for t in _poisson_times(rng, sc.rate_monitor, 0.0, sc.total_hours):
        emit("monitor-0", rng.choice(all_hosts), Relation.FLOW, t,
             _benign_anomaly(sc, rng, low=True))

    # ---- attack campaign (Section 9.3 grid) ------------------------------
    truth = GroundTruth(None, None, [], [], None, None)
    if sc.attack:
        workstations = sorted(
            e.entity_id for e in entities.values() if e.role == "workstation"
        )
        if sc.silenced_origin:
            origin = rng.choice(workstations)
            entities[origin] = Entity(origin, EntityType.HOST,
                                      role="workstation", instrumented=False)
        else:
            origin = rng.choice(
                [w for w in workstations if entities[w].instrumented]
            )
        t = sc.baseline_hours + 4.0 + rng.uniform(0.0, 4.0)
        truth.origin = origin
        truth.compromised = [origin]
        truth.first_instrumented = origin if entities[origin].instrumented else None
        # Initial-access trace: the foothold leaves a small number of
        # anomalous inbound events at the origin (C2 establishment).  If
        # the origin is uninstrumented these are unobserved -- telemetry
        # may begin after compromise (Section 2).
        foot_t = t - rng.uniform(0.4, 0.9)
        for k in range(sc.foothold_events):
            te = foot_t + k * rng.uniform(0.02, 0.06)
            amp = min(0.95, max(0.05, rng.gauss(sc.amplitude + sc.foothold_boost, 0.07)))
            ev = emit("ext-c2", origin, Relation.FLOW, te, amp)
            if ev is not None:
                if truth.first_event_time is None or te < truth.first_event_time:
                    truth.first_event_time = te
                truth.last_event_time = max(truth.last_event_time or te, te)
        current = origin
        for _hop in range(sc.hops):
            dept = current.split("-")[1] if current.startswith("wk-") else None
            same_dept = [
                h for h in workstations
                if h not in truth.compromised
                and dept is not None and h.startswith(f"wk-{dept}-")
            ]
            candidates = same_dept if (same_dept and rng.random() < 0.7) else [
                h for h in workstations + servers if h not in truth.compromised
            ]
            if not candidates:
                break
            nxt = rng.choice(sorted(candidates))
            n_events = max(1, sc.events_per_hop - rng.randrange(0, 2))
            hop_t0 = None
            for k in range(n_events):
                te = t + k * rng.uniform(0.03, 0.1)
                amp = min(0.95, max(0.05, rng.gauss(sc.amplitude, 0.07)))
                ev = emit(current, nxt, Relation.AUTH, te, amp)
                if ev is not None:
                    if truth.first_event_time is None:
                        truth.first_event_time = te
                    truth.last_event_time = te
                    if hop_t0 is None:
                        hop_t0 = te
            if hop_t0 is not None:
                truth.hop_edges.append((current, nxt, hop_t0))
            truth.compromised.append(nxt)
            if truth.first_instrumented is None and entities[nxt].instrumented:
                truth.first_instrumented = nxt
            current = nxt
            t += rng.expovariate(1.0 / sc.dwell_mean) + 0.05

    # ---- adversarial sensors (RQ3) ---------------------------------------
    injected: List[Tuple[float, Signal]] = []
    if sc.n_flooders > 0:
        instrumented_wk = sorted(
            e.entity_id for e in entities.values()
            if e.role == "workstation" and e.instrumented
            and e.entity_id not in truth.compromised
        )
        scapegoat = rng.choice(instrumented_wk)
        flooders = rng.sample([h for h in instrumented_wk if h != scapegoat],
                              sc.n_flooders)
        truth.scapegoat = scapegoat
        truth.flooders = flooders
        t0 = truth.first_event_time or (sc.baseline_hours + 6.0)
        for fi, fl in enumerate(flooders):
            seq = 0
            tt = t0 + rng.uniform(0.0, 0.1)
            while tt < min(t0 + sc.flood_duration, sc.total_hours):
                # forged telemetry: scapegoat -> flooder, reported ONLY by
                # the flooder's own compromised sensor (uncorroborated)
                emit(scapegoat, fl, Relation.AUTH, tt, 0.9,
                     producer=f"sensor:{fl}", corroborated=False)
                # forged cooperative message about the flooder itself, so
                # that graph relevance routes influence to the scapegoat;
                # the adversary varies the incident key to defeat
                # semantic-uniqueness decay (it controls message fields)
                seq += 1
                injected.append((tt + 0.005, Signal(
                    signal_id=f"flood:{fl}:{seq}",
                    sender=f"sensor:{fl}",
                    sequence=seq,
                    scope=fl,
                    incident_key=f"forged-{fl}-{seq}",
                    evidence_weight=1.0,
                    event_time=tt,
                    expiry=tt + 2.0,
                )))
                tt += sc.flood_interval * rng.uniform(0.8, 1.2)

    if sc.replay:
        # The replayer captures genuine-looking signals and re-sends exact
        # copies (same id, same sequence): the signal plane must reject
        # them by unique id / sequence / freshness (Section 10).
        victim = truth.compromised[1] if len(truth.compromised) > 1 else None
        if victim is not None and entities[victim].instrumented:
            base_t = (truth.first_event_time or sc.baseline_hours) + 0.2
            captured = Signal(
                signal_id=f"sig:{victim}:1",
                sender=f"sensor:{victim}",
                sequence=1,
                scope=victim,
                incident_key="incident-0",
                evidence_weight=0.9,
                event_time=base_t,
                expiry=base_t + 2.0,
            )
            for c in range(sc.replay_copies):
                # identical copies delivered at increasing times
                injected.append((base_t + 0.1 + 0.1 * c, captured))

    events.sort(key=lambda e: e.event_time)
    injected.sort(key=lambda pair: pair[0])

    run = SimulatedRun(sc, seed, entities, events, injected, truth)
    run.hop_distance = _hop_distances(events, truth)
    return run


def _hop_distances(events: Sequence[Event], truth: GroundTruth) -> Dict[Tuple[str, str], int]:
    """Undirected BFS distances from the true origin over the union graph
    (used for the hop-distance-error attribution metric, Section 9.5)."""
    if truth.origin is None:
        return {}
    adj: Dict[str, set] = {}
    for ev in events:
        adj.setdefault(ev.source, set()).add(ev.target)
        adj.setdefault(ev.target, set()).add(ev.source)
    dist = {truth.origin: 0}
    frontier = [truth.origin]
    while frontier:
        nxt = []
        for u in frontier:
            for v in adj.get(u, ()):
                if v not in dist:
                    dist[v] = dist[u] + 1
                    nxt.append(v)
        frontier = nxt
    return {(truth.origin, n): d for n, d in dist.items()}
