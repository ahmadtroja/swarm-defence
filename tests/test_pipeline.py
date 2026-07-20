"""End-to-end pipeline properties (Section 8 procedure): idempotent
ingestion, the no-re-emission rule, producer authenticity for local
evidence, deterministic replay, and full-system smoke runs."""

import dataclasses

import pytest

from swarmdefence.evidence import Signal
from swarmdefence.graph import BenignBaseline
from swarmdefence.model import Entity, EntityType, Event, Relation
from swarmdefence.pipeline import BASELINES, DetectionPipeline, SystemConfig
from swarmdefence.runner import execute_run
from swarmdefence.simulation import Scenario, generate_run


def _entities(*ids, dark=()):
    return {
        i: Entity(i, EntityType.HOST, role="workstation", instrumented=i not in dark)
        for i in ids
    }


def _pipeline(config=None, entities=None):
    base = BenignBaseline()
    base.freeze()
    return DetectionPipeline(
        config or SystemConfig(), entities or _entities("A", "B", "C"), base
    )


def _ev(i, src, dst, t, anomaly, producer=None, corroborated=1.0):
    return Event(
        event_id=f"p-{i}", source=src, target=dst, relation=Relation.AUTH,
        event_time=t, arrival_time=t,
        attributes={"anomaly": anomaly, "corroborated": corroborated},
        producer=producer or f"sensor:{dst}",
    )


def test_idempotent_ingestion():
    p = _pipeline()
    ev = _ev(1, "A", "B", 25.0, 0.5)
    p.ingest_event(ev)
    p.ingest_event(ev)  # duplicate delivery
    assert len(p.ledger) == 1


def test_no_reemission_from_peer_only_elevation():
    """Section 5.1: a sensor never emits a cooperative signal solely
    because peer evidence raised its combined score."""
    # all influence safeguards off, so peer pressure can raise the score
    p = _pipeline(SystemConfig(enforce_gate=False, enforce_budget=False,
                               enforce_diversity=False))
    # heavy peer pressure on entity C via signals about its neighbour B
    p.ingest_event(_ev(0, "B", "C", 25.0, 0.1))  # low local evidence at C
    p.plane.enroll("sensor:X")
    for i in range(1, 40):
        sig = Signal(
            signal_id=f"x{i}", sender="sensor:X", sequence=i, scope="B",
            incident_key=f"k{i}", evidence_weight=1.0,
            event_time=25.0, expiry=27.0,
        )
        p.deliver_signal(sig, 25.0 + i * 0.001)
    assert p._combined("C", 25.1) > p.config.theta_emit  # peer-raised score
    # a subsequent zero-evidence local observation must NOT emit a signal
    emitted = p.ingest_event(_ev(99, "B", "C", 25.2, 0.0))
    assert emitted == []


def test_forged_uncorroborated_event_does_not_raise_peer_local_evidence():
    """Audit: transport authentication does not make signed false
    telemetry trustworthy.  A compromised sensor reporting a fake edge
    scapegoat->flooder must not raise the scapegoat's local evidence."""
    p = _pipeline()
    p.ingest_event(_ev(0, "A", "B", 25.0, 0.95,
                       producer="sensor:B", corroborated=0.0))
    assert p.local.decayed("B", 25.0) == pytest.approx(0.95)  # its own claim
    assert p.local.decayed("A", 25.0) == 0.0                  # peer unaffected


def test_corroborated_event_updates_both_endpoints():
    p = _pipeline()
    p.ingest_event(_ev(0, "A", "B", 25.0, 0.8))
    assert p.local.decayed("B", 25.0) == pytest.approx(0.8)
    assert p.local.decayed("A", 25.0) == pytest.approx(0.48)  # weaker outbound


def test_uninstrumented_entity_has_no_local_evidence():
    p = _pipeline(entities=_entities("A", "B", dark={"A"}))
    p.ingest_event(_ev(0, "A", "B", 25.0, 0.9))
    assert p.local.decayed("A", 25.0) == 0.0
    assert p.local.decayed("B", 25.0) == pytest.approx(0.9)


def test_alerts_recorded_with_threshold():
    cfg = SystemConfig(theta_alert=0.5)
    p = _pipeline(cfg)
    p.ingest_event(_ev(0, "A", "B", 25.0, 0.9))
    assert any(a.entity == "B" and a.combined >= 0.5 for a in p.alerts)


def test_incident_package_is_explainable():
    """Section 5.4: output includes candidates, abstention state,
    parameters, ledger head and signal-plane statistics."""
    p = _pipeline()
    for k in range(8):
        p.ingest_event(_ev(k, "A", "B", 25.0 + 0.05 * k, 0.9))
    pkg = p.incident_package(now=26.0)
    for key in ("top_k", "abstained", "abstain_reason", "suspicious_entities",
                "parameters", "ledger_head", "signal_plane_stats"):
        assert key in pkg


def test_all_baseline_configs_run_end_to_end():
    sc = Scenario(name="smoke", total_hours=30.0, baseline_hours=24.0,
                  dwell_mean=0.2, hops=3)
    run = generate_run(sc, seed=5)
    for name, cfg in BASELINES.items():
        pipeline, result = execute_run(run, cfg)
        assert result.ledger_ok, name
        assert all(0.0 <= s <= 1.0 for _, _, s in pipeline.score_samples), name


def test_deterministic_replay_same_seed():
    """Section 9.6: identical campaigns and seeds must reproduce results
    exactly (deterministic replay of attribution decisions)."""
    sc = Scenario(name="det", total_hours=34.0, dwell_mean=0.3)
    r1 = generate_run(sc, seed=11)
    r2 = generate_run(sc, seed=11)
    _, a = execute_run(r1, BASELINES["B5_full"])
    _, b = execute_run(r2, BASELINES["B5_full"])
    for field in ("detected", "latency", "false_alert_episodes", "top1",
                  "truth_rank", "hop_error", "n_suspicious", "abstained"):
        assert getattr(a, field) == getattr(b, field), field


def test_different_seeds_differ():
    sc = Scenario(name="det", total_hours=34.0, dwell_mean=0.3)
    r1 = generate_run(sc, seed=11)
    r2 = generate_run(sc, seed=12)
    assert [e.event_id for e in r1.events] != [e.event_id for e in r2.events] or \
        r1.truth.origin != r2.truth.origin


def test_rising_edge_emission_only():
    """A sensor signals when local evidence crosses theta_emit from
    below; sustained or decaying evidence is not re-broadcast."""
    p = _pipeline()
    first = p.ingest_event(_ev(0, "A", "B", 25.0, 0.8))
    assert len(first) >= 1                      # crossing emits
    again = p.ingest_event(_ev(1, "A", "B", 25.1, 0.85))
    assert again == []                           # still above: no re-emission


def test_signal_pulled_by_later_edge():
    """Causal-relevance routing: a stored signal about entity X becomes
    relevant to Y when a new edge X->Y appears within freshness."""
    p = _pipeline()
    p.plane.enroll("sensor:X")
    sig = Signal(
        signal_id="sX1", sender="sensor:X", sequence=1, scope="A",
        incident_key="inc", evidence_weight=0.9, event_time=25.0, expiry=27.0,
    )
    assert p.deliver_signal(sig, 25.0)
    # B has no relationship with A yet, so no influence
    assert p._combined("B", 25.0) == 0.0
    # a new edge A->B pulls the stored signal into B's cooperative state
    p.ingest_event(_ev(0, "A", "B", 25.5, 0.4))
    assert p.coop.cooperative("B", 25.5) > 0.0


def test_pulled_signal_contributes_at_most_once_per_recipient():
    p = _pipeline()
    p.plane.enroll("sensor:X")
    sig = Signal(
        signal_id="sX1", sender="sensor:X", sequence=1, scope="A",
        incident_key="inc", evidence_weight=0.9, event_time=25.0, expiry=27.0,
    )
    p.deliver_signal(sig, 25.0)
    p.ingest_event(_ev(0, "A", "B", 25.2, 0.4))
    once = p.coop.cooperative("B", 25.2)
    p.ingest_event(_ev(1, "A", "B", 25.2001, 0.4))  # repeated edge
    assert p.coop.cooperative("B", 25.2001) == pytest.approx(once, rel=1e-6)
