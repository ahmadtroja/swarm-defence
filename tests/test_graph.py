"""Equation 4 and graph-view properties: bounded edge evidence,
elapsed-time decay (vs. the audited tick-based accumulator), benign
baseline scoring, and time-respecting path search."""

import random

import pytest

from swarmdefence.graph import BenignBaseline, TemporalGraph
from swarmdefence.model import Event, Relation


def _ev(i, src, dst, t, anomaly, corroborated=1.0):
    return Event(
        event_id=f"g-{i}",
        source=src,
        target=dst,
        relation=Relation.AUTH,
        event_time=t,
        arrival_time=t,
        attributes={"anomaly": anomaly, "corroborated": corroborated},
        producer=f"sensor:{dst}",
    )


def test_edge_evidence_bounded_under_continuous_reinforcement():
    """The audited original accumulator approached delta/(1-lambda) at a
    scale set by scheduler cadence; Equation 4 must stay in [0,1]."""
    g = TemporalGraph(kappa_p=0.35)
    for i in range(1000):
        v = g.add_event(_ev(i, "A", "B", i * 0.01, 0.9))
        assert 0.0 <= v <= 1.0
    assert g.edge_evidence("A", "B", 10.0) <= 1.0


def test_edge_evidence_decays_with_elapsed_time():
    g = TemporalGraph(kappa_p=0.5)
    g.add_event(_ev(0, "A", "B", 0.0, 0.8))
    assert g.edge_evidence("A", "B", 1.0) < g.edge_evidence("A", "B", 0.0)
    assert g.edge_evidence("A", "B", 20.0) < 0.01


def test_static_mode_does_not_decay():
    g = TemporalGraph(kappa_p=0.5, temporal_decay=False)
    g.add_event(_ev(0, "A", "B", 0.0, 0.8))
    assert g.edge_evidence("A", "B", 100.0) == g.edge_evidence("A", "B", 0.0)


def test_benign_baseline_suppresses_repeated_routes():
    """Repeated use alone must not accumulate attack evidence (Section
    6.4): a route seen often in the benign baseline gains far less edge
    evidence than a novel route for the same anomaly value."""
    base = BenignBaseline()
    for _ in range(30):
        base.observe("A", "B")
    base.freeze()
    g = TemporalGraph(baseline=base)
    v_known = g.add_event(_ev(0, "A", "B", 1.0, 0.6))
    v_novel = g.add_event(_ev(1, "A", "C", 1.0, 0.6))
    assert v_novel > 10 * v_known


def test_baseline_freeze_prevents_training_contamination():
    base = BenignBaseline()
    base.observe("A", "B")
    base.freeze()
    with pytest.raises(RuntimeError):
        base.observe("A", "B")  # test campaigns must not alter the baseline


def test_time_respecting_paths_enforce_causal_order():
    """A->B at t=2 cannot be followed by B->C at t=1 (Section 6.6)."""
    g = TemporalGraph(kappa_p=0.1)
    g.add_event(_ev(0, "B", "C", 1.0, 0.9))
    g.add_event(_ev(1, "A", "B", 2.0, 0.9))
    paths = g.best_paths("A", 0.0, 10.0, eval_time=2.5)
    assert "B" in paths
    assert "C" not in paths  # would require going back in time
    # the static baseline ignores temporal order and (incorrectly) reaches C
    gs = TemporalGraph(kappa_p=0.1, temporal_decay=False)
    gs.add_event(_ev(0, "B", "C", 1.0, 0.9))
    gs.add_event(_ev(1, "A", "B", 2.0, 0.9))
    assert "C" in gs.best_paths("A", 0.0, 10.0)


def test_time_respecting_chain_is_found_with_bottleneck_quality():
    g = TemporalGraph(kappa_p=0.05)
    g.add_event(_ev(0, "A", "B", 1.0, 0.9))
    g.add_event(_ev(1, "B", "C", 2.0, 0.5))
    paths = g.best_paths("A", 0.0, 10.0, eval_time=2.0)
    assert set(paths) == {"B", "C"}
    b_quality, _, path_b = paths["B"]
    c_quality, _, path_c = paths["C"]
    assert path_c == ("A", "B", "C")
    assert c_quality <= b_quality  # bottleneck cannot improve along a path


def test_edge_provenance_retained():
    g = TemporalGraph()
    g.add_event(_ev(0, "A", "B", 1.0, 0.9))
    assert g.edge_provenance("A", "B") == ("g-0",)
