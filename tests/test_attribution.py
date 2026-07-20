"""Stable-evidence semantics (Section 6.5) and Equation 5 origin ranking
with top-k, unknown-origin, and abstention (Section 6.6)."""

import pytest

from swarmdefence.attribution import (
    UNKNOWN_ORIGIN,
    OriginRanker,
    RankingWeights,
    StableEvidenceTracker,
)
from swarmdefence.graph import TemporalGraph
from swarmdefence.model import Event, Relation


def _ev(i, src, dst, t, anomaly=0.8):
    return Event(
        event_id=f"a-{i}", source=src, target=dst, relation=Relation.AUTH,
        event_time=t, arrival_time=t, attributes={"anomaly": anomaly},
        producer=f"sensor:{dst}",
    )


# -- stability ------------------------------------------------------------

def test_sustained_evidence_becomes_stable():
    tr = StableEvidenceTracker(theta_s=0.6, tau=0.5, kappa_hold=0.5)
    for k in range(6):
        tr.observe("n", 0.8, k * 0.2)
    assert tr.suspicious()["n"] == pytest.approx(0.5)  # stable_since + tau
    assert tr.first_alerts()["n"] == 0.0


def test_brief_spike_is_not_stable():
    tr = StableEvidenceTracker(theta_s=0.6, tau=0.5, kappa_hold=1.0)
    tr.observe("n", 0.65, 0.0)   # analytic hold is far below tau
    tr.observe("n", 0.2, 0.3)    # and the hold breaks
    assert "n" not in tr.suspicious()


def test_gap_beyond_tolerance_resets_stability():
    tr = StableEvidenceTracker(theta_s=0.6, tau=1.5, kappa_hold=1.0,
                               gap_tolerance=0.5)
    tr.observe("n", 0.65, 0.0)
    tr.observe("n", 0.65, 5.0)   # unbridgeable gap: hold restarts at t=5
    tr.observe("n", 0.65, 5.4)
    assert "n" not in tr.suspicious()


def test_first_alert_precedes_stable_time():
    """Section 6.5: report first-alert and stable times separately; the
    stability window necessarily adds attribution delay."""
    tr = StableEvidenceTracker(theta_s=0.6, tau=0.5, kappa_hold=0.5)
    for k in range(6):
        tr.observe("n", 0.9, k * 0.2)
    assert tr.first_alerts()["n"] < tr.suspicious()["n"]


# -- ranking ---------------------------------------------------------------

def _chain_graph():
    g = TemporalGraph(kappa_p=0.05)
    g.add_event(_ev(0, "A", "B", 1.0))
    g.add_event(_ev(1, "B", "C", 2.0))
    return g


def test_true_chain_origin_ranks_first():
    g = _chain_graph()
    ranker = OriginRanker()
    suspicious = {"A": 1.2, "B": 1.5, "C": 2.5}
    res = ranker.rank(g, suspicious, roles={}, instrumented={}, now=3.0)
    assert res.top1 == "A"
    assert not res.abstained
    top_a = res.ranking[0]
    assert top_a.coverage == pytest.approx(1.0)  # A explains B and C
    assert top_a.evidence_events  # provenance ids attached (Section 5.4)


def test_abstains_without_stable_evidence():
    res = OriginRanker().rank(_chain_graph(), {}, {}, {}, now=3.0)
    assert res.abstained and res.abstain_reason == "no_stable_evidence"


def test_unknown_origin_wins_when_nothing_explains_the_evidence():
    """Two suspicious entities with no connecting paths: the unknown or
    external origin hypothesis must outrank both observed candidates."""
    g = TemporalGraph(kappa_p=0.05)  # no edges at all
    res = OriginRanker().rank(g, {"X": 1.0, "Y": 1.1}, {}, {}, now=2.0)
    assert res.top1 == UNKNOWN_ORIGIN


def test_abstains_on_small_margin():
    g = TemporalGraph(kappa_p=0.05)
    g.add_event(_ev(0, "A", "B", 1.0))
    g.add_event(_ev(1, "B", "A", 1.1))  # symmetric evidence, ambiguous
    res = OriginRanker(min_margin=0.05).rank(
        g, {"A": 1.2, "B": 1.21}, {}, {}, now=2.0
    )
    assert res.abstained
    assert res.abstain_reason in ("insufficient_margin", "score_below_threshold")
    assert res.ranking  # top-k is still reported alongside the abstention


def test_temporal_contradiction_penalized():
    """A candidate whose paths arrive only after a node was already
    suspicious cannot explain that node (V term)."""
    g = TemporalGraph(kappa_p=0.05)
    g.add_event(_ev(0, "A", "B", 5.0))
    ranker = OriginRanker(arrival_slack=0.1)
    # B was stably suspicious at t=1.0, long before A->B at t=5.0
    res = ranker.rank(g, {"A": 0.5, "B": 1.0}, {}, {}, now=6.0)
    a = next(c for c in res.ranking if c.entity == "A")
    assert a.contradictions > 0
    assert a.coverage == 0.0


def test_missing_telemetry_penalized_and_reported():
    g = _chain_graph()
    res = OriginRanker().rank(
        g, {"A": 1.2, "B": 1.5, "C": 2.5},
        roles={},
        instrumented={"B": False},  # mid-path node has no sensor
        now=3.0,
    )
    a = next(c for c in res.ranking if c.entity == "A")
    assert a.missingness > 0


def test_role_sensor_delay_adjusts_earliness():
    """Section 6.6: earliness must account for role-specific detector
    delay -- a slow-sensor role with a later stable time can still be
    earliest after adjustment."""
    g = TemporalGraph(kappa_p=0.05)
    g.add_event(_ev(0, "S", "W", 1.0))
    ranker = OriginRanker(role_sensor_delay={"server": 0.5, "workstation": 0.0})
    res = ranker.rank(
        g, {"S": 1.3, "W": 1.0},
        roles={"S": "server", "W": "workstation"},
        instrumented={}, now=2.0,
    )
    s = next(c for c in res.ranking if c.entity == "S")
    w = next(c for c in res.ranking if c.entity == "W")
    assert s.earliness > w.earliness  # 1.3 - 0.5 < 1.0 - 0.0


def test_weights_must_sum_to_one():
    with pytest.raises(ValueError):
        RankingWeights(w_t=0.5, w_c=0.5, w_q=0.5)


def test_topk_bounded():
    g = _chain_graph()
    res = OriginRanker(top_k=2).rank(g, {"A": 1.2, "B": 1.5, "C": 2.5}, {}, {}, 3.0)
    assert len(res.ranking) <= 2
