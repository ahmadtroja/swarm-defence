"""Equations 2-3: influence budgets, source diversity, uniqueness decay,
staleness decay, and the local-evidence gate.

These are the audit's central security findings: "a cap on scores does
not stop replay, flooding, collusion" -- bounded STATE is not bounded
INFLUENCE.  The budget, per-source share cap, uniqueness decay and gate
are the influence controls, and each is verified here."""

import pytest

from swarmdefence.evidence import CooperativeEvidence, Signal


def _sig(i: int, sender="sensor:F", scope="victim", key=None, weight=1.0, t=0.0):
    return Signal(
        signal_id=f"s{sender}-{i}",
        sender=sender,
        sequence=i,
        scope=scope,
        incident_key=key if key is not None else f"k{i}",
        evidence_weight=weight,
        event_time=t,
        expiry=t + 2.0,
    )


def test_flooding_single_source_bounded_by_share_cap_and_budget():
    coop = CooperativeEvidence(budget=0.6, source_share_cap=0.4)
    for i in range(500):  # adversary varies incident keys to defeat dedupe
        coop.contribute("j", _sig(i, t=0.0), trust=1.0, relevance=1.0, now=0.0)
    c = coop.cooperative("j", 0.0)
    assert c <= 0.4 * 0.6 + 1e-9  # single sender capped at its diversity share


def test_colluding_sources_bounded_by_aggregate_budget():
    coop = CooperativeEvidence(budget=0.6, source_share_cap=0.4)
    for s in range(10):  # ten colluding senders
        for i in range(100):
            coop.contribute("j", _sig(i, sender=f"sensor:F{s}", t=0.0),
                            trust=1.0, relevance=1.0, now=0.0)
    assert coop.cooperative("j", 0.0) <= 0.6 + 1e-9


def test_no_budget_ablation_allows_saturation():
    coop = CooperativeEvidence(budget=0.6, enforce_budget=False,
                               enforce_diversity=False)
    for i in range(100):
        coop.contribute("j", _sig(i, t=0.0), trust=1.0, relevance=1.0, now=0.0)
    assert coop.cooperative("j", 0.0) > 1.0  # unbounded influence (ablation)
    # ...but combined evidence is still numerically clamped to [0,1]:
    assert coop.combined("j", 0.5, 0.0) == 1.0


def test_gate_blocks_peer_only_elevation():
    """An entity with zero local evidence cannot be raised by peer
    evidence alone (Equation 3): S_j = L_j + g_j * C_j with g_j = 0."""
    coop = CooperativeEvidence(theta_g=0.2)
    for i in range(50):
        coop.contribute("j", _sig(i, t=0.0), trust=1.0, relevance=1.0, now=0.0)
    assert coop.combined("j", 0.0, 0.0) == 0.0
    # with adequate local evidence the gate opens fully
    assert coop.combined("j", 0.3, 0.0) > 0.3


def test_gate_ablation_allows_peer_only_elevation():
    coop = CooperativeEvidence(theta_g=0.2, enforce_gate=False)
    for i in range(50):
        coop.contribute("j", _sig(i, t=0.0), trust=1.0, relevance=1.0, now=0.0)
    assert coop.combined("j", 0.0, 0.0) > 0.0


def test_uniqueness_decay_on_repeated_claims():
    """Semantic repeats of the same (sender, incident, scope) claim decay
    geometrically even when message ids differ."""
    coop = CooperativeEvidence(enforce_budget=False, enforce_diversity=False)
    first = coop.contribute("j", _sig(1, key="same"), 1.0, 1.0, now=0.0)
    second = coop.contribute("j", _sig(2, key="same"), 1.0, 1.0, now=0.0)
    third = coop.contribute("j", _sig(3, key="same"), 1.0, 1.0, now=0.0)
    assert second == pytest.approx(first * 0.5)
    assert third == pytest.approx(first * 0.25)


def test_staleness_decay():
    coop = CooperativeEvidence(mu=1.0, enforce_budget=False)
    coop.contribute("j", _sig(1, t=0.0), 1.0, 1.0, now=0.0)
    assert coop.cooperative("j", 1.0) < coop.cooperative("j", 0.0)


def test_rolling_window_expiry():
    coop = CooperativeEvidence(window=6.0, enforce_budget=False)
    coop.contribute("j", _sig(1, t=0.0), 1.0, 1.0, now=0.0)
    assert coop.cooperative("j", 7.0) == 0.0


def test_combined_always_bounded():
    coop = CooperativeEvidence(enforce_budget=False, enforce_gate=False,
                               enforce_diversity=False)
    for i in range(200):
        coop.contribute("j", _sig(i, t=0.0), 1.0, 1.0, now=0.0)
    assert coop.combined("j", 1.0, 0.0) == 1.0


def test_sender_concentration_metric():
    coop = CooperativeEvidence()
    coop.contribute("j", _sig(1, sender="sensor:A"), 1.0, 1.0, now=0.0)
    coop.contribute("j", _sig(2, sender="sensor:A"), 1.0, 1.0, now=0.0)
    coop.contribute("j", _sig(3, sender="sensor:B"), 1.0, 1.0, now=0.0)
    assert 0.5 < coop.sender_concentration() < 1.0


def test_proportional_gate_bounds_amplification():
    """Peer evidence may amplify weak local evidence by at most
    coop_local_multiple; it can never substitute for it."""
    coop = CooperativeEvidence(theta_g=0.2, coop_local_multiple=2.0)
    for s in range(5):
        for i in range(20):
            coop.contribute("j", _sig(i, sender=f"sensor:F{s}", t=0.0),
                            trust=1.0, relevance=1.0, now=0.0)
    local = 0.1
    assert coop.combined("j", local, 0.0) <= local + 2.0 * local + 1e-9
