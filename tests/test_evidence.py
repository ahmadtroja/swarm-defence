"""Equation 1 properties: boundedness, elapsed-time decay, irregular
timing (design paper Section 6.2; audit: "use elapsed-time decay for
irregular event timing")."""

import math
import random

import pytest

from swarmdefence.evidence import LocalEvidence


def test_bounded_under_random_streams():
    rng = random.Random(0)
    le = LocalEvidence(kappa_s=0.5)
    t = 0.0
    for _ in range(2000):
        t += rng.uniform(0.001, 3.0)
        v = le.update("n", rng.random(), t)
        assert 0.0 <= v <= 1.0


def test_decays_without_reinforcement():
    le = LocalEvidence(kappa_s=0.5)
    le.update("n", 0.8, 0.0)
    values = [le.decayed("n", t) for t in (0.5, 1.0, 2.0, 5.0)]
    assert all(values[i] > values[i + 1] for i in range(len(values) - 1))
    assert values[-1] < 0.1


def test_elapsed_time_decay_is_composition_invariant():
    """Decay over [0, 2] equals decay over [0, 1] then [1, 2]: the update
    depends on elapsed time, not on how often a scheduler ticks (the audit
    rejected tick-dependent decay)."""
    a = LocalEvidence(kappa_s=0.7)
    b = LocalEvidence(kappa_s=0.7)
    a.update("n", 0.9, 0.0)
    b.update("n", 0.9, 0.0)
    b.update("n", 0.0, 1.0)  # intermediate observation with no evidence
    assert math.isclose(a.decayed("n", 2.0), b.decayed("n", 2.0), rel_tol=1e-9)


def test_new_evidence_reinforces():
    le = LocalEvidence(kappa_s=0.5)
    le.update("n", 0.4, 0.0)
    assert le.update("n", 0.7, 1.0) == pytest.approx(0.7)
    # weaker evidence never lowers the decayed value
    le2 = LocalEvidence(kappa_s=0.5)
    le2.update("n", 0.9, 0.0)
    assert le2.update("n", 0.1, 0.1) == pytest.approx(0.9 * math.exp(-0.05))


def test_rejects_out_of_range_detector_values():
    le = LocalEvidence(kappa_s=0.5)
    with pytest.raises(ValueError):
        le.update("n", 1.5, 0.0)
    with pytest.raises(ValueError):
        le.update("n", -0.1, 0.0)
