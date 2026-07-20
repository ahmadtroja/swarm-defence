"""Secure signal plane controls (design paper Sections 5.2 and 10):
replay, sequence regression, freshness, clock skew, enrollment,
revocation, and per-source rate limits."""

from swarmdefence.evidence import Signal, SignalPlane


def _sig(sid="s1", sender="sensor:A", seq=1, t=10.0, weight=0.8, expiry=None):
    return Signal(
        signal_id=sid,
        sender=sender,
        sequence=seq,
        scope="B",
        incident_key="inc",
        evidence_weight=weight,
        event_time=t,
        expiry=expiry if expiry is not None else t + 2.0,
    )


def _plane(**kw) -> SignalPlane:
    plane = SignalPlane(**kw)
    plane.enroll("sensor:A")
    return plane


def test_replay_duplicate_id_rejected():
    plane = _plane()
    assert plane.validate(_sig(), 10.0) == (True, "accepted")
    ok, reason = plane.validate(_sig(), 10.5)
    assert not ok and reason == "duplicate_id"
    assert plane.stats.rejected_duplicate == 1


def test_sequence_regression_rejected():
    plane = _plane()
    plane.validate(_sig(sid="s1", seq=5), 10.0)
    ok, reason = plane.validate(_sig(sid="s2", seq=4), 10.1)
    assert not ok and reason == "sequence_regression"


def test_stale_signal_rejected():
    plane = _plane(freshness_window=1.0)
    ok, reason = plane.validate(_sig(t=10.0), 11.5)
    assert not ok and reason == "stale"


def test_expired_signal_rejected():
    plane = _plane()
    ok, reason = plane.validate(_sig(t=10.0, expiry=10.5), 11.0)
    assert not ok and reason == "stale"


def test_future_timestamp_beyond_skew_rejected():
    plane = _plane(max_future_skew=0.1)
    ok, reason = plane.validate(_sig(t=11.0), 10.0)
    assert not ok and reason == "future_timestamp"


def test_unenrolled_and_revoked_rejected():
    plane = _plane()
    ok, reason = plane.validate(_sig(sender="sensor:evil"), 10.0)
    assert not ok and reason == "unenrolled_sender"
    plane.revoke("sensor:A")
    ok, reason = plane.validate(_sig(), 10.0)
    assert not ok and reason == "revoked_sender"


def test_per_source_rate_limit():
    plane = _plane(rate_limit_per_window=5, rate_window=1.0)
    accepted = 0
    for i in range(20):
        ok, _ = plane.validate(_sig(sid=f"s{i}", seq=i + 1, t=10.0 + i * 0.01), 10.0 + i * 0.01)
        accepted += ok
    assert accepted == 5
    assert plane.stats.rejected_rate_limited == 15


def test_malformed_weight_rejected():
    plane = _plane()
    ok, reason = plane.validate(_sig(weight=1.5), 10.0)
    assert not ok and reason == "malformed_weight"


def test_ablation_flags_disable_checks():
    plane = SignalPlane(enforce_dedupe=False, enforce_freshness=False)
    plane.enroll("sensor:A")
    assert plane.validate(_sig(), 10.0)[0]
    # duplicate id now passes (dedupe ablation of Section 9.4)
    assert plane.validate(_sig(), 10.5)[0]
    # stale/expired now passes (freshness ablation of Section 9.4)
    ok, _ = plane.validate(_sig(sid="s3", seq=3, t=0.0, expiry=0.5), 50.0)
    assert ok
