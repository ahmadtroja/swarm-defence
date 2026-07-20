"""Local evidence smoothing and the controlled cooperative evidence protocol.

Implements the formal model of design paper Sections 6.2 and 6.3:

Equation 1 (local evidence smoothing, elapsed-time form)::

    L_n(t) = max( d_n(t), L_n(t_prev) * exp(-kappa_s * (t - t_prev)) )

A peak-hold smoother with elapsed-time exponential decay.  It is bounded
in [0, 1] whenever d is, handles irregular event timing (audit: "use
elapsed-time decay for irregular event timing"), and decays to zero
without reinforcement.

Equation 2 (budgeted peer evidence)::

    C_j(t) = min( B_j(W),  sum_{i in I_j(t)}  eta * tau_ij * r_ij * u_i * w_i
                                              * exp(-mu * (t - t_i)) )

where I_j(t) contains only unique, fresh, authenticated, in-scope
messages, each sender's aggregate share of B_j is additionally capped
(independent-source diversity), and the sum is evaluated over a rolling
window W.

Equation 3 (local-evidence gate)::

    g_j(t) = min(1, L_j(t) / theta_g)
    S_j(t) = min(1, L_j(t) + g_j(t) * C_j(t))

Peer evidence can therefore never, on its own, drive an entity with no
local evidence to a confirmed state (audit finding: "a cap on scores does
not stop replay, flooding, collusion" -- the budget, source cap, dedupe,
freshness and gate are the actual influence controls; the [0,1] clamp is
only a numeric bound).
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------
# Equation 1 -- local evidence
# --------------------------------------------------------------------------

@dataclass
class LocalEvidenceState:
    value: float = 0.0
    last_time: Optional[float] = None
    contributing_events: List[str] = field(default_factory=list)


class LocalEvidence:
    """Per-entity smoothed local evidence L_n(t) (Equation 1)."""

    def __init__(self, kappa_s: float) -> None:
        if kappa_s < 0:
            raise ValueError("kappa_s must be non-negative")
        self.kappa_s = kappa_s
        self._state: Dict[str, LocalEvidenceState] = {}

    def decayed(self, entity: str, t: float) -> float:
        st = self._state.get(entity)
        if st is None or st.last_time is None:
            return 0.0
        dt = t - st.last_time
        if dt < 0:
            # Out-of-order arrival: evaluate at the stored time (arrival time
            # is retained on the event itself; Section 6.1).
            dt = 0.0
        return st.value * math.exp(-self.kappa_s * dt)

    def update(self, entity: str, d: float, t: float, event_id: str = "") -> float:
        """Apply Equation 1 and return the new L_n(t)."""
        if not 0.0 <= d <= 1.0:
            raise ValueError(f"detector evidence d={d} outside [0,1]")
        st = self._state.setdefault(entity, LocalEvidenceState())
        new_val = max(d, self.decayed(entity, t))
        st.value = new_val
        st.last_time = t if st.last_time is None else max(st.last_time, t)
        if event_id and d > 0.05:
            st.contributing_events.append(event_id)
            del st.contributing_events[:-64]  # bounded provenance list
        return new_val

    def provenance(self, entity: str) -> Tuple[str, ...]:
        st = self._state.get(entity)
        return tuple(st.contributing_events) if st else ()

    def entities(self) -> Tuple[str, ...]:
        return tuple(self._state)


# --------------------------------------------------------------------------
# Secure signal plane (Section 5.2)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Signal:
    """A cooperative evidence message (Section 5.2).

    Contents are minimized: sender, scope entity, bounded evidence weight
    and correlation key -- no raw telemetry (privacy, Section 5.2).
    """

    signal_id: str
    sender: str                # enrolled sensor identity
    sequence: int              # monotonic per sender
    scope: str                 # affected entity id
    incident_key: str
    evidence_weight: float     # in [0,1]; sender's local evidence
    event_time: float
    expiry: float
    schema_version: str = "signal-v1"


@dataclass
class RejectStats:
    accepted: int = 0
    rejected_unenrolled: int = 0
    rejected_revoked: int = 0
    rejected_duplicate: int = 0
    rejected_sequence: int = 0
    rejected_stale: int = 0
    rejected_future: int = 0
    rejected_rate_limited: int = 0
    rejected_malformed: int = 0

    def as_dict(self) -> Dict[str, int]:
        return dict(self.__dict__)


class SignalPlane:
    """Validation layer for cooperative signals (Section 5.2, Section 10).

    Enforces: sender enrollment and revocation, monotonic sequence
    numbers, unique-id deduplication (replay), freshness windows,
    bounded clock skew for future timestamps, and per-source rate limits.
    Every control can be disabled individually for the safety ablations
    of Section 9.4.
    """

    def __init__(
        self,
        freshness_window: float = 2.0,       # hours a signal stays acceptable
        max_future_skew: float = 0.1,        # bounded clock-skew policy
        rate_limit_per_window: int = 30,     # max accepted msgs / sender / window
        rate_window: float = 1.0,            # hours
        enforce_dedupe: bool = True,
        enforce_freshness: bool = True,
        enforce_rate_limit: bool = True,
    ) -> None:
        self.freshness_window = freshness_window
        self.max_future_skew = max_future_skew
        self.rate_limit_per_window = rate_limit_per_window
        self.rate_window = rate_window
        self.enforce_dedupe = enforce_dedupe
        self.enforce_freshness = enforce_freshness
        self.enforce_rate_limit = enforce_rate_limit

        self._enrolled: set[str] = set()
        self._revoked: set[str] = set()
        self._seen_ids: set[str] = set()
        self._last_seq: Dict[str, int] = {}
        self._recent: Dict[str, Deque[float]] = {}
        self.stats = RejectStats()

    def enroll(self, sender: str) -> None:
        self._enrolled.add(sender)

    def revoke(self, sender: str) -> None:
        self._revoked.add(sender)

    def validate(self, sig: Signal, now: float) -> Tuple[bool, str]:
        """Return (accepted, reason). ``now`` is receipt time in hours."""
        if not 0.0 <= sig.evidence_weight <= 1.0:
            self.stats.rejected_malformed += 1
            return False, "malformed_weight"
        if sig.sender not in self._enrolled:
            self.stats.rejected_unenrolled += 1
            return False, "unenrolled_sender"
        if sig.sender in self._revoked:
            self.stats.rejected_revoked += 1
            return False, "revoked_sender"
        if self.enforce_dedupe and sig.signal_id in self._seen_ids:
            self.stats.rejected_duplicate += 1
            return False, "duplicate_id"
        if self.enforce_dedupe:
            last = self._last_seq.get(sig.sender)
            if last is not None and sig.sequence <= last:
                self.stats.rejected_sequence += 1
                return False, "sequence_regression"
        if sig.event_time - now > self.max_future_skew:
            self.stats.rejected_future += 1
            return False, "future_timestamp"
        if self.enforce_freshness and (
            now > sig.expiry or now - sig.event_time > self.freshness_window
        ):
            self.stats.rejected_stale += 1
            return False, "stale"
        if self.enforce_rate_limit:
            q = self._recent.setdefault(sig.sender, deque())
            while q and q[0] < now - self.rate_window:
                q.popleft()
            if len(q) >= self.rate_limit_per_window:
                self.stats.rejected_rate_limited += 1
                return False, "rate_limited"
            q.append(now)
        self._seen_ids.add(sig.signal_id)
        if self.enforce_dedupe:
            self._last_seq[sig.sender] = sig.sequence
        self.stats.accepted += 1
        return True, "accepted"


# --------------------------------------------------------------------------
# Equations 2 and 3 -- budgeted cooperative evidence with local gate
# --------------------------------------------------------------------------

@dataclass
class AcceptedContribution:
    sender: str
    time: float
    raw: float                 # eta * tau * r * u * w  (before staleness decay)


class CooperativeEvidence:
    """Per-recipient cooperative evidence C_j(t) and combined S_j(t).

    Implements Equations 2 and 3 with:

    * rolling influence budget B_j over window W,
    * per-sender share cap (independent-source diversity: no single
      sender may supply more than ``source_share_cap`` of B_j),
    * per-sender-per-scope uniqueness decay u_i (semantic repeats of the
      same claim lose weight even when message ids differ),
    * staleness decay exp(-mu * age),
    * the local-evidence gate g_j.

    Budget, gate and diversity can each be disabled for the safety
    ablations of Section 9.4.
    """

    def __init__(
        self,
        eta: float = 0.4,
        mu: float = 1.0,
        budget: float = 0.6,
        window: float = 6.0,
        theta_g: float = 0.2,
        source_share_cap: float = 0.4,
        coop_local_multiple: float = 2.0,
        enforce_budget: bool = True,
        enforce_gate: bool = True,
        enforce_diversity: bool = True,
    ) -> None:
        self.eta = eta
        self.mu = mu
        self.budget = budget
        self.window = window
        self.theta_g = theta_g
        self.source_share_cap = source_share_cap
        self.coop_local_multiple = coop_local_multiple
        self.enforce_budget = enforce_budget
        self.enforce_gate = enforce_gate
        self.enforce_diversity = enforce_diversity

        # recipient -> accepted contributions (rolling window)
        self._contrib: Dict[str, List[AcceptedContribution]] = {}
        # (recipient, sender, scope-claim) -> repeat count for uniqueness decay
        self._claims: Dict[Tuple[str, str, str], int] = {}
        # observability for cooperation-safety metrics (Section 9.5)
        self.total_influence_by_sender: Dict[str, float] = {}

    def contribute(
        self,
        recipient: str,
        sig: Signal,
        trust: float,
        relevance: float,
        now: float,
    ) -> float:
        """Register an accepted signal's contribution toward recipient j.

        Returns the raw (pre-staleness) contribution actually credited
        after uniqueness decay.  Budget and gate are applied at read time
        in :meth:`cooperative` / :meth:`combined`, because the budget is a
        property of the rolling window, not of a single message.
        """
        key = (recipient, sig.sender, sig.incident_key + "|" + sig.scope)
        repeats = self._claims.get(key, 0)
        self._claims[key] = repeats + 1
        u = 0.5 ** repeats  # uniqueness/freshness factor u_i
        raw = self.eta * _clip01(trust) * _clip01(relevance) * u * sig.evidence_weight
        lst = self._contrib.setdefault(recipient, [])
        lst.append(AcceptedContribution(sig.sender, now, raw))
        self.total_influence_by_sender[sig.sender] = (
            self.total_influence_by_sender.get(sig.sender, 0.0) + raw
        )
        return raw

    def cooperative(self, recipient: str, t: float) -> float:
        """Evaluate Equation 2: budgeted, diversity-capped, stale-decayed sum."""
        lst = self._contrib.get(recipient)
        if not lst:
            return 0.0
        # Drop contributions that fell out of the rolling window.
        lst[:] = [c for c in lst if t - c.time <= self.window]
        per_sender: Dict[str, float] = {}
        for c in lst:
            if c.time > t:
                continue
            decayed = c.raw * math.exp(-self.mu * (t - c.time))
            per_sender[c.sender] = per_sender.get(c.sender, 0.0) + decayed
        if self.enforce_diversity:
            cap = self.source_share_cap * self.budget
            per_sender = {s: min(v, cap) for s, v in per_sender.items()}
        total = sum(per_sender.values())
        if self.enforce_budget:
            total = min(total, self.budget)
        return total

    def gate(self, local: float) -> float:
        """Equation 3 gate g_j."""
        if not self.enforce_gate:
            return 1.0
        return min(1.0, local / self.theta_g) if self.theta_g > 0 else 1.0

    def combined(self, recipient: str, local: float, t: float) -> float:
        """Equation 3: S_j = min(1, L_j + g_j * C_j), where the gate both
        scales peer influence below theta_g and bounds it proportionally
        to local evidence (peer evidence may at most add
        ``coop_local_multiple`` times the local evidence, so it can
        amplify but never substitute for local observation)."""
        c = self.cooperative(recipient, t)
        if self.enforce_gate:
            c = min(self.gate(local) * c, self.coop_local_multiple * local)
        return min(1.0, local + c)

    def sender_concentration(self) -> float:
        """Max share of total accepted influence from a single sender
        (cooperation-safety metric, Section 9.5)."""
        total = sum(self.total_influence_by_sender.values())
        if total <= 0:
            return 0.0
        return max(self.total_influence_by_sender.values()) / total


def _clip01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x
