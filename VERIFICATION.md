# Verification matrix

This document maps each requirement of the design paper ("Cooperative
Distributed Detection with Time-Decayed Graph Evidence", v1.0) and each
finding of the audit ("Technical Audit and Verification") to the mechanism
that implements it and the test or experiment that verifies it.

Verification here means: the implemented mechanism provably (by property
test) or measurably (by controlled experiment) satisfies the stated
requirement *within this reference implementation and simulation*. It does
not certify real-world effectiveness.

## Formal model (design paper Section 6)

| Requirement | Mechanism | Verified by |
|---|---|---|
| Eq.1: local evidence bounded in [0,1], elapsed-time decay, irregular timing | `evidence.LocalEvidence` (peak-hold with exponential elapsed-time decay) | `test_evidence.py`: boundedness under random streams, monotone decay, composition invariance (decay depends on elapsed time, not tick count) |
| Eq.2: cooperative evidence from unique, fresh, authenticated, in-scope messages only | `evidence.SignalPlane` validation + `CooperativeEvidence.contribute` | `test_signal_plane.py` (all reject paths), `test_cooperative.py` |
| Eq.2: rolling influence budget B_j(W) | `CooperativeEvidence.cooperative` budget clamp over rolling window | `test_colluding_sources_bounded_by_aggregate_budget`, `test_rolling_window_expiry` |
| Eq.2: independent-source diversity | per-sender share cap (no sender exceeds 40% of B_j) | `test_flooding_single_source_bounded_by_share_cap_and_budget` |
| Eq.2: uniqueness u_i (semantic repeats decay) | geometric decay per (sender, incident, scope) claim | `test_uniqueness_decay_on_repeated_claims` |
| Eq.2: staleness decay exp(-mu * age) | read-time decay + signal-age discount on pull | `test_staleness_decay` |
| Eq.3: gate limits peer influence when local evidence is weak | g_j = min(1, L/theta_g) plus proportional cap (peer evidence adds at most 2x local) | `test_gate_blocks_peer_only_elevation`, `test_proportional_gate_bounds_amplification` |
| Eq.4: edge evidence bounded, elapsed-time decay, no tick dependence | `graph.TemporalGraph.add_event` (noisy-OR over decayed prior) | `test_edge_evidence_bounded_under_continuous_reinforcement`, `test_edge_evidence_decays_with_elapsed_time` |
| Eq.4: events scored against benign edge baseline; repetition alone gains nothing | `graph.BenignBaseline.novelty`; frozen training window | `test_benign_baseline_suppresses_repeated_routes`, `test_baseline_freeze_prevents_training_contamination` |
| S6.5: stable evidence = threshold held for duration tau, gap tolerance, first-alert reported separately | `attribution.StableEvidenceTracker` with sound two-component analytic hold | `test_attribution.py` stability tests incl. `test_first_alert_precedes_stable_time` |
| Eq.5: earliness, coverage, path quality, contradictions, missingness; weights pre-registered, positive weights sum to 1 | `attribution.OriginRanker` | `test_true_chain_origin_ranks_first`, `test_temporal_contradiction_penalized`, `test_missing_telemetry_penalized_and_reported`, `test_role_sensor_delay_adjusts_earliness`, `test_weights_must_sum_to_one` |
| S6.6: unknown/external origin candidate, top-k output, abstention on low score / small margin / absent coverage | unknown-origin candidate + abstention rules in `OriginRanker.rank` | `test_unknown_origin_wins_when_nothing_explains_the_evidence`, `test_abstains_without_stable_evidence`, `test_abstains_on_small_margin`, `test_topk_bounded` |

## Audit findings (security and integrity)

| Audit finding | Countermeasure | Verified by |
|---|---|---|
| "A cap on scores does not stop replay, flooding, collusion" — bounded state is not bounded influence | Influence is bounded by budget + share cap + uniqueness + gate; the [0,1] clamp is only numeric | `test_no_budget_ablation_allows_saturation` (shows the clamp alone is insufficient), RQ3 experiment (framed 0.000 full vs 1.000 no-safeguards) |
| Replay / duplicate delivery / reordering | unique-id dedupe, monotonic sequence, freshness windows, expiry, bounded future skew | `test_signal_plane.py`; replay experiment (800/800 replays rejected) |
| Message flooding | per-source rate limit at the plane, budget + share cap at the evidence layer | `test_per_source_rate_limit`; flood1 experiment (framed 0.000) |
| Colluding sensors | share cap forces diversity; gate prevents peer-only elevation; concentration metric reported | collude3 experiment (gate is the load-bearing control: framed 0.100 with vs 1.000 without) |
| Signed false telemetry is not trustworthy | producer-authenticity rule: an endpoint's local evidence updates only from its own sensor's (or corroborated) observations | `test_forged_uncorroborated_event_does_not_raise_peer_local_evidence` |
| Unbounded recursive re-emission | sensors emit only on a rising local-evidence crossing; peer-raised scores never trigger emission | `test_no_reemission_from_peer_only_elevation`, `test_rising_edge_emission_only` |
| Double-counting correlated evidence | one contribution per (signal, recipient); corroborating outbound records do not reinforce edges; provenance retained | `test_pulled_signal_contributes_at_most_once_per_recipient`, `test_edge_provenance_retained` |
| Decaying state cannot replace forensic evidence | append-only hash-chained `EventLedger`, verified after every experiment run; decayed views are derived | `test_ledger.py` (tamper detection), `ledger_verified_all: true` across all 700 runs |
| Tick-dependent decay (original paper defect) | all decay is elapsed-time based | `test_elapsed_time_decay_is_composition_invariant` and Eq.4 tests |
| "Earliest stable suspicion is not initial compromise" | multi-factor Eq.5 ranking with unknown-origin and abstention replaces forced top-1 | fast-grid experiment: hop error 0.25 (full) vs 1.10 (earliest-alert); silenced-origin grid |
| Missing telemetry modeled explicitly | `Entity.instrumented`, M term, unknown-origin support | `test_missing_telemetry_penalized_and_reported`; silenced-origin experiment |
| Evidence scores are not probabilities | no probability language anywhere; RQ5 explicitly not performed | `results/RESULTS.md` scope statement |
| Hybrid (not "decentralized") architecture stated honestly | replicated evidence service is a single logical service in this reference implementation | `README.md`, module docstrings |

## Evaluation protocol (design paper Section 9)

| Protocol requirement | Where honoured |
|---|---|
| Matched false-alert budgets; thresholds frozen before test | Phase 1 calibration on attack-free seeds (0.1 FA/host-day), thresholds recorded in `results/` |
| Identical telemetry and detector features across compared systems | one `SimulatedRun` per (scenario, seed) executed through every `SystemConfig` |
| Baselines B0–B5 and safety ablations | `pipeline.BASELINES`; `test_all_baseline_configs_run_end_to_end` |
| Low-rate movement defined by a grid, incl. dwell beyond the decay horizon | `Scenario` (dwell 0.5 h and 3 h; the slow grid shows the pre-registered degradation) |
| Compromised-agent, replay and missing-sensor conditions as first-class | phases 3–4 of the experiment |
| Effect sizes with 95% CIs, paired by campaign/seed | percentile bootstrap in `runner.bootstrap_ci`; `paired_deltas` in results |
| Deterministic reproduction (seeds, frozen params, scripts) | `test_deterministic_replay_same_seed`; seeds and parameters in `results/results.json` |
| Censored (undetected) campaigns reported, not dropped | detection rate reported alongside latency medians |

## Known gaps (not verified here)

- **RQ5 calibration**: Brier/ECE/reliability on held-out campaign families —
  not performed; outputs remain uncalibrated evidence scores.
- **Real data**: LANL, DARPA Transparent Computing, CALDERA cyber-range
  campaigns (Section 9.2) — the simulation is a stand-in with generative
  assumptions of its own.
- **Distributed-systems faults**: broker partitions, failover, split-brain
  reconciliation, clock-skew grids (RQ4 beyond throughput) — the reference
  implementation is single-process; replication semantics are out of scope.
- **Cryptography**: sender authentication and the ledger hash chain are
  simulated at the data-structure level; there is no real PKI, enrollment
  protocol, or key-revocation infrastructure.
- **Baseline poisoning and adaptive attackers**: the benign baseline's
  training window is frozen by construction; drift and poisoning tests remain
  open (Section 10).
- **Multi-origin campaigns**: the ranking supports multiple origins in
  principle, but the simulator only generates single-origin campaigns.
- **Residual elevation risk**: sustained collusion combined with coincident
  benign anomalies can still elevate a benign entity toward the stable
  threshold in the full system (collude3 framed rate 0.100); ranking demotes
  such candidates (scapegoat top-k 0.050) but the design's trust-adaptation
  term tau_ij is static in this implementation.
