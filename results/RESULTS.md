# Experiment results: cooperative distributed detection

**Scope and claim boundary.** These are measurements of the reference
implementation on a *synthetic* enterprise simulation (Section 9 protocol,
simulation instantiation). They quantify behaviour of this implementation
under the stated generative assumptions. They are **not** evidence about
real enterprise traffic, CALDERA/LANL/DARPA datasets, or production
readiness, and evidence scores are **not** calibrated probabilities (RQ5
calibration was not performed).

- Date: 2026-07-20 12:56:06 UTC
- Matched false-alert budget: 0.1 episodes/host-day
- Seeds: calibration [1, 2, 3, 4, 5], main 101–130, adversarial 201–220, silenced 301–320
- Quick mode: False
- Total wall time: 105.9 s

## Frozen thresholds (calibrated, then fixed before all test runs)

| system | theta_alert = theta_s |
|---|---|
| B0_local_only | 0.525 |
| B1_central_streaming | 0.700 |
| B2_static_graph | 0.525 |
| B3_temporal_graph_only | 0.525 |
| B4_cooperation_only | 0.575 |
| B5_full | 0.575 |
| A_no_budget | 0.575 |
| A_no_gate | 0.575 |
| A_no_dedupe | 0.575 |
| A_no_all_safeguards | 0.575 |

## Main grid — scenario `fast` (RQ1, RQ2)

| system | detect rate | median latency (h) | FA/host-day | abstain rate | top-1 | top-3 | MRR | unk top-1 | hop err |
|---|---|---|---|---|---|---|---|---|---|
| B0_local_only | 1.000 | 0.000 | 0.093 | 0.000 | 0.400 | 0.900 | 0.611 | 0.000 | 1.100 |
| B1_central_streaming | 1.000 | 0.000 | 0.100 | 0.000 | 0.400 | 0.933 | 0.622 | 0.000 | 1.100 |
| B2_static_graph | 1.000 | 0.000 | 0.093 | 0.133 | 0.615 | 0.885 | 0.737 | 0.000 | 0.538 |
| B3_temporal_graph_only | 1.000 | 0.000 | 0.093 | 0.267 | 0.455 | 0.773 | 0.576 | 0.318 | 0.467 |
| B4_cooperation_only | 1.000 | 0.032 | 0.083 | 0.000 | 0.333 | 0.867 | 0.572 | 0.000 | 1.167 |
| B5_full | 1.000 | 0.032 | 0.083 | 0.233 | 0.565 | 0.739 | 0.630 | 0.304 | 0.250 |

Top-1/top-3/MRR are computed over non-abstained runs only; the
abstention rate column must be read alongside them.

## Main grid — scenario `slow` (RQ1, RQ2)

| system | detect rate | median latency (h) | FA/host-day | abstain rate | top-1 | top-3 | MRR | unk top-1 | hop err |
|---|---|---|---|---|---|---|---|---|---|
| B0_local_only | 1.000 | 0.000 | 0.093 | 0.000 | 0.333 | 0.400 | 0.367 | 0.000 | 1.000 |
| B1_central_streaming | 1.000 | 0.000 | 0.100 | 0.000 | 0.333 | 0.400 | 0.367 | 0.000 | 0.967 |
| B2_static_graph | 1.000 | 0.000 | 0.093 | 0.033 | 0.345 | 0.345 | 0.345 | 0.138 | 0.880 |
| B3_temporal_graph_only | 1.000 | 0.000 | 0.093 | 0.067 | 0.286 | 0.393 | 0.333 | 0.357 | 0.778 |
| B4_cooperation_only | 1.000 | 0.032 | 0.083 | 0.067 | 0.286 | 0.393 | 0.339 | 0.000 | 1.036 |
| B5_full | 1.000 | 0.032 | 0.083 | 0.033 | 0.276 | 0.345 | 0.310 | 0.345 | 0.737 |

Top-1/top-3/MRR are computed over non-abstained runs only; the
abstention rate column must be read alongside them.

## Adversarial grid — compromised sensors (RQ3)

### Scenario `flood1`

| system | benign elev./host-h | scapegoat framed | scapegoat in top-k | saturation | sender concentration | top-1 (true origin) |
|---|---|---|---|---|---|---|
| B5_full | 0.006 | 0.000 | 0.000 | 0.007 | 0.952 | 0.571 |
| A_no_budget | 0.006 | 0.100 | 0.050 | 0.018 | 0.952 | 0.467 |
| A_no_gate | 0.006 | 0.000 | 0.000 | 0.007 | 0.952 | 0.571 |
| A_no_dedupe | 0.006 | 0.000 | 0.000 | 0.007 | 0.956 | 0.571 |
| A_no_all_safeguards | 0.008 | 1.000 | 0.750 | 0.114 | 0.956 | 0.056 |

Signal-plane rejections (totals across runs): `B5_full`: dup=0, stale=0, rate=2391; `A_no_budget`: dup=0, stale=0, rate=2391; `A_no_gate`: dup=0, stale=0, rate=2391; `A_no_dedupe`: dup=0, stale=0, rate=2413; `A_no_all_safeguards`: dup=0, stale=0, rate=2413

### Scenario `collude3`

| system | benign elev./host-h | scapegoat framed | scapegoat in top-k | saturation | sender concentration | top-1 (true origin) |
|---|---|---|---|---|---|---|
| B5_full | 0.007 | 0.100 | 0.050 | 0.031 | 0.398 | 0.353 |
| A_no_budget | 0.008 | 0.100 | 0.050 | 0.069 | 0.398 | 0.353 |
| A_no_gate | 0.008 | 1.000 | 0.900 | 0.031 | 0.398 | 0.000 |
| A_no_dedupe | 0.007 | 0.100 | 0.050 | 0.029 | 0.398 | 0.375 |
| A_no_all_safeguards | 0.011 | 1.000 | 0.900 | 0.246 | 0.398 | 0.000 |

Signal-plane rejections (totals across runs): `B5_full`: dup=0, stale=0, rate=7089; `A_no_budget`: dup=0, stale=0, rate=7089; `A_no_gate`: dup=0, stale=0, rate=7089; `A_no_dedupe`: dup=0, stale=0, rate=7152; `A_no_all_safeguards`: dup=0, stale=0, rate=7152

### Scenario `replay`

| system | benign elev./host-h | scapegoat framed | scapegoat in top-k | saturation | sender concentration | top-1 (true origin) |
|---|---|---|---|---|---|---|
| B5_full | 0.005 | 0.000 | 0.000 | 0.005 | 0.152 | 0.571 |
| A_no_budget | 0.005 | 0.000 | 0.000 | 0.005 | 0.152 | 0.571 |
| A_no_gate | 0.005 | 0.000 | 0.000 | 0.005 | 0.152 | 0.571 |
| A_no_dedupe | 0.005 | 0.000 | 0.000 | 0.005 | 0.153 | 0.571 |
| A_no_all_safeguards | 0.005 | 0.000 | 0.000 | 0.005 | 0.153 | 0.571 |

Signal-plane rejections (totals across runs): `B5_full`: dup=800, stale=0, rate=0; `A_no_budget`: dup=800, stale=0, rate=0; `A_no_gate`: dup=800, stale=0, rate=0; `A_no_dedupe`: dup=0, stale=0, rate=0; `A_no_all_safeguards`: dup=0, stale=0, rate=0

## Silenced-origin grid — missing telemetry

The true origin has no sensor; the design's stated target is the
earliest *observable* origin (Section 2), i.e. the first instrumented
compromised entity. `top-1 (true)` is expected to be low here by
construction; `observable top-1` and hop error measure the intended
behaviour.

| system | abstain rate | top-1 (true) | observable top-1 | hop err vs true |
|---|---|---|---|---|
| B5_full | 0.200 | 0.000 | 0.375 | 1.462 |
| B3_temporal_graph_only | 0.250 | 0.000 | 0.400 | 1.300 |

## Paired differences (95% percentile-bootstrap CIs)

| comparison (paired by seed) | n | mean diff | 95% CI |
|---|---|---|---|
| latency_h: B5_full - B0_local_only (fast, detected pairs) | 30 | 0.186 | [-0.023, 0.455] |
| latency_h: B5_full - B1_central_streaming (fast, detected pairs) | 30 | 0.184 | [-0.030, 0.457] |
| detection_rate: B5_full - B0_local_only (fast) | 30 | 0.000 | [0.000, 0.000] |
| top1: B5_full - B4_cooperation_only (fast) | 30 | 0.100 | [-0.067, 0.267] |
| top1: B5_full - B2_static_graph (fast) | 30 | -0.100 | [-0.300, 0.100] |
| top1: B5_full - B0_local_only (fast) | 30 | 0.033 | [-0.067, 0.133] |
| scapegoat_framed: A_no_budget - B5_full (flood1) | 20 | 0.100 | [0.000, 0.250] |

A CI excluding 0 indicates a difference unlikely to be a seed artifact
*within this simulation*; it says nothing about other environments.

## Systems overhead (RQ4, coarse)

| scenario | system | median events/s (single thread) | ledger verified |
|---|---|---|---|
| fast | B0_local_only | 32539.872 | yes |
| fast | B1_central_streaming | 29176.562 | yes |
| fast | B2_static_graph | 32976.315 | yes |
| fast | B3_temporal_graph_only | 32095.271 | yes |
| fast | B4_cooperation_only | 24776.591 | yes |
| fast | B5_full | 25081.893 | yes |
| slow | B0_local_only | 31979.204 | yes |
| slow | B1_central_streaming | 29615.057 | yes |
| slow | B2_static_graph | 32965.013 | yes |
| slow | B3_temporal_graph_only | 32516.151 | yes |
| slow | B4_cooperation_only | 25250.828 | yes |
| slow | B5_full | 24948.177 | yes |

## Not evaluated here

- RQ5 calibration (Brier/ECE/reliability) — requires held-out campaign
  families; outputs remain uncalibrated evidence scores.
- Real datasets (LANL, DARPA TC) and cyber-range (CALDERA) campaigns.
- Broker partitions/failover, clock skew grids, baseline poisoning,
  multi-origin campaigns (design Sections 9.1 RQ4 items beyond
  throughput, 10).
