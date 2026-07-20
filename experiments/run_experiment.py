#!/usr/bin/env python3
"""Section 9 evaluation protocol: baselines, ablations, adversarial runs.

Phases
------
1. Calibration: per-system alert thresholds are tuned on attack-free
   calibration seeds to a matched false-alert budget, then FROZEN before
   any test run (Section 9.6).
2. Main grid (RQ1, RQ2): fast and slow low-rate campaigns, identical
   telemetry per seed across systems B0-B5 (paired comparisons).
3. Adversarial grid (RQ3): flooding, colluding and replaying compromised
   sensors against the full system and its safety ablations, all at the
   full system's frozen threshold.
4. Missing-telemetry grid: silenced-origin campaigns (earliest
   OBSERVABLE origin is the design's stated target, Section 2).

Outputs: results/results.json (raw + aggregate) and results/RESULTS.md.

Usage: python3 experiments/run_experiment.py [--quick]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import asdict, replace
from typing import Dict, List, Optional, Sequence

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from swarmdefence.pipeline import BASELINES, SystemConfig
from swarmdefence.runner import (
    RunResult,
    bootstrap_ci,
    calibrate_threshold,
    execute_run,
    mean,
    median,
)
from swarmdefence.simulation import Scenario, generate_run

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")

# ---------------------------------------------------------------------------
# Pre-registered experiment definition (frozen before test runs, S9.6)
# ---------------------------------------------------------------------------

FA_BUDGET = 0.10          # false-alert episodes per host-day (matched budget)
CAL_SEEDS = [1, 2, 3, 4, 5]
MAIN_SEEDS = list(range(101, 131))       # 30 campaigns per scenario
ADV_SEEDS = list(range(201, 221))        # 20 campaigns per adversarial case
SILENCED_SEEDS = list(range(301, 321))   # 20 campaigns

MAIN_SYSTEMS = [
    "B0_local_only", "B1_central_streaming", "B2_static_graph",
    "B3_temporal_graph_only", "B4_cooperation_only", "B5_full",
]
ABLATION_SYSTEMS = [
    "B5_full", "A_no_budget", "A_no_gate", "A_no_dedupe", "A_no_all_safeguards",
]

SCENARIOS = {
    "fast": Scenario(name="fast", dwell_mean=0.5),
    "slow": Scenario(name="slow", dwell_mean=3.0),
}
ADV_SCENARIOS = {
    "flood1": Scenario(name="flood1", dwell_mean=0.5, n_flooders=1,
                       flood_interval=0.02),
    "collude3": Scenario(name="collude3", dwell_mean=0.5, n_flooders=3,
                         flood_interval=0.02),
    "replay": Scenario(name="replay", dwell_mean=0.5, replay=True),
}
SILENCED_SCENARIO = Scenario(name="silenced", dwell_mean=0.5, silenced_origin=True)


def run_result_to_dict(r: RunResult) -> dict:
    d = asdict(r)
    return d


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def aggregate(results: List[RunResult]) -> dict:
    n = len(results)
    detected = [r for r in results if r.detected]
    attributed = [r for r in results if r.attributed]
    top1 = [1.0 if r.truth_rank == 1 else 0.0 for r in attributed]
    top3 = [1.0 if (r.truth_rank or 99) <= 3 else 0.0 for r in attributed]
    mrr = [1.0 / r.truth_rank if r.truth_rank else 0.0 for r in attributed]
    obs_top1 = [1.0 if r.observable_rank == 1 else 0.0 for r in attributed]
    hop = [float(r.hop_error) for r in attributed if r.hop_error is not None]
    return {
        "n_runs": n,
        "detection_rate": round(len(detected) / n, 4) if n else None,
        "latency_median_h": _r(median([r.latency for r in detected])),
        "latency_mean_h": _r(mean([r.latency for r in detected])),
        "fa_per_host_day": _r(mean([r.fa_per_host_day() for r in results])),
        "abstention_rate": _r(mean([1.0 if r.abstained else 0.0 for r in results])),
        "attributed_runs": len(attributed),
        "top1_accuracy": _r(mean(top1)),
        "top3_accuracy": _r(mean(top3)),
        "mrr": _r(mean(mrr)),
        "unknown_top1_rate": _r(
            mean([1.0 if r.unknown_top1 else 0.0 for r in attributed])
        ),
        "observable_top1_accuracy": _r(mean(obs_top1)),
        "hop_error_mean": _r(mean(hop)),
        "n_suspicious_mean": _r(mean([float(r.n_suspicious) for r in results])),
        "benign_elevations_per_host_hour": _r(
            mean([r.benign_elevations_per_host_hour for r in results])
        ),
        "scapegoat_framed_rate": _r(
            mean([1.0 if r.scapegoat_framed else 0.0 for r in results])
        ),
        "scapegoat_in_topk_rate": _r(
            mean([1.0 if r.scapegoat_in_topk else 0.0 for r in results])
        ),
        "saturation_rate_mean": _r(mean([r.saturation_rate for r in results])),
        "sender_concentration_mean": _r(
            mean([r.sender_concentration for r in results])
        ),
        "events_per_second_median": _r(median([r.events_per_second for r in results])),
        "ledger_verified_all": all(r.ledger_ok for r in results),
        "plane_rejections": _sum_plane([r.plane_stats for r in results]),
    }


def _r(x: Optional[float], nd: int = 4) -> Optional[float]:
    return round(x, nd) if x is not None else None


def _sum_plane(stats: List[Dict[str, int]]) -> Dict[str, int]:
    out: Dict[str, int] = defaultdict(int)
    for st in stats:
        for k, v in st.items():
            out[k] += v
    return dict(out)


def paired_delta(
    a: List[RunResult], b: List[RunResult], value_fn, label: str
) -> dict:
    """Paired (by seed) mean difference a-b with a percentile-bootstrap
    95% CI (Section 9.6)."""
    by_seed_a = {r.seed: r for r in a}
    by_seed_b = {r.seed: r for r in b}
    diffs = []
    for seed in sorted(set(by_seed_a) & set(by_seed_b)):
        va, vb = value_fn(by_seed_a[seed]), value_fn(by_seed_b[seed])
        if va is not None and vb is not None:
            diffs.append(va - vb)
    m, lo, hi = bootstrap_ci(diffs)
    return {
        "comparison": label,
        "n_pairs": len(diffs),
        "mean_diff": _r(m),
        "ci95": [_r(lo), _r(hi)],
    }


# ---------------------------------------------------------------------------
# Main experiment
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true",
                    help="reduced seed counts (smoke run, not for reporting)")
    args = ap.parse_args()

    cal_seeds = CAL_SEEDS[:2] if args.quick else CAL_SEEDS
    main_seeds = MAIN_SEEDS[:5] if args.quick else MAIN_SEEDS
    adv_seeds = ADV_SEEDS[:4] if args.quick else ADV_SEEDS
    sil_seeds = SILENCED_SEEDS[:4] if args.quick else SILENCED_SEEDS

    t_start = time.time()
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # ---- Phase 1: calibration at matched false-alert budget ---------------
    print(f"[phase 1] calibrating alert thresholds "
          f"(budget {FA_BUDGET} FA/host-day, seeds {cal_seeds})")
    thresholds: Dict[str, float] = {}
    calibration_curves: Dict[str, Dict[str, float]] = {}
    for name in MAIN_SYSTEMS:
        theta, curve = calibrate_threshold(
            BASELINES[name], cal_seeds, FA_BUDGET
        )
        thresholds[name] = theta
        calibration_curves[name] = {str(k): round(v, 4) for k, v in curve.items()}
        print(f"  {name:26s} theta* = {theta}")
    # Ablations run at the full system's frozen operating point, so the
    # only difference is the missing safeguard.
    for name in ABLATION_SYSTEMS:
        thresholds.setdefault(name, thresholds["B5_full"])

    # theta_s (stable-evidence threshold feeding origin ranking) is pre-
    # registered as 0.85 * theta_alert for every system: attribution is
    # post-hoc triage whose false candidates are demoted by ranking, so it
    # may run below the operational alert threshold (Section 7 lists
    # theta_s as a separate parameter; sensitivity reported via ablations).
    STABLE_FRACTION = 0.85

    def frozen(name: str) -> SystemConfig:
        th = thresholds[name]
        return replace(BASELINES[name], theta_alert=th,
                       theta_s=round(STABLE_FRACTION * th, 4))

    all_results: List[RunResult] = []

    # ---- Phase 2: main grid (RQ1, RQ2) -------------------------------------
    print("[phase 2] main grid: scenarios", list(SCENARIOS), "x", MAIN_SYSTEMS)
    main_results: Dict[str, Dict[str, List[RunResult]]] = defaultdict(dict)
    for sc_name, sc in SCENARIOS.items():
        per_system: Dict[str, List[RunResult]] = {s: [] for s in MAIN_SYSTEMS}
        for seed in main_seeds:
            run = generate_run(sc, seed)          # identical telemetry ...
            for system in MAIN_SYSTEMS:           # ... for every system
                _, res = execute_run(run, frozen(system))
                per_system[system].append(res)
                all_results.append(res)
        main_results[sc_name] = per_system
        print(f"  scenario {sc_name}: done ({len(main_seeds)} seeds)")

    # ---- Phase 3: adversarial grid (RQ3) ------------------------------------
    print("[phase 3] adversarial grid:", list(ADV_SCENARIOS), "x", ABLATION_SYSTEMS)
    adv_results: Dict[str, Dict[str, List[RunResult]]] = defaultdict(dict)
    for sc_name, sc in ADV_SCENARIOS.items():
        per_system = {s: [] for s in ABLATION_SYSTEMS}
        for seed in adv_seeds:
            run = generate_run(sc, seed)
            for system in ABLATION_SYSTEMS:
                _, res = execute_run(run, frozen(system))
                per_system[system].append(res)
                all_results.append(res)
        adv_results[sc_name] = per_system
        print(f"  scenario {sc_name}: done ({len(adv_seeds)} seeds)")

    # ---- Phase 4: silenced origin (missing telemetry) -----------------------
    print("[phase 4] silenced-origin grid")
    sil_results: Dict[str, List[RunResult]] = {"B5_full": [], "B3_temporal_graph_only": []}
    for seed in sil_seeds:
        run = generate_run(SILENCED_SCENARIO, seed)
        for system in sil_results:
            _, res = execute_run(run, frozen(system))
            sil_results[system].append(res)
            all_results.append(res)

    # ---- Aggregate ----------------------------------------------------------
    aggregates = {
        "main": {
            sc: {s: aggregate(rs) for s, rs in per.items()}
            for sc, per in main_results.items()
        },
        "adversarial": {
            sc: {s: aggregate(rs) for s, rs in per.items()}
            for sc, per in adv_results.items()
        },
        "silenced": {s: aggregate(rs) for s, rs in sil_results.items()},
    }

    fast = main_results["fast"]
    deltas = [
        paired_delta(fast["B5_full"], fast["B0_local_only"],
                     lambda r: r.latency, "latency_h: B5_full - B0_local_only (fast, detected pairs)"),
        paired_delta(fast["B5_full"], fast["B1_central_streaming"],
                     lambda r: r.latency, "latency_h: B5_full - B1_central_streaming (fast, detected pairs)"),
        paired_delta(fast["B5_full"], fast["B0_local_only"],
                     lambda r: 1.0 if r.detected else 0.0, "detection_rate: B5_full - B0_local_only (fast)"),
        paired_delta(fast["B5_full"], fast["B4_cooperation_only"],
                     lambda r: 1.0 if (r.attributed and r.truth_rank == 1) else 0.0,
                     "top1: B5_full - B4_cooperation_only (fast)"),
        paired_delta(fast["B5_full"], fast["B2_static_graph"],
                     lambda r: 1.0 if (r.attributed and r.truth_rank == 1) else 0.0,
                     "top1: B5_full - B2_static_graph (fast)"),
        paired_delta(fast["B5_full"], fast["B0_local_only"],
                     lambda r: 1.0 if (r.attributed and r.truth_rank == 1) else 0.0,
                     "top1: B5_full - B0_local_only (fast)"),
    ]
    if "flood1" in adv_results:
        fl = adv_results["flood1"]
        deltas.append(paired_delta(
            fl["A_no_budget"], fl["B5_full"],
            lambda r: 1.0 if r.scapegoat_framed else 0.0,
            "scapegoat_framed: A_no_budget - B5_full (flood1)"))

    payload = {
        "meta": {
            "protocol": "Design paper v1.0 Section 9 (simulation instantiation)",
            "date_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            "fa_budget_per_host_day": FA_BUDGET,
            "calibration_seeds": cal_seeds,
            "main_seeds": [main_seeds[0], main_seeds[-1]],
            "adversarial_seeds": [adv_seeds[0], adv_seeds[-1]],
            "silenced_seeds": [sil_seeds[0], sil_seeds[-1]],
            "quick_mode": args.quick,
            "frozen_thresholds": thresholds,
            "wall_seconds": None,  # filled below
        },
        "calibration_curves": calibration_curves,
        "aggregates": aggregates,
        "paired_deltas": deltas,
        "runs": [run_result_to_dict(r) for r in all_results],
    }
    payload["meta"]["wall_seconds"] = round(time.time() - t_start, 1)

    out_json = os.path.join(RESULTS_DIR, "results.json")
    with open(out_json, "w") as f:
        json.dump(payload, f, indent=1)
    print(f"[done] wrote {out_json} "
          f"({len(all_results)} runs, {payload['meta']['wall_seconds']}s)")

    write_markdown(payload)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _fmt(v) -> str:
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)


def _table(headers: List[str], rows: List[List[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out)


def write_markdown(payload: dict) -> None:
    meta = payload["meta"]
    agg = payload["aggregates"]
    lines: List[str] = []
    add = lines.append
    add("# Experiment results: cooperative distributed detection")
    add("")
    add("**Scope and claim boundary.** These are measurements of the reference")
    add("implementation on a *synthetic* enterprise simulation (Section 9 protocol,")
    add("simulation instantiation). They quantify behaviour of this implementation")
    add("under the stated generative assumptions. They are **not** evidence about")
    add("real enterprise traffic, CALDERA/LANL/DARPA datasets, or production")
    add("readiness, and evidence scores are **not** calibrated probabilities (RQ5")
    add("calibration was not performed).")
    add("")
    add(f"- Date: {meta['date_utc']} UTC")
    add(f"- Matched false-alert budget: {meta['fa_budget_per_host_day']} episodes/host-day")
    add(f"- Seeds: calibration {meta['calibration_seeds']}, main "
        f"{meta['main_seeds'][0]}–{meta['main_seeds'][1]}, adversarial "
        f"{meta['adversarial_seeds'][0]}–{meta['adversarial_seeds'][1]}, "
        f"silenced {meta['silenced_seeds'][0]}–{meta['silenced_seeds'][1]}")
    add(f"- Quick mode: {meta['quick_mode']}")
    add(f"- Total wall time: {meta['wall_seconds']} s")
    add("")
    add("## Frozen thresholds (calibrated, then fixed before all test runs)")
    add("")
    add(_table(["system", "theta_alert = theta_s"],
               [[k, _fmt(v)] for k, v in meta["frozen_thresholds"].items()]))
    add("")

    det_cols = ["system", "detect rate", "median latency (h)", "FA/host-day",
                "abstain rate", "top-1", "top-3", "MRR", "unk top-1", "hop err"]

    for sc_name, per in agg["main"].items():
        add(f"## Main grid — scenario `{sc_name}` (RQ1, RQ2)")
        add("")
        rows = []
        for system, a in per.items():
            rows.append([
                system, _fmt(a["detection_rate"]), _fmt(a["latency_median_h"]),
                _fmt(a["fa_per_host_day"]), _fmt(a["abstention_rate"]),
                _fmt(a["top1_accuracy"]), _fmt(a["top3_accuracy"]),
                _fmt(a["mrr"]), _fmt(a["unknown_top1_rate"]),
                _fmt(a["hop_error_mean"]),
            ])
        add(_table(det_cols, rows))
        add("")
        add("Top-1/top-3/MRR are computed over non-abstained runs only; the")
        add("abstention rate column must be read alongside them.")
        add("")

    add("## Adversarial grid — compromised sensors (RQ3)")
    add("")
    for sc_name, per in agg["adversarial"].items():
        add(f"### Scenario `{sc_name}`")
        add("")
        rows = []
        for system, a in per.items():
            rows.append([
                system,
                _fmt(a["benign_elevations_per_host_hour"]),
                _fmt(a["scapegoat_framed_rate"]),
                _fmt(a["scapegoat_in_topk_rate"]),
                _fmt(a["saturation_rate_mean"]),
                _fmt(a["sender_concentration_mean"]),
                _fmt(a["top1_accuracy"]),
            ])
        add(_table(
            ["system", "benign elev./host-h", "scapegoat framed",
             "scapegoat in top-k", "saturation", "sender concentration",
             "top-1 (true origin)"], rows))
        add("")
        rej = {s: a["plane_rejections"] for s, a in per.items()}
        add("Signal-plane rejections (totals across runs): " +
            "; ".join(
                f"`{s}`: dup={v.get('rejected_duplicate', 0)}, "
                f"stale={v.get('rejected_stale', 0)}, "
                f"rate={v.get('rejected_rate_limited', 0)}"
                for s, v in rej.items()))
        add("")

    add("## Silenced-origin grid — missing telemetry")
    add("")
    add("The true origin has no sensor; the design's stated target is the")
    add("earliest *observable* origin (Section 2), i.e. the first instrumented")
    add("compromised entity. `top-1 (true)` is expected to be low here by")
    add("construction; `observable top-1` and hop error measure the intended")
    add("behaviour.")
    add("")
    rows = []
    for system, a in agg["silenced"].items():
        rows.append([
            system, _fmt(a["abstention_rate"]), _fmt(a["top1_accuracy"]),
            _fmt(a["observable_top1_accuracy"]), _fmt(a["hop_error_mean"]),
        ])
    add(_table(["system", "abstain rate", "top-1 (true)",
                "observable top-1", "hop err vs true"], rows))
    add("")

    add("## Paired differences (95% percentile-bootstrap CIs)")
    add("")
    rows = [
        [d["comparison"], str(d["n_pairs"]), _fmt(d["mean_diff"]),
         f"[{_fmt(d['ci95'][0])}, {_fmt(d['ci95'][1])}]"]
        for d in payload["paired_deltas"]
    ]
    add(_table(["comparison (paired by seed)", "n", "mean diff", "95% CI"], rows))
    add("")
    add("A CI excluding 0 indicates a difference unlikely to be a seed artifact")
    add("*within this simulation*; it says nothing about other environments.")
    add("")

    add("## Systems overhead (RQ4, coarse)")
    add("")
    ov_rows = []
    for sc_name, per in agg["main"].items():
        for system, a in per.items():
            ov_rows.append([sc_name, system, _fmt(a["events_per_second_median"]),
                            _fmt(a["ledger_verified_all"])])
    add(_table(["scenario", "system", "median events/s (single thread)",
                "ledger verified"], ov_rows))
    add("")
    add("## Not evaluated here")
    add("")
    add("- RQ5 calibration (Brier/ECE/reliability) — requires held-out campaign")
    add("  families; outputs remain uncalibrated evidence scores.")
    add("- Real datasets (LANL, DARPA TC) and cyber-range (CALDERA) campaigns.")
    add("- Broker partitions/failover, clock skew grids, baseline poisoning,")
    add("  multi-origin campaigns (design Sections 9.1 RQ4 items beyond")
    add("  throughput, 10).")
    add("")

    out_md = os.path.join(RESULTS_DIR, "RESULTS.md")
    with open(out_md, "w") as f:
        f.write("\n".join(lines))
    print(f"[done] wrote {out_md}")


if __name__ == "__main__":
    main()
