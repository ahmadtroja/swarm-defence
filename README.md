# swarm-defence

Reference implementation and controlled evaluation of the design paper
**"Cooperative Distributed Detection with Time-Decayed Graph Evidence"**
(revised concept manuscript v1.0, 16 July 2026), built to the requirements of
the accompanying **"Technical Audit and Verification"** report on the original
swarm-defense draft.

The audit's verdict on the original paper was that it claimed experiments that
did not exist. Its recommended route forward was:

> *Immediate: publish only a system-design and evaluation-protocol manuscript.
> Next: implement the event model, signal protocol, immutable ledger, typed
> graph, origin ranking, and replayable attribution output. Then: run
> baselines, ablations, adversarial fault tests, and scalability experiments
> with frozen parameters.*

This repository is that "next" and "then" step: a working implementation of the
revised design (Sections 5–8), a verification test suite for its stated safety
properties, and an executed instantiation of the Section 9 evaluation protocol
on a controlled synthetic enterprise simulation.

**Claim boundary.** Results in `results/` are measurements of *this
implementation on a synthetic simulation*. They are not evidence about real
enterprise traffic, production readiness, or the LANL/DARPA/CALDERA evaluations
the protocol ultimately calls for, and all scores remain uncalibrated evidence
scores, not probabilities (design paper Sections 6.6 and 11).

## Layout

```
swarmdefence/
  model.py        Typed temporal events; append-only hash-chained event ledger (S5.3, S6.1)
  evidence.py     Eq.1 local evidence smoothing; secure signal plane; Eq.2-3
                  budgeted cooperative evidence with source diversity and local gate (S5.2, S6.2-6.3)
  graph.py        Typed temporal multigraph; Eq.4 bounded elapsed-time edge evidence
                  scored against a benign baseline; time-respecting path search (S6.4)
  attribution.py  Stable-evidence tracking (S6.5); Eq.5 candidate-origin ranking with
                  top-k, unknown-origin hypothesis and abstention (S6.6)
  pipeline.py     The S8 processing procedure; SystemConfig toggles the S9.4
                  baselines (B0-B5) and safety ablations on identical telemetry
  simulation.py   Synthetic enterprise: benign background, low-rate campaigns with
                  ground truth (S9.3 grid), missing telemetry, compromised sensors
  runner.py       Run execution, matched false-alert-budget calibration, metrics,
                  paired bootstrap CIs (S9.5-9.6)
tests/            Verification suite: 63 property tests mapped to design/audit claims
experiments/
  run_experiment.py   The pre-registered experiment (calibrate -> freeze -> run)
results/
  RESULTS.md      Generated report with all tables
  results.json    Full raw + aggregate results (every run, every seed)
VERIFICATION.md   Claim-by-claim matrix: audit finding -> mechanism -> test/experiment
```

## Reproduce

```bash
pip install pytest         # only dev dependency; runtime is stdlib-only
python3 -m pytest tests/   # verification suite (63 tests)
python3 experiments/run_experiment.py           # full run (~2 min single thread)
python3 experiments/run_experiment.py --quick   # smoke run (not for reporting)
```

Everything is deterministic given the seeds recorded in `results/results.json`;
the experiment regenerates `results/RESULTS.md` and `results/results.json`.

## Headline findings (synthetic simulation only)

- **Safety controls work and are load-bearing (RQ3).** With all safeguards on,
  a flooding compromised sensor could not push its scapegoat into the stable
  suspicious set in any run (framed rate 0.000), while removing all safeguards
  yields framed rate 1.000 and drops true-origin top-1 from 0.571 to 0.056.
  The rolling influence budget is the critical control against a single
  flooder; the local-evidence gate is the critical control against three
  colluding sensors (framed 0.100 with gate vs 1.000 without). Replayed
  signals are fully rejected by dedupe/sequence checks (800/800), and even
  with dedupe ablated, uniqueness decay contains their influence.
- **Attribution: graph ranking trades recall for precision (RQ2, fast
  campaigns).** The full system reaches 0.565 top-1 with 0.23 abstention and
  the lowest hop-distance error (0.25); the earliest-alert baseline answers
  always but with 0.400 top-1 and hop error 1.10. The static-graph baseline is
  competitive on top-1 (0.615) in this benign-rate regime — consistent with
  the audit's warning that simpler baselines can be strong; the temporal
  system's advantage here is hop error, abstention on weak evidence, and
  adversarial robustness, not raw top-1.
- **The latency hypothesis (RQ1) is NOT supported at a matched false-alert
  budget.** Cooperation's benign elevations force a higher calibrated
  threshold (0.575 vs 0.525), which offsets its evidence boost: paired
  latency difference B5−B0 is +0.186 h with a 95% CI [−0.023, 0.455] that
  includes zero. Detection coverage is identical.
- **Slow campaigns degrade every system (pre-registered limitation).** With
  3 h mean dwell, top-1 falls to ~0.3 across the board: evidence decays and the
  campaign outlives the bounded incident window, exactly the failure mode
  Section 11 of the design paper anticipates. Slow-and-quiet movement remains
  an open problem for decay-based designs.
- **Missing telemetry behaves as specified.** With a silenced origin, the
  system cannot name the true origin (top-1 0.0, by construction) and recovers
  the earliest *observable* origin in ~0.4 of non-abstained runs with mean hop
  error ~1.3–1.5 from the true origin.
- **Forensics and overhead (RQ4, coarse).** The hash-chained ledger verified in
  all 700 runs; single-threaded throughput was ~25–33 k events/s per run.

See `results/RESULTS.md` for all tables, seeds, frozen thresholds and CIs, and
`VERIFICATION.md` for what is verified versus what remains open.
