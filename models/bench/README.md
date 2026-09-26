# Benchmarks — how Ring Zero performs on blocking different attacks

Two axes, measured and reported **separately**. Conflating them ("the model
blocks 94% of attacks") is dishonest, because the model never blocks — the kernel
does, deterministically, and the model is advisory/raise-only. So:

## Axis 1 — Enforcement outcome (the product)

For each attack scenario, run it against the running product and record one of:

- **blocked** — the syscall was refused (`-EACCES`) or the effect was prevented.
- **recorded** — observed and logged, but not refused (v1 policy for exec/network).
- **missed** — neither refused nor observed.

For kernel-mapped categories this is **deterministic**: given the rule is loaded
and the agent is detected, it blocks every time. So the real signal on this axis
is **coverage and evasions** — does an attack variant (renamed binary, hardlink,
deep path, out-of-tree helper) slip detection? Every scenario ships with its
evasion variants, and a miss is reported, not hidden.

## Axis 2 — Detection quality (the model)

For the advisory model layer, on a labelled test set, per category:

- **precision / recall / F1** against the ground-truth label.
- **ECE** (expected calibration error) — not just accuracy.
- **shuffled-context control** — score the same options against *shuffled*
  context. A model that does as well is reading option priors, not the situation,
  and **does not ship** (the `models/README.md` bar).
- **delta over the deterministic floor** — the only number that justifies the
  model existing: attacks the patterns miss that the model catches, and
  false-positives the model adds.

## Honesty rules (enforced by the harness, not by us)

1. **Reproducible.** Every number is produced by a script here; no hand numbers.
2. **Synthetic is labelled synthetic.** The bootstrap test set is programmatic
   (we have no real traces yet). Real-trace results are reported separately as the
   review queue fills. A synthetic number is never presented as field efficacy.
3. **Misses are columns, not omissions.** The evasion and recorded-not-refused
   results appear in the same table as the wins.
4. **Per-category, never one blended score.** A single "attack block rate" hides
   which attacks and how.

## The scenario suite

`scenarios.jsonl` — one row per attack, covering all 13 `EnforcementCategories`,
each with: category, an attack description, how to execute it, the expected
enforcement path, the block/record/miss expectation, and evasion variants.

`run_attacks.sh` executes the enforceable scenarios against the product on a VM
and writes the Axis-1 results. `eval_detection.py` runs Axis-2 against a labelled
set and a chosen provider.

## Reading the results

`RESULTS.md` is generated, never edited by hand. Each row is one attack; the
columns are the two axes above. Categories whose enforcement path is `review`
(trajectory/judgment) carry a detection number and an **honest** "not blocked,
routed to review" on Axis 1 — because that is what actually happens, and claiming
otherwise would be the exact overreach this file exists to prevent.
