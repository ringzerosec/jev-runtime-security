# L8 — Evaluation

> **Laya track, chapter 8 of 10.** Goal: know how to tell whether a checkpoint
> works, whether its confidence can be trusted, and whether it is reading the
> situation or just the option priors — using Laya's own harness (`evals.py`)
> and ours (`models/laya_eval.py`). And know which test actually answers the
> question doubters ask: "will it hold on attacks it has never seen?"

## L8.1 Laya's harness: `evals.py`

The library ships a reproducible evaluation layer, torch-free on the metric
side:

- **`Dataset` / `Example`** (103, 70) — a labelled set: states, the questions
  (one definition reused across examples), and expected answers.
- **Evaluators** (`Evaluator`, 246): `ChoiceAccuracy` (255), `NoulAccuracy`
  (264), `ScoreMAE` (273 — mean absolute error of the *expected level* against
  the gold level), `ScoreWithin` (282 — fraction within a tolerance),
  `MeanConfidence` (295). `default_evaluators()` (305) assembles them per type.
- **Calibration metrics**: `ece` (339), `brier` (353), and two
  *selective-prediction* metrics that matter for a gated system — `aurc` (372,
  area under the risk–coverage curve: as you raise the abstention threshold,
  how fast does error fall?) and `selective_accuracy` (385: accuracy on the
  answers that *clear* a threshold). `is_confidence_metric` (401) marks which
  ones depend on `answer_confidence`.
- **Reproducibility by construction**: `questions_fingerprint` (160) hashes the
  question definitions, `file_fingerprint` (203) the data file, `_run_identity`
  (235) the library version + both — so a reported number names exactly what
  produced it. This is the same ethic as `models/bench/README.md` ("every number
  is produced by a script; no hand numbers").

`evals_cli.py` runs it from the shell; `_eval_policy.py` and
`evals_shortlist.py` extend it to policy-gated and shortlisted decisions.

## L8.2 Our harness: `models/laya_eval.py`

For the brain we need two things Laya's harness doesn't do out of the box:
compare *our* gold ranks across checkpoints, and run the **shuffled-context
control**. `laya_eval.py` loads a checkpoint dir, runs `rows.jsonl`
(state / questions / gold — the same rows the feeder dumps), and reports:

- **accuracy** — predicted rank (argmax of `probabilities`) == gold rank;
- **mean P(gold)** — the calibrated mass the model put on the right option
  (a smoother signal than accuracy on a small set);
- **shuffled-context accuracy** — the same questions scored against a
  *different* row's state (`rows[(i+1) % n]`). A model that does as well here
  is reading **option priors** ("exfiltration questions usually answer
  severe"), not the situation, and per `models/README.md` **does not ship**;
- **delta real − shuffled** — the number to watch.

One gotcha it already encodes: Laya nests results under `res["answers"][qid]`;
read that path, not `res[qid]`.

## L8.3 Reading our first numbers correctly

| | accuracy | mean P(gold) | shuffled acc | delta |
|---|---|---|---|---|
| base `typed-decisions` | 4/9 | 0.42 | 0.22 | +0.22 |
| v1 (fine-tuned, 9 rows) | 9/9 | 0.85 | 0.44 | +0.56 |

What this does and doesn't say:

- It **does** say the fine-tune learned, and that v1 reads the situation
  (accuracy collapses when the state is swapped).
- It **does not** say v1 generalizes: the 9 rows *are* the training rows. 9/9
  is training-set fit. Shuffled accuracy of 0.44 (above the 1/3 chance for
  3-option questions) also means some option-prior learning happened — the
  seed rows skew severe. Both are expected at this size and are why the roster
  labels it a smoke test.

## L8.4 The test that answers the real question: held-out attack *families*

Held-out **rows** measure interpolation: more examples of patterns you've seen.
The objection that matters — "millions of states, OOD inputs" — is about
patterns you haven't. So the evaluation that answers it holds out whole
**families**:

- Partition the circumvention scenarios by *mechanism* (staged-for-subagent,
  deferred job, side-channel device, laundered artifact, delegation — the five
  seed classes in `bench/scenarios.jsonl`).
- Train on N−1 families; test on the unseen one. Rotate.
- Report per-family accuracy, ECE, and — because the floor exists — the
  **tighten direction**: on an unseen family, does the model at least raise
  severity or abstain (contain/review), or does it confidently call it benign?
  Confidently-benign-on-novel is the only failure that costs anything; the
  kernel holds the direct attempt regardless.

Add the bench's other gates: ECE on held-out rows (not the shipped number), the
shuffled-context control, an FP floor on benign sessions (alert fatigue), and the
promotion rule — a new version must beat the current one on all of these before
it is served.

## L8.5 Reading a reliability diagram

The model repo ships `eval/reliability_eval_in.png` and
`eval/reliability_eval_zs.png` (in-distribution vs zero-shot). Confidence on the
x-axis, observed accuracy on the y-axis, one point per bin: points on the
diagonal are calibrated; above it under-confident; below it over-confident.
ECE is the mass-weighted distance from the diagonal. When you fit temperatures on
our rows (L5), draw this for *our* data before trusting any threshold.

## Try it

```sh
cd /Users/jarvis/rgs/rgs-linux-oss/models
~/laya-venv/bin/python laya_eval.py --model ~/laya_base/typed-decisions --label base
~/laya-venv/bin/python laya_eval.py --model ~/laya_v1_out --label v1 --show-raw
```

Then compute `ece` and `aurc` with Laya's own functions on the per-row
`answer_confidence` / correctness lists — the exercise below.

## Where this lives

- `laya/evals.py` — `Dataset` (103), evaluators (246–305), `ece` (339),
  `brier` (353), `aurc` (372), `selective_accuracy` (385), fingerprints
  (160, 203, 235). `laya/evals_cli.py`.
- `models/laya_eval.py`; `models/bench/README.md` (the two axes and the honesty
  rules); `models/bench/scenarios.jsonl` (the families).
- Model repo: `eval/results.md`, `eval/reliability_*.png`.

## Exercise

1. Extend `laya_eval.py` to also emit ECE and AURC using `laya.evals.ece` /
   `aurc` over `answer_confidence`. Run it on v1. What does AURC tell you that
   accuracy can't?
2. Design the held-out-family protocol for the five seed classes: which family
   would you expect v1 to fail on first, and what is the *acceptable* failure
   (tighten/abstain) versus the unacceptable one?
3. v1's shuffled-context accuracy is 0.44. Say precisely what that number
   measures and whether it would rise or fall if the training rows were
   balanced across severity levels.

---

Next: **[L9 — Shipping: ONNX, int8, serving](L9-shipping-onnx-int8-serving.md)**.
