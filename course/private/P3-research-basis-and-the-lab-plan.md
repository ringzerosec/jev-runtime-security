# P3 — Research basis and the lab plan

> **Private track.** Model IP; never in a public zip.
> Goal: know where the brain's design comes from, what we have actually proven
> on our own hardware, what the lab (NVIDIA Inception compute) is for and in what
> order, and — just as important — what we are deliberately *not* doing yet.

## P3.1 Lineage: SalesRLAgent → Laya → the brain

The reflex model's lineage is one author's line of work:

- **SalesRLAgent** (Nandakishor M, arXiv 2503.23303, Mar 2025) — the *why*. A
  sequential task framed as a **sequential decision problem**: states = the
  situation at each turn, actions = probability estimates, reward = prediction
  accuracy. A System-1 probability estimator, not a generator: a **state
  encoder** → **policy net** (probability) + **value net** (expected cumulative
  reward) + a **meta-learning confidence module**. 1.2M synthetic conversations,
  trained on CPU in ~6 h, 8-bit, incremental state updates, **85 ms CPU** vs
  3,450 ms for GPT-4. Ablations: sequential modelling −10.7 pts, embeddings −7.7,
  meta-learning −2.7.
- **Laya** (`convaiinnovations/laya`, Apache-2.0) — the *how*. The same shape made
  rigorous and local: a bidirectional **encoder** (ModernBERT-large) with typed
  decision heads, trained with **strictly proper scoring rules (RLCD)** so the
  probabilities are calibrated (reported ECE 0.081 vs 0.246 for a hosted
  alternative), fine-tuneable, exportable to ONNX.
- **The brain** — Laya as the on-device reflex tier, fine-tuned on our runtime
  states, plus the mechanisms in P1/P2 around it.

Read the paper as a **design pattern, not an evidence base**: single author, no
code, the RL algorithm and reward are never stated, and the headline numbers are
on the author's own synthetic benchmark. Take the architecture; verify everything
else ourselves.

## P3.2 What transfers from the paper

1. **State representation (its §III.C) — the most transferable idea.** Not
   independent turns but *evolving* state: recency-weighted history embeddings +
   per-turn features + engagement signals + technique/objection detection. Our
   mapping: recency-weighted **session-trace embedding** + per-event features
   (syscall class, path-sensitivity class, tool, process-tree depth, write→exec
   linkage, taint, policy-in-force) + **circumvention-pattern detection**. And its
   answer to "state that must persist": **incremental state updates, not full
   recomputation**.
2. **Meta-learning "knows when it doesn't know" (its §IV.C).** Confidence from
   similarity to training data, ensemble consistency, familiar structure, and
   **novelty detection**. The author's motivation — *confident but wrong
   predictions on unusual patterns* — is exactly the runtime-security failure
   mode. It maps 1:1 onto the enforce / contain / review tiers: novel ⇒ contain.
3. **Training recipe (its §IV.D).** Supervised init → RL → **curriculum**
   (simple → complex) → **adversarial counter-examples** → ensembles → balanced
   batches. Our miss-driven loop (`models/TRAINING-LOOP.md`) is this, with
   curriculum = direct attacks first, multi-step/evasion later.
4. **Synthetic data at scale worked** — templated scenarios × programmatic
   variation × multi-agent simulation, with no real data. That is the template
   for the data engine, with one upgrade: **our labels come from the kernel's
   outcome**, a far better oracle than a language model's self-labels.
5. **Deployment engineering** — quantize, cache, incremental state, CPU, <100 ms.
   We are already at 160 ms int8 on a laptop CPU.

**What does not transfer.** Its encoder is a hosted embedding API (the opposite
of our no-network rule — Laya fixed exactly this by owning the encoder). It has
no proper-scoring objective or ECE (Laya adds it). And its domain is cooperative;
ours is adversarial, so the novelty signal may only ever **tighten** — which the
registry clamp guarantees and the paper never needed.

## P3.3 What we have actually proven (measured, 2026-10-03)

On an Apple M5 (16 GB, MPS), from Laya's `typed-decisions` checkpoint, on the 9
oracle/seed rows in `models/misses/`:

- **Train:** 2 epochs, loss 1.02 → 0.37, in minutes, ~9 GB peak.
- **Test** (`models/laya_eval.py`): base → v1 went **4/9 → 9/9**, mean P(gold)
  **0.42 → 0.85**, **shuffled-context delta +0.22 → +0.56** (accuracy collapses
  when the situation is swapped — it reads the situation, not option priors).
- **Ship:** `laya_v1.int8.onnx`, **571 MB, self-contained**, **~160 ms per row
  on CPU** (onnxruntime), and the int8 decision matches fp32 (same argmax).

The honest label, recorded in `models/ROSTER.md`: **a smoke test on the training
rows, not a benchmark** — no held-out rows, no calibration rows (temperatures
defaulted). It proves the pipeline end to end (`laya_feed.py` → upstream MPS
trainer → `laya_eval.py` → `export_onnx.py --quantize`). Real numbers need
held-out rows. The loop is now limited by **rows, not tooling**.

## P3.4 The lab plan — what the Inception compute is for, in order

Compute makes training cheap. It does not produce data. So the lab's stages run
in this order, and the expensive runs come last.

| Stage | What | Why first/last | Rough budget *(estimates)* |
|---|---|---|---|
| 1 | **Data engine.** Templated attacker-vs-policy simulation in the sandbox at scale; hackathon counter-examples; pilot review-queue rows. Labels = kernel outcome / human. Curriculum tagged direct → multi-step. | Everything downstream trains on this. | CPU + sandbox VMs; little GPU |
| 2 | **Runtime-state encoder.** Laya encoder + the engineered event/session features (P3.2 §1), incremental session state. | The reflex tier; must stay on-device. | fine-tunes: tens of GPU-h per iteration |
| 3 | **Decision objective + session value head.** RLCD per-category severity, plus a value head ("where is this session heading") as the judgment signal. | Cheap once (1)–(2) exist. | tens of GPU-h |
| 4 | **Novelty / confidence module** → the enforce / contain / review tiers. | The OOD answer; gates authority. | small |
| 5 | **Judgment tier** — a generative model fine-tuned (LoRA) on session traces, customer-self-hosted. | Long context + explanations for the audit trail; off the endpoint. | ~4B LoRA: tens–low hundreds of GPU-h |
| 6 | **Scaled System 1** — continued-pretraining of a *larger encoder* on real runtime states. | Only when (1) has produced a measured gap Laya can't close. | hundreds–low thousands of GPU-h |

**Measure what the doubters actually fear.** Not held-out *rows* but **held-out
attack families**: train on N circumvention patterns, test on an unseen one. Plus
ECE, the shuffled-context control, the FP floor, and the benchmark gate before
any version is promoted.

## P3.5 Why we don't pretrain a System 1 from scratch now

The suggestion — "3–8B sparse MoE, ~2T tokens, build the System 1 properly" —
is architecturally sympathetic and wrong for us right now, for four reasons:

1. **The data doesn't exist.** 2T general tokens buy language competence, not
   runtime-security judgment; the security signal is the labelled runtime states
   we're still collecting. Pretraining first is training on guesses.
2. **The cost is off.** `6 × N × D` for 7B × 2T ≈ 8×10²² FLOPs — tens of
   thousands of GPU-hours, well into six figures without credits; an MoE roughly
   halves it and adds engineering.
3. **It violates the endpoint constraint.** A 3–8B model doesn't run on a laptop
   at 160 ms in 571 MB. It describes a server model, which we already have a
   slot for (stage 5).
4. **It assumes the model is the whole defense.** It isn't — the kernel is the
   floor (P2). The model only has to tighten on the hard tail.

Revisit at stage 6, on real data, as a **scaled encoder with a decision
objective** — not a next-token MoE.

## Where this lives

- `models/THE-BRAIN.md`, `models/ROSTER.md`, `models/TRAINING-LOOP.md`,
  `models/bench/README.md` — design, inventory, loop, measurement rules.
- `models/laya_feed.py`, `models/laya_eval.py` — the proven pipeline.
- arXiv 2503.23303; `convaiinnovations/laya` on Hugging Face.

## Exercise

1. Write the one-paragraph lab pitch you would give NVIDIA: what the compute is
   spent on, in what order, and what it is *not* spent on.
2. Define "held-out attack family" and explain why it, not held-out rows, is the
   test that answers "millions of states."
3. Re-derive the pretraining cost in P3.5 from `6 × N × D` and say which of the
   four reasons would survive if compute were free.

---

Back to the **[private track index](README.md)**.
