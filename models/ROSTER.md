# Model roster — the brain, by tier

> Read `THE-BRAIN.md` first. The RLCD intent models **are the product**; this
> file is the inventory. Every model is **local, fine-tuneable, open-weight** —
> no hosted API in the product. Models **decide** (off the hot path); the kernel
> **executes** (precompute-then-bit). Every model is **tighten-only** versus the
> deterministic floor — and tighten-only is not advisory-only.

They plug into the registry (`checks/src/registry.rs`) under one contract, so
swapping or adding a model is a config route, not a code change.

| Tier | Job | Base model | On-device? | ~Size (int8) |
|---|---|---|---|---|
| **Reflex** (per-event / per-artifact) — **all 13 categories** | typed decision per `EnforcementCategory`, including the core one: *does this written artifact express intent to circumvent policy?* | **Laya** — `convaiinnovations/laya`, **Apache-2.0**, ModernBERT-large encoder ~421M (mmBERT-base ~322M multilingual) — **LOCKED** | ✅ | **571 MB** (int8 ONNX, measured) |
| **DLP** | secret / PII spans | GLiNER-small family (open, Apache/MIT) — also an encoder | ✅ | ~0.2–0.4 GB *(est.)* |
| **Malware** (bounded) | agent-written / downloaded file → malicious? | small YARA-labelled encoder (`models/malware/`); may fold into Laya if a pilot shows it carries the decision | ✅ | ~0.1–0.2 GB *(est.)* |
| **Judgment** (per-session) | multi-step reasoning over a whole trace; operator-defined behaviours; a verdict **with an explanation** for the audit trail | ~4B **generative** fine-tune (Kev / Qwen class) — **adopt + fine-tune, never pretrain** | ❌ **customer-self-hosted** (on-prem box); **absent** in the sealed-sandbox SKU | ~8 GB (off the box) |

**On-device total ≈ 0.9–1.2 GB, int8** (Laya **measured** at 571 MB,
self-contained int8 ONNX; DLP/malware still estimates). The heavy reasoning
model never lives on the endpoint. **Shipping-path latency, measured
(2026-10-03, Apple M5 CPU, onnxruntime, int8):** ~160 ms per single 68-token
row (min 152 ms), and the int8 decision matches the fp32 model (same argmax;
P(gold) 0.56 vs 0.60).

## 13 categories, one reflex model

Laya is a typed-decision engine, not a per-task classifier: it reads the
situation once and scores whatever option set it is handed. A category is a
**question template + a small ordinal option set** (`schema.py`), not a model.
A new category costs a template and labelled rows, not a training run. This is
why the roster is four tiers and not thirteen models, and why the on-device
footprint is ~1 GB and not ~10.

## Sizing follows the task, not a rule of thumb

- *Per-artifact / per-event* (fits 512–1024 tokens): the encoder, on-device.
  Scaling Laya to 1B+ would break the one property that makes it shippable
  (runs on every laptop, no GPU) for marginal gain. Don't.
- *Per-session* (whole trace, needs long context + an explanation): generative,
  self-hosted. Not a bigger encoder — encoders don't reason over a session or
  explain themselves.

## Why Laya over Tev1 (the reflex base)

Same 5 cases, our own contract, zero-shot (no fine-tuning):

| | Tev1 (generative Qwen-0.8B) | **Laya (encoder)** |
|---|---|---|
| accuracy on our cases | 3/5 (under-graded exfil + injection) | **5/5** |
| calibrated probability | no | **yes** (0.52–0.88, sensible) |
| CPU latency (unoptimized PyTorch) | 1–5.5 s | 0.3–2.1 s |
| licence | unfinalized | **Apache-2.0** |

Laya's `score` type is an ordinal severity (0..N) — a clean fit for our
benign→severe option sets and tighten-only. **Honest caveats:** 5 hand-written
cases is a **smoke test, not a benchmark** (`bench/` is the real measure, and
its bootstrap set is synthetic and labelled so). Laya's 33 ms figure is
**GPU/ONNX**; on CPU, unoptimized PyTorch, it is hundreds of ms to ~2 s. The
shipping path is the ONNX-int8 export, **measured at ~160 ms/row on an M5 CPU**
(see above). Laya's
base checkpoint is weak on domain decisions (their own typed-decisions set:
0.362 base → 0.766 fine-tuned); the categories are earned through the training
loop, not zero-shot.

## Serving

`laya.predict(state, questions)` in-process, exported to **ONNX** for the
sealed sandbox (no server, no network). The registry's `DecisionEndpoint` wraps
it; the tighten-only clamp is enforced centrally in the registry, not
per-model. The judgment tier is reached through the same contract
(`HttpEndpoint`, System-One compatible) when a customer runs one.

## Status (honest)

No weights ship in this release; the shipped checks are deterministic
(`README.md`). The `enforce` bit is pattern-set only today; the
calibrated-confidence model→enforce path is the next target (`THE-BRAIN.md` §5,
§7). Nothing here is a claim that a model blocks anything *yet*.

**Loop proven end to end (2026-10-03, Apple M5 / MPS).** `laya_feed.py` →
Laya's upstream MPS trainer → `laya_eval.py`, from the `typed-decisions`
checkpoint, on the 9 oracle/seed rows in `misses/` (2 epochs, loss 1.02 → 0.37,
minutes). Training-set fit 4/9 → 9/9, mean P(gold) 0.42 → 0.85, shuffled-context
delta +0.22 → +0.56 (it reads the situation, not option priors). That is a
**smoke test on the training rows — not a benchmark**: no held-out set, no
calibration rows (temperatures defaulted to 1.2). It proves the pipeline; real
numbers need held-out pilot rows. Weights/ONNX live outside git
(`models/data/`, `~/laya_v1_out`) — model IP, private only.

## Next

1. **Fine-tune Laya v1** on `build_dataset.py` output + `misses/` (including the
   five `multi_step_evasion` seed rows). Re-run the 5 cases + the benchmark.
2. **Wire Laya through the registry** (`DecisionEndpoint` → `laya.predict`,
   ONNX, sealed path) — end to end, on-device.
3. **Benchmark the shipping path** — single-row int8 CPU latency and artifact
   size are measured (~160 ms, 571 MB; see above). Still to do: batch-of-10,
   MPS, and the DLP / malware encoders.
4. **Implement the calibrated-confidence tiers** (enforce / contain / review),
   gated as in `THE-BRAIN.md` §5 — the `GPL/` side as an issue + diff.
5. The training loop then feeds confirmed misses back (`TRAINING-LOOP.md`),
   manual-triggered, benchmark-gated.
