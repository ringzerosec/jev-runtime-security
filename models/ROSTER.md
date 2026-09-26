# Model roster (base models)

All models are advisory and **raise-only** (the kernel decides; see the one rule).
All are **local, fine-tuneable, open-weight** — no hosted API in the product. They
plug into the pluggable registry (`checks/src/registry.rs`) under one contract, so
swapping or adding a model is a config route, not a code change.

| Tier | Job | Base model (LOCKED / candidate) | Why |
|---|---|---|---|
| **Reflex** (per-event) | option-scoring for each `EnforcementCategory` | **Laya** — `convaiinnovations/laya`, **Apache-2.0**, ModernBERT-large encoder (~421M; mmBERT-base ~322M multilingual) | encoder = one forward pass → fast + **calibrated probabilities** natively; open + shippable + local |
| **DLP** | secret/PII extraction | **GLiNER-family** (open, Apache/MIT, e.g. `urchade/gliner*`) — also an encoder | schema-driven entity extraction; catches what regex misses; raise-only floor over the redactor |
| **Judgment** (per-trace) | trajectory / behaviour, custom definitions | generative / Span-1-style — **TBD (build/adopt)** | needs reasoning over long traces & operator-defined behaviours; the hard, later bet |
| **Malware** (bounded) | agent-written/downloaded file → malicious? | small encoder decision model, YARA-labelled — see `models/malware/` | releasable now on open data; floor over `yara-x` |

## Why Laya over Tev1 (the reflex base)

Same 5 cases, our own contract, zero-shot (no fine-tuning):

| | Tev1 (generative Qwen-0.8B) | **Laya (encoder)** |
|---|---|---|
| accuracy on our cases | 3/5 (under-graded exfil + injection) | **5/5** |
| calibrated probability | no | **yes** (0.52–0.88, sensible) |
| CPU latency | 1–5.5 s | 0.3–2.1 s |
| licence | unfinalized | **Apache-2.0** |

Laya's `score` question type is an ordinal severity (0..N) — a clean fit for our
benign→severe option sets and raise-only. Honest caveat: 5 hand-written cases is a
**smoke test, not a benchmark** (`models/bench` is the real measure), and the
33 ms figure is GPU/ONNX — CPU unoptimized is ~hundreds of ms.

## Serving

`laya.predict(state, questions)` in-process, exported to **ONNX** for the sealed
sandbox (no server, no network). The registry's `DecisionEndpoint` wraps it; the
raise-only clamp is enforced centrally in the registry, not per-model.

## Next

1. **Fine-tune Laya v1** on `build_dataset.py` output + the seed misses
   (`models/misses/`), re-run the 5 cases + the benchmark. (Laya is Apache-2.0, so
   the fine-tuned weights are ours to ship.)
2. Wire Laya through the registry (`DecisionEndpoint` → `laya.predict`) — the
   sealed local path end to end.
3. The training loop then feeds confirmed misses back (`models/TRAINING-LOOP.md`),
   manual-triggered, benchmark-gated.
