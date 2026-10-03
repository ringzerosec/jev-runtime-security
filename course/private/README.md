# Private research track — model IP, never in a public zip

The public course (Chapters 1–17, `../`) teaches the open-source kernel
enforcement and userspace. **This directory is different: it is model IP.** It
documents the brain — the decision model, why it is the product's USP, where
its authority comes from, the research it is built on, and the lab plan. Per the
rule set on 2026-10-03, anything related to model IP lives only in the private
fork (`abhiabhijit/jev-runtime-security`, branch `models-rnd`) and is **never
pushed to the public upstream and never included in a zip handed to learners.**

| Chapter | What it teaches |
|---|---|
| [P1 — The brain: where a decision model fits](P1-the-brain-where-a-decision-model-fits.md) | the indirect-attack gap a rule can't see; System 1 vs System 2; 13 categories = one model; where the model may act and the one place it may not; tighten-only ≠ advisory-only; the calibrated-confidence tiers; shipped vs designed |
| [P2 — Why the state space doesn't hit the model](P2-why-the-state-space-does-not-hit-the-model.md) | the standard doubter's objection ("millions of states / changing context / OOD / persistent state") answered clause by clause from the mechanisms; where state actually persists; the real gaps and why a bigger model fixes none of them; **the eight-question drill** |
| [P3 — Research basis and the lab plan](P3-research-basis-and-the-lab-plan.md) | SalesRLAgent → Laya → the brain; what transfers and what doesn't; what we have *measured* on our own hardware (and its honest label); the six-stage lab plan for Inception compute; why we don't pretrain a System 1 now |

Read P1 → P2 → P3. The drill in P2.8 is the test: if you can answer all eight
cold, you can defend the design to anyone.

## The Laya track — paper to implementation to kernel bit

Ten chapters that read the decision model's source end to end. Every chapter
cites file:line in the upstream `laya` package (installed in `~/laya-venv`) and
ends with a "Try it" that runs on this machine and an exercise answered from the
source, not from the chapter.

| Chapter | Source read | Question answered |
|---|---|---|
| [L1 — The idea: from SalesRLAgent to RLCD](L1-the-idea-from-salesrlagent-to-rlcd.md) | arXiv 2503.23303; model card | Why an encoder that emits a distribution, and what "RLCD" means |
| [L2 — A question becomes a sequence](L2-a-question-becomes-a-sequence.md) | `common.py` `build_sequence`, `build_head`, `render_options` | How state + typed question are laid out as one token sequence |
| [L3 — The model: forward pass](L3-the-model-forward-pass.md) | `common.py` `DecisionModel.forward`, `_DynamicMultiheadAttention` | Scorer at option markers, act head, temperature buffer |
| [L4 — The objective: proper scoring rules and RLCD](L4-the-objective-proper-scoring-and-rlcd.md) | `proper_reward`, `td_lambda_targets`, trainer loss step (read yourself) | Why the target is a distribution; why ordinal needs RPS; what RL is doing |
| [L5 — Calibration, confidence, abstention](L5-calibration-confidence-and-abstention.md) | `calibrate.py`, `confidence.py`, `_decode_answers` | Which number you may threshold, and when "c of answers at c are right" holds |
| [L6 — The runtime: load, predict, decide](L6-the-runtime-load-predict-decide.md) | `agent.py`, `structured.py`, `shortlist.py` | One request end to end; batch, long, schema paths |
| [L7 — Training in practice](L7-training-in-practice.md) | MPS trainer; `models/laya_feed.py` | The gold contract, the stages, our measured run |
| [L8 — Evaluation](L8-evaluation.md) | `evals.py`; `models/laya_eval.py` | Accuracy, ECE, AURC, shuffled-context control, held-out attack families |
| [L9 — Shipping: ONNX, int8, serving](L9-shipping-onnx-int8-serving.md) | `export_onnx.py`, `onnx_agent.py`, `serve.py`, `router.py` | The 571 MB artifact, ~160 ms/row CPU, `/v1/systemone` |
| [L10 — The bridge to Ring Zero](L10-the-bridge-to-ring-zero.md) | `checks/src/registry.rs`, `agent/src/write_scan`, `GPL/bpf`, `THE-BRAIN.md` | The one contract, the clamp, shipped vs designed, the data loop |

Order: P1 → P2 → P3, then L1 → L10. The exercises in L4, L8 and L10 plus the
P2.8 drill are the whole test.

## Producing the public zip (learners get this; never the directory above)

From the repo root, excluding this track *and* the lab build artifacts:

```sh
cd /Users/jarvis/rgs/rgs-linux-oss
zip -r ~/Desktop/ring-zero-course.zip course \
  -x "course/private/*" \
  -x "course/labs/*/vmlinux.h" -x "course/labs/*/*.o" -x "course/labs/*/target/*" \
  -x "course/labs/00-setup/hello" -x "*.DS_Store"
unzip -l ~/Desktop/ring-zero-course.zip | grep -c "course/private/"   # must print 0
```

The last line is the check. If it prints anything but `0`, do not send the zip.
