# Research direction — System 1 / System 2, and what the brain is made of

> Private fork only (model IP). Companion to `THE-BRAIN.md` (what the brain
> is for and where it may act) and `ROSTER.md` (the inventory). This file is
> the *architecture direction*: what we are building the reflex model out of,
> why, and what the first experiments are. It exists because an advisor's
> critique on 2026-10-03 was right about the part that matters, and the
> reasoning should not have to be re-derived next month.

## 1. The critique, verbatim in substance

> "That research paper [SalesRLAgent] and Laya are honestly crap for this use
> case. The architecture is too shallow for what you're trying to solve. Go
> back to Kahneman's System 1 and System 2 work and start from there. Also
> refer to Google's vision encoder (SigLIP2) and OpenAI's Whisper audio
> encoder for multimodal. You can use both towers."

What is right about it: Laya is one text encoder with scoring heads. It reads
up to ~1k tokens of *text* in one pass and emits a distribution. For a product
that protects **all AI agents** — not only coding agents in a terminal — the
state the reflex model must judge is not only text. Computer-use and browser
agents perceive a screen; voice agents perceive audio. A single text tower is a
System 1 for one slice of the agent world.

What is not in the critique and is still true: our universal sensor is the
**kernel**, not the screen. Syscalls, file writes, process lineage, egress are
ground truth of what an agent *did*, for every agent, with no integration.
Vision and audio are **provenance** senses — what the agent was *told* — and
they matter because the question the brain answers is "does the action match
the task," which needs both halves.

## 2. Kahneman as the design spec

| Kahneman | Property | In the brain |
|---|---|---|
| **System 1** | fast, parallel, always on, perceptual, pattern-matching; produces a *feeling of confidence*; learns expert intuition from feedback in a regular environment | pretrained **perception encoders** (frozen) + small fusion + typed decision heads, run on every event, on-device, off the hot path |
| **System 2** | slow, serial, effortful; engaged when System 1 is surprised or unsure | generative judgment model over the whole session, self-hosted on the customer's GPUs, invoked on **abstention / low confidence / novelty** |
| the handoff | surprise, not rules | the calibrated-confidence tiers in `THE-BRAIN.md` §5: enforce / contain / review |
| the learning loop | intuition is trained by feedback | System 2's and humans' verdicts become System 1 training rows (`TRAINING-LOOP.md`) |

Two consequences we commit to:

1. **System 1 is a perception stack, not a classifier.** Its job is to turn
   everything observable about an agent step into one state vector and a
   calibrated verdict, in one forward pass. Encoders are perception; the heads
   are the verdict.
2. **System 2 is called by System 1's uncertainty, never on a schedule.** The
   abstain head and the per-bucket confidence gate are the trigger. This is
   what keeps the heavy tier off the common path and the data loop honest.

## 3. The architecture: towers → fusion → heads

```
                    ┌──────────────── System 1 (on-device, always on) ────────────────┐
  kernel events ──► kernel-event tower (ours; small transformer over tokenized events)  │
  text (code,     ─► text tower (ModernBERT today; or SigLIP2's text tower, see §4)     │
   shell, msgs)                                                                        │
  screenshots    ─► vision tower (SigLIP2, frozen)                ─► fusion ─► heads ──┼─► verdict + confidence
  audio          ─► audio tower (Whisper-small encoder, frozen)    (cross-attn,         │   + abstain
                                                                    ~50–150M)          │
                    └──────────────────────────────────────────────────────────────────┘
                                                            abstain / novelty
                                                                  ▼
                    ┌──────────────── System 2 (customer GPU, on surprise) ────────────┐
                    │ generative judge over the full session → verdict → training row  │
                    └──────────────────────────────────────────────────────────────────┘
```

**Towers (perception).** Pretrained, open-weight, permissively licensed,
encoder-only, frozen at first:

| Tower | Base | Why this one | Status |
|---|---|---|---|
| **Kernel-event** | ours — a small transformer over a tokenized event stream (process lineage, file ops with provenance taint, egress, timing) | nobody ships this; it is the sensor every agent produces and the moat | **to build** — the first experiment (§6) |
| **Text** | ModernBERT-large (Laya's encoder) today; candidate: SigLIP2's text tower so text and screen share one space | code, shell, transcripts, tool messages | have (Laya v1) |
| **Vision** | SigLIP2 (Apache-2.0; base/large/so400m variants, dense features, multilingual) | computer-use / browser agents act on what they see; the injection is on the screen | when computer-use agents enter scope |
| **Audio** | Whisper-small encoder (244M, MIT) | voice agents are instructed by audio | last |

**Fusion.** A small cross-attention transformer that takes whichever towers
are present (missing modalities are simply absent, not zero-filled) and emits
one state vector. This is the only new backbone we train from scratch, and it
is deliberately small.

**Head design note (from Gero-4B, 2026-10-04).** Gero's *branch readout* —
one shared `Linear(hidden, 1)` scorer, each option its own branch that sees the
prefix but not the other options, softmax across branches — has **zero
position bias by construction** and handles any option count with one set of
weights. Laya packs options into one sequence with `[MASK]` markers, so options
see each other and bias has to be corrected afterwards (permutation,
per-bucket temperatures). Prefer the branch readout for any head we build on a
decoder backbone (System 2), and the per-option cross-encoder equivalent on
the fusion stack. Also adopt from Gero: the pre-train data checker (leak,
position, majority-text, string-presence), the reward fixed-point test, the
zero-gradient-at-truth rule for any added loss term, Murphy
reliability/resolution, and `correct = soft[pred]` on ambiguous items.

**System 2 is a scorer, not a chatbot.** Gero shows a 4B backbone + LoRA on the
last layers + branch scorer yields calibrated typed decisions from the same
model that would otherwise generate text. The judgment tier should be built
this way: same `DecisionEndpoint` contract and confidence semantics as System
1, no letter parsing.

**Heads.** Carried over from Laya unchanged in design: typed decision heads
(choice / ordinal score / boolean), the **abstain head**, proper-scoring
training, per-type *and* per-option-count temperature calibration, the
confidence gate with explicit `passed / abstained / unevaluated` states. This
machinery is encoder-agnostic and it is the part that makes confidence
*actionable*. The course track L2–L5 and L8 document it.

**"Both towers."** SigLIP2 is a two-tower (image + text) contrastive model.
Using its text tower as *our* text encoder puts text state and screen state in
the same embedding space, so fusion can compare "what the agent read" with
"what it then did" directly. Whether that beats ModernBERT for code/shell is an
experiment (§6, E3), not an assumption.

## 4. What survives from the Laya work, what is replaced

| Keep | Replace |
|---|---|
| typed heads, abstain head, proper-scoring objective (L4) | the single ModernBERT tower as *the* model |
| per-bucket temperature calibration + ECE/AURC evaluation (L5, L8) | "state = one text string" |
| the `DecisionEndpoint` contract and tighten-only clamp (`checks/src/registry.rs`, L10) | nothing — the contract is unchanged; a multi-tower model is just another endpoint |
| the feeder → train → held-out-families → promote loop (L7, L8) | nothing — the loop gains new input types |
| the measured numbers (571 MB int8, ~160 ms/row CPU) as the *text-only baseline* | — |

Laya v1 remains the shipped **text-only System 1** until the kernel-event
tower beats it on the held-out-family benchmark. Nothing in this file changes
what ships today; `THE-BRAIN.md` §7 still governs public claims.

## 5. Budget and footprint (targets, not measurements)

- Towers frozen: SigLIP2-base ~0.4 GB, Whisper-small encoder ~0.1 GB (encoder
  only), text tower ~0.4 GB (ModernBERT-large) or ~0.1 GB (SigLIP2 text).
  Kernel tower + fusion ~0.1–0.2 GB. **On-device total ~0.7–1.1 GB int8**, text
  + kernel only ~0.5 GB.
- Latency off the hot path: a screenshot through SigLIP2-base on CPU is a few
  hundred ms; text and events are faster. Acceptable because the kernel never
  waits (`THE-BRAIN.md` §3).
- Training: towers frozen → the trainable part is ~0.2 GB; a single Inception
  GPU box is enough for every experiment in §6. This is the cheap path, by
  design — it is what the "pretrain a 3–8B MoE for $30k" advice would have
  spent ten times more to reach.

## 6. The first experiments (Inception box)

Every experiment reports the four gates from `bench/README.md`: held-out
accuracy, held-out ECE, shuffled-context delta, FP floor on benign sessions —
plus **held-out attack families** (train on N−1 mechanisms, test on the unseen
one; report the tighten direction).

- **E0 — Baselines, measured (2026-10-04, M5 16 GB, 9 rows — a smoke signal,
  not a benchmark).** Zero-shot on our rows, same metrics (`laya_eval.py`,
  `gero_eval.py`):

  | model | acc | mean P(gold) | shuffled acc | delta | ms/question |
  |---|---|---|---|---|---|
  | Laya base `typed-decisions` (421M, zero-shot) | 4/9 | 0.42 | 0.22 | +0.22 | ~160 (int8 CPU) |
  | **Gero-4B** (Qwen3-4B branch scorer, zero-shot) | 2/9 | 0.29 | 0.22 | **+0.00** | ~36,000 (fp16 MPS, swap-bound) |
  | Laya v1 (fine-tuned on these rows — training fit, not generalisation) | 9/9 | 0.85 | 0.44 | +0.56 | ~160 |

  Reading: a generic 4B decision model with no domain data does **not** read a
  security situation better than a 421M one — Gero's delta of 0.00 means its
  verdicts did not change when the state was swapped; it answered from option
  priors. This is the "data is the moat, not the recipe" claim, measured.
  Caveats: n=9; snake_case option labels (`staging_for_exfiltration`) may
  under-serve Gero's "option - description" training format (retry with
  `schema.py` descriptions is cheap); the latency is a 16 GB machine thrashing,
  not the model. The real Gero question — does a 4B *fine-tuned* scorer
  generalise to unseen attack families better than Laya — needs a GPU and is
  folded into E2/E3.
- **E1 — Kernel-event tokenizer + tower.** Define the event vocabulary
  (process, exec, open/write with taint bit, connect, timing buckets), train a
  small transformer on recorded sessions (`bench/scenarios.jsonl` +
  pilot traces) with Laya-style heads. Question: does the event stream alone
  separate circumvention from benign work, and on which families does it fail?
- **E2 — Text + kernel fusion.** Add the text tower (what the agent wrote) to
  E1 through fusion. Question: how much does the write-scan text add over
  events, and vice versa? This is the first *two-sense* System 1.
- **E3 — Text tower bake-off.** ModernBERT-large vs SigLIP2 text tower on the
  same rows. Question: does a contrastively-trained text tower lose on
  code/shell, and by how much?
- **E4 — Vision tower.** Only once a computer-use agent is in the pilot:
  screenshots through SigLIP2 into fusion. Question: can System 1 tell that the
  on-screen instruction and the subsequent action disagree?
- **E5 — The handoff.** Measure the abstain rate and System 2's verdict
  agreement on abstained rows. Question: is surprise a better trigger than a
  threshold alone? This is the Kahneman claim, tested.

E1 and E2 are the plan for the next lab block. E3 is cheap and can run in
parallel. E4/E5 wait on data we do not have yet.

## 7. Anti-patterns this file exists to prevent

| Wrong | Right |
|---|---|
| "The reflex model is a text classifier." | It is a perception stack over every sense an agent has, with a verdict head. |
| "Add vision because it's multimodal." | Add vision when agents that *see* are in scope; the kernel tower comes first because every agent produces it. |
| "Replace Laya." | Replace the *tower*; keep the heads, calibration, gate, contract, and loop. |
| "System 2 on every event." | System 2 on surprise. The abstain head is the trigger. |
| "Bigger model." | More senses, same small verdict head, frozen towers. |

References (public): Kahneman, *Thinking, Fast and Slow* (2011); Kahneman &
Klein, "Conditions for Intuitive Expertise" (2009); SigLIP2
(huggingface.co/blog/siglip2); Whisper (openai/whisper-small);
Gneiting & Raftery (2007) for the heads' objective.
