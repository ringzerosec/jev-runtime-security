# L10 — The bridge to Ring Zero

> **Laya track, chapter 10 of 10.** Goal: connect everything above to the code
> that makes it the brain of the product. Where a Laya verdict enters the
> system, the single contract it must speak (`checks/src/registry.rs`), how an
> answer becomes a kernel bit (`agent/src/write_scan`, `GPL/bpf`), exactly what
> is shipped versus designed, and the loop that keeps the model getting better.
> If P1–P3 are the *why*, this is the *where*.

## L10.1 The shape, one more time

```
agent writes file ──► FAN_CLOSE_WRITE ──► write-scan (userspace, off hot path)
                                             │  deterministic patterns → floor
                                             │  reflex model (Laya)     → raise / confidence
                                             ▼
                              agent_write_verdicts[(dev, ino)] = {enforce, review, severity}
                                             │
agent later open()/exec() ──► LSM hook reads ONE bit ──► allow / refuse (kernel speed)
```

Three facts from this diagram carry the whole design:

1. **The model runs after the write closes, before the artifact is used.** The
   kernel never waits on it (THE ONE RULE). Laya's ~160 ms on CPU (L9) is
   spent *here*, where there is no syscall to hold up.
2. **The verdict is keyed on content identity `(dev, ino)`**, not a path — a
   rename or hardlink cannot shake it off (`ringzero.bpf.c:116`).
3. **Two bits, not one** — `enforce` and `review` — and *who may set which* is
   the safety argument. That is the line between shipped and designed (§L10.4).

## L10.2 The contract: `checks/src/registry.rs`

Every model — Laya, a self-hosted judgment model, hosted Jev, GLiNER, the YARA
encoder — speaks **one** interface:

```rust
pub trait DecisionEndpoint: Send + Sync {
    fn name(&self) -> &str;
    /// Return (chosen option, confidence). The option MUST be one of `options`.
    fn decide(&self, category: &str, question: &str, options: &[String], state: &Value)
        -> Result<(String, f32), String>;
}
```

and the `Registry` owns the policy around it:

- **`OptionSet`** (39) — a category's options, *ordered benign → severe*;
  `rank()` is the index, and an unknown option ranks 0 "so it can never
  downgrade." This is `schema.py`'s `OPTIONS` on the Rust side, and it is the
  same ordinal ladder L4's RPS term was trained on. Three files must agree on
  the order: `schema.py`, the feeder's `criteria`, and the registry's
  `OptionSet`. If one drifts, the model's index means something else.
- **`Registry::score(category, state, floor_option, floor_conf)`** (215) — the
  deterministic result is the **floor**; the model's answer is accepted only if
  `rank(opt) > rank(floor)` (**THE clamp**, 240). An unknown option or a transport
  error keeps the floor **with the error attached** — "never a downgrade, never
  a silent swap." A category with no route is deterministic-only.
- **The five tests** (301–340) are the spec: `model_may_raise`,
  `model_may_not_lower`, `unknown_option_is_rejected_to_floor`,
  `error_keeps_floor`, `no_route_is_deterministic`. Read them as the
  requirements a `LayaEndpoint` must satisfy, and run them:
  `cargo test -p ringzero-checks registry`.

### Mapping a Laya answer onto `decide`

| Registry | Laya (L2, L6) |
|---|---|
| `category` → `question` text | `questions[category] = {"type": "score", "instructions": QUESTION[cat], "criteria": OPTIONS[cat]}` |
| `options` (ordered) | `criteria` list — **same order** |
| `state: Value` | `state` dict — **same keys the feeder used in training** (`{"situation": …}` plus whatever `laya_feed.py` emitted). Train/serve skew here silently degrades the model. |
| returned `option` | `options[argmax(probabilities)]` — **argmax, not the expected level**: `score` (a float like 1.51) is for humans; the clamp needs an index |
| returned `confidence: f32` | **`answer_confidence`** — never `confidence` (L5.1) |
| `Err(_)` | transport/OOM failure, or `abstention == "unevaluated"` — keep the floor, attach the reason |

## L10.3 Where the verdict becomes a bit: `agent/src/write_scan`

`write_scan::decide(pattern_worst, model_severity, enforce_at)` (`mod.rs:467`)
is "the safety argument … a function so it can be tested without a kernel, a
filesystem or a model." Today it returns `(enforce, review, severity)` where:

- `enforce` is a function of **`pattern_worst` alone**;
- `severity` is the **worse** of pattern and model (a model may raise what a
  human is told);
- `review` is set if **either** flagged.

Then `fanotify.rs` writes the struct into `agent_write_verdicts`; the BPF
`write_verdict` (`ringzero.bpf.c:118`) is `{enforce, review, severity, _pad}`
with the comment "enforce — deterministic only … review — model may set."

That is **v1 as shipped**, and the comments are accurate for it. Do not describe
it otherwise in public (`CONTRIBUTING.md`: claiming we block what we only record
is the one review comment that always blocks a merge).

## L10.4 Shipped vs designed — the exact gaps

`THE-BRAIN.md` §7 states the target: calibrated-confidence tiers, with the model
allowed to set `enforce` above τ_enforce. The distance between today's code and
that target is small and enumerable — this list *is* the engineering plan:

| # | Gap today | Change | Where |
|---|---|---|---|
| 1 | `HttpEndpoint::decide` speaks the chat-completions "answer with one letter" contract and **returns confidence `1.0`** (registry.rs:177) | A `LayaEndpoint` (in-process ONNX or `/v1/systemone`) that returns `answer_confidence`; the letter-contract endpoint stays for generative judgment models | `checks/src/registry.rs` (Apache-2.0, our side) |
| 2 | `Registry::score` passes confidence through but **no tier policy** consumes it | A `Tier` from `(rank, confidence, τ_enforce, τ_contain)`: ENFORCE / CONTAIN / REVIEW; thresholds in config, fitted per bucket (`calibrate.fit_abstention_thresholds`, L5) — never guessed | `checks/`, `agent/src/config.rs` |
| 3 | `write_scan::decide` derives `enforce` from `pattern_worst` alone | `enforce = pattern_enforce ‖ (model_rank ≥ enforce_rank ∧ confidence ≥ τ_enforce)`; `contain` as a new output driving quarantine + egress narrowing + session raise | `agent/src/write_scan/mod.rs` — keep it a pure function; extend the tests |
| 4 | BPF comment and `write_verdict` layout say "a model may never set enforce" | Comment update + the fail-safe argument for the hook change, filed as issue + diff per `CONTRIBUTING.md`; the kernel side reads the same bit — the *who-may-set* moves to userspace policy | `GPL/bpf/ringzero.bpf.c` |
| 5 | No calibration payload shipped with the checkpoint | Ship `calibration.json` next to `laya_v1.int8.onnx`; `ONNXAgent.load_calibration` at startup; refuse to run enforce-tier with unfitted temperatures (`[1.2,1.2,1.2]` = L7's "no calibration rows") | roster / packaging |

Nothing here touches the hot path. Every change is userspace policy on a
confidence number the model already emits. **The fail-safe argument for #3/#4**,
which the GPL diff must carry: on model error → floor (unchanged); on
`abstained`/`unevaluated` → review (unchanged); the model can only move the bit
*toward* refuse, never away; and the deterministic floor still sets `enforce`
on its own exactly as today — so the new path can only add refusals, and only
above a calibrated, held-out-validated threshold.

## L10.5 Choosing the endpoint shape

Two ways to run Laya behind `DecisionEndpoint`:

- **In-process / sidecar ONNX** (`onnxruntime`, int8, no network): the sealed
  endpoint. One file, one process, ~160 ms/row CPU. Preferred for the
  per-artifact reflex. The Rust side can call `ort` directly or a local Python
  sidecar over a Unix socket; either way `state` never leaves the machine, so the
  `redact` hook (registry.rs:92) is belt-and-braces rather than load-bearing.
- **`/v1/systemone` over HTTP** (`laya-serve`, L9.6): for a shared GPU box or the
  judgment tier. Same Jev-compatible shape, so a hosted-Jev deployment and a
  self-hosted Laya are interchangeable by URL. The `redact` hook *is*
  load-bearing here.

Both must serialise `state` **the way the feeder did** (L10.2). Make that one
function, used by `laya_feed.py` at training time and by the endpoint at serve
time, and the skew problem disappears by construction.

## L10.6 The loop that makes the brain better

`models/TRAINING-LOOP.md` is the governance; mechanically the loop is:

```
pilot / hackathon session ──► miss (oracle-confirmed) ──► misses/misses.jsonl
      ▲                                                        │
      │                                              laya_feed.py (L7)
      │                                                        ▼
  ship int8 + calibration  ◄── promotion rule ◄── laya_eval.py + held-out families (L8)
                                                               ▲
                                                 trainer (L7) ─┘
```

The promotion rule: a new checkpoint ships only if it beats the current one on
held-out accuracy, ECE on held-out rows, the shuffled-context delta, the
benign-session FP floor, **and** per-family tighten-direction on unseen attack
families. `bench/README.md` has the honesty rules (every number from a script);
`THE-BRAIN.md` §8 has the anti-patterns that this loop exists to prevent —
chief among them "keep model work small." The loop *is* the USP's engine.

## Try it

```sh
cd /Users/jarvis/rgs/rgs-linux-oss
cargo test -p ringzero-checks registry   # the five contract tests
cargo test -p agent write_scan           # decide() and its safety tests
```

Then, as a sketch (not for the hot path): write a `Fixed`-style endpoint test
(see registry.rs:274) that returns `("credential_accessed", 0.93)` and assert
the `Verdict.confidence` is **0.93**, not 1.0 — the first thing a real
`LayaEndpoint` must get right.

## Where this lives

- `checks/src/registry.rs` — `SYSTEM` (33), `OptionSet` (39), `Verdict` (56),
  `DecisionEndpoint` (68), `HttpEndpoint` (85), `Registry::score` (215), the
  clamp (240), tests (270–340).
- `agent/src/write_scan/mod.rs` — `decide` (467), `scan_agent_code` (155),
  `scan_protected_intent` (431); `fanotify.rs` for the map write.
- `GPL/bpf/ringzero.bpf.c` — `write_verdict` (118), `agent_write_verdicts`.
- `models/THE-BRAIN.md` (§3–§8), `models/ROSTER.md`, `models/TRAINING-LOOP.md`,
  `models/schema.py` (`OPTIONS`, `ENFORCEMENT`, `QUESTION`).

## Exercise

1. Write out the five registry tests as English requirements. Which one would a
   naïve `LayaEndpoint` that returns the *expected level* instead of the argmax
   fail, and how?
2. State the fail-safe argument for letting the model set `enforce` above
   τ_enforce in four sentences, each naming a concrete failure (model down,
   model abstains, model says benign, model confidently wrong) and what the
   kernel does in each.
3. Three files must agree on option order. Name them, and design the one test
   that catches drift between them.
4. A reviewer says: "so the model is optional — if it's down, the system still
   works." Answer in two sentences using §L10.4 and `THE-BRAIN.md` §8, without
   contradicting the fact that the floor still holds when the model is down.

---

**End of the Laya track.** Back to the [index](README.md). The drill in P2.8
and the exercises in L4, L8 and L10 are the test: if you can answer them cold,
you can defend the brain — paper to kernel bit — to anyone.
