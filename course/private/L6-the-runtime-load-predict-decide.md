# L6 — The runtime: load, predict, decide

> **Laya track, chapter 6 of 10.** Goal: follow one request through
> `agent.py` from `laya.load(...)` to the answer dict — what gets loaded, how a
> state and its questions become batched tensors, how the two model outputs
> become typed answers, and the three convenience paths on top (`predict_batch`,
> `predict_long`, `decide`). Read `agent.py` 446–560 (init), 1183–1335
> (`_forward`, `predict_batch`), 1450 (`predict_long`), 1787 (`decide`),
> 1902 (`load`); `structured.py`; `shortlist.py`.

## L6.1 `load()` — one table of names (agent.py:1902)

```python
laya.load("convaiinnovations/laya")                 # Hub repo, root checkpoint (English)
laya.load("convaiinnovations/laya", subfolder="multilingual")
laya.load("typed-decisions")                        # alias -> resolved by router.resolve_model_spec
laya.load("/Users/jarvis/laya_v1_out", device="mps") # a local checkpoint dir
```

The rule in the code: a bare word is treated as a registry alias (the same table
the `Router` reads) *unless* it looks like a path (`/`, `.`, `~`) or the directory
actually holds `rl_agent_config.json` (`_is_local_checkpoint_arg`, 1882). So our
fine-tuned dir loads by path, and `fast=True` / `compile=True` select the
TileLang GPU path or `torch.compile`.

## L6.2 What `Agent.__init__` does

Reading the first ~120 lines of the class and its helpers:

- **Strict checkpoint load.** `build_model(cfg, encoder_dir=…)` builds the
  architecture *uninitialised* (meta device), then `load_state_dict(…,
  strict=True)` fills every parameter from `model.safetensors`.
  `_verify_compatibility` (112) checks the weights match the config's
  architecture before trusting them.
- **Tokenizer repair.** `_fix_tokenizer_config` (57) patches the saved tokenizer
  config so transformers 4.x and 5.x both load it — you saw the trainer and our
  feeder call this too.
- **Device and precision.** `dtype` is an *autocast target*, not a promise:
  on MPS a call autocasts only at or above `mps_amp_min_rows` rows (285), so a
  single-row predict runs float32 while a batch runs float16. CUDA/CPU have
  their own rules (`_cuda_amp_dtype`, `_cpu_amp_dtype`). `dtype_for(rows)`
  tells you which applies.
- **Serialization and fallback.** `_InferenceGate` (162) serializes inference
  per agent; `_infer` has a per-request **GPU-OOM → CPU fallback** whose
  frequency and last failure are counted so an operator can see "a slow lane"
  in `/health` instead of discovering it by accident.
- **Temperatures and hooks.** Per-type + per-bucket temperatures from the
  config (L5), optional `lang_temperatures` overrides, optional `calibration`
  payload, and a `HookRegistry` (the class inherits it) for `on_predict_start` /
  `on_predict_end`.

## L6.3 One request, end to end

`predict(state, questions)` is the one-state path; `predict_batch` (1259) is the
same thing over many states packed into shared forward passes — the throughput
path on GPU. Both run this pipeline:

1. **Hooks, start.** `PredictContext(states, questions, max_len, head_max_len)`
   is built and `on_predict_start` hooks dispatched. A hook may **rewrite** the
   state/questions, change the token budget, or `ctx.skip(result)` to
   short-circuit inference entirely. (This is how you'd insert a policy
   pre-check or a cache in front of the model.)
2. **Validate + normalise questions** into the internal `{t, ins, crit, …}`
   form; count options (`_option_count`, 317); check the scan budget
   (`_check_scan_budget`, 373) so a state that will be truncated is reported.
3. **Tokenize once, build per question.** `encode_state` tokenizes the state
   once; `build_sequence(..., state_ids=…)` reuses those ids for every question
   (L2). The question half is cached per call by `_reuse_question_tokens` (a
   `ContextVar` cache) so a batch of 1,000 states with the same questions
   doesn't re-tokenize the options 1,000 times.
4. **Collate** (`collate_items`, common.py:775) into `input_ids`,
   `attention_mask`, `marker_pos`, `marker_mask`, `qtype`.
5. **Forward** (`_forward` → `_infer`): returns `logits` as float32 numpy and
   `softmax(act_logits)`.
6. **Decode** (`_decode_answers`): per question, slice this item's option logits
   (`_option_logits`, 437), divide by the bucket temperature, softmax,
   `unpermute_probs` back into the caller's option order, then build the typed
   answer:
   - `choice` → `choice` (argmax key), `probabilities` keyed by label
   - `score` → `score` = **expected level** `Σ i·p_i` (a float, e.g. 1.51),
     `legend` (index → level text), `probabilities` keyed `"0".."k-1"`
   - `noul` → `noul` = `p[1]` (P(true))
   - every answer also gets `confidence`, `answer_confidence`, and
     `action.act_probability` (L3, L5).
7. **Gate** — `apply_confidence_gate` if `min_confidence` was passed (L5).
8. **Hooks, end** — `on_predict_end` may rewrite results.
9. **Usage** — `input_tokens`, `state_tokens`, `state_tokens_dropped`,
   `truncated`, `truncated_questions`: the honest accounting of what the model
   actually saw.

That is the dict you printed in L1's "Try it."

## L6.4 Long states: `predict_long` (1450)

A state longer than the room left by the head (L2's `state_room`) can't fit in
one sequence. `predict_long` splits it into **windows** sized by
`window_budget` (common.py:272), runs each window, and combines — so a whole
document (or a long session transcript) can be scanned with the same questions.
Its budget helpers refuse to silently shrink a window below a sane fraction
(`_WINDOW_CLAMP_WARN_RATIO`) and cap batch blow-up. For the brain this is the
path a *session-level* scan would use if it ran on the reflex model — but the
roster puts session reasoning on the judgment tier precisely because windowing a
512–1024-token encoder over a long trace is the wrong tool.

## L6.5 Many options: `shortlist` (shortlist.py)

Laya's own caveat: it is weaker than a generative model at **very high
cardinality** (> 20 options). `predict_shortlist` (63) handles it by embedding
the options and the state (`embed_fn_from_agent`, 126 — the encoder's own hidden
states; `cached_embed_fn`, 183), ranking by cosine, and asking the real question
only over the top-k (`_rank`, 290). Our option sets are 3–4 long, so we never
hit this — but it is the pattern for an "open-ended" category if one ever
appears.

## L6.6 Schema-driven decisions: `decide` (1787, structured.py)

`decide(state, schema)` takes a **JSON schema or a Pydantic model** and turns
each field into a typed question — an enum → `choice` (`_enum_field`), a bool →
`noul`, a bounded integer with level descriptions → `score` (`_score_field`) —
runs them in one pass, and projects the answers back into a `DecisionResult`
shaped like the schema (`_project`, `answers_to_json`, `answer_to_pydantic`).
This is the ergonomic front door for a product: define the decision as a type,
get a typed object back, with the per-field probabilities still attached in
`details`.

## Try it

```sh
~/laya-venv/bin/python - <<'EOF'
import laya, json
a = laya.load('/Users/jarvis/laya_v1_out', device='cpu')
qs = {"exfil": {"type":"score","instructions":"Is data being staged or sent outside its boundary?","criteria":["none","staging_for_exfiltration","exfiltration"]},
      "cred":  {"type":"score","instructions":"Is the agent accessing a credential or secret?","criteria":["benign","credential_referenced","credential_accessed"]}}
states = [{"situation":"agent opened ~/.aws/credentials and base64-encoded it"},
          {"situation":"agent ran cargo test in the workspace"}]
for r in a.predict_batch(states, qs):
    print({k: (v["score"], v["answer_confidence"]) for k, v in r["answers"].items()}, r["usage"]["state_tokens"])
EOF
```

Two states × two questions = four sequences, one forward pass. Note the
`usage` block per state.

## Where this lives

- `laya/agent.py` — `_fix_tokenizer_config` (57), `_verify_compatibility`
  (112), `_InferenceGate` (162), `_option_logits` (437), `Agent` (446),
  `_forward` (1183), `_decode_answers`, `predict_batch` (1259),
  `predict_long` (1450), `decide` (1787), `load_calibration` (1866), `load` (1902).
- `laya/structured.py` — `plan_from_json_schema` (192), `decide` (283).
- `laya/shortlist.py` — `predict_shortlist` (63), `embed_fn_from_agent` (126).
- `laya/hooks.py` — `HookRegistry`, `PredictContext`, `dispatch`.

## Exercise

1. Trace a `predict` call with two questions on one state: how many sequences,
   how many forward passes, and which step would differ if you used
   `predict_batch` over 500 states?
2. Write an `on_predict_start` hook that returns a cached result when the state
   hash was seen before. Where in the pipeline does it short-circuit, and what
   never runs as a consequence?
3. Why is `score` returned as an *expected level* (a float) rather than the
   argmax index? Give one case where the two disagree and say which one a
   tighten-only policy should act on.

---

Next: **[L7 — Training in practice](L7-training-in-practice.md)**.
