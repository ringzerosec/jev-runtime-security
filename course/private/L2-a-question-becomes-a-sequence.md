# L2 — A question becomes a sequence

> **Laya track, chapter 2 of 10.** Goal: understand the single most important
> mechanism in Laya — how a state and a typed question are packed into *one*
> token sequence, and where in that sequence each option is scored. Everything
> else (the model, the loss, calibration, ONNX) is built on this layout. Read
> `common.py` lines 75–262 alongside this chapter.

## L2.1 The format, in one line

Every (state, question) pair becomes this sequence (`build_sequence`, docstring):

```
[CLS] <type> question: <instructions> [SEP] [MASK] opt0 [MASK] opt1 ... [SEP] <state> [SEP]
```

Three things to notice before the code:

1. **The question comes first, the state last.** The head (question + options) is
   built to a fixed budget; the state gets *whatever room is left*.
2. **Each option is preceded by a `[MASK]` token.** Those `[MASK]` positions are
   the **markers**. The model will read the hidden state *at each marker* and
   turn it into one logit — one per option. That's the whole "decision head."
3. **It is one sequence per question.** A request with three questions over one
   state is three sequences (sharing a tokenized state — see `state_ids`).

So Laya is, mechanically, a **fill-the-masks** model: the options are written
into the input, and the encoder is asked "how well does the state support the
text sitting after *this* mask?" — once, bidirectionally, for all of them.

## L2.2 Rendering options: `render_options` (common.py:107)

Each question type renders its options to text differently:

```python
# choice: criteria is a dict label -> description
["%s: %s" % (k, render_criterion(v)) ...]      # or just str(k) if no description
# score: criteria is a LIST, ordinal, index = level
["level %d: %s" % (i, render_criterion(c)) for i, c in enumerate(crit)]
# noul: always exactly two, in semantic order [false, true]
[false_label + ": " + (...), true_label + ": " + (...)]
```

Two details that matter for us:

- For `score`, **the list index is the level**. Our `schema.py` option sets are
  lists ordered benign → severe, so *level = severity rank* by construction.
- `render_criterion` turns a dict/list criterion into compact JSON rather than a
  Python `repr` — a real bug class the comments document (`{'desc': ...}` leaking
  into prompts). Criteria are text the model reads; render them deliberately.

## L2.3 Building the head: `build_head` (common.py:196)

```python
head_ids = encode("%s question: %s" % (q["t"], ins))        # "score question: Is data being…"
for i in order:
    opt_tokens = encode(" " + opts[i], truncation=True, max_length=48)   # ≤48 tokens per option
    opt_ids.append([tok.mask_token_id] + opt_tokens)       # [MASK] + option text
opt_budget = head_max_len - sum(len(o) for o in opt_ids)
if opt_budget < 16:                                         # too many/long options: squeeze each
    per = max(4, (head_max_len - 16) // len(opt_ids)); opt_ids = [o[:per] for o in opt_ids]
head_ids = head_ids[: max(8, opt_budget)]                   # instructions get what's left (≥8)
ids = [CLS] + head_ids + [SEP]
for o in opt_ids:
    markers.append(len(ids)); ids.extend(o)                 # marker = index of this option's [MASK]
ids.append(SEP)
```

Read the budget logic carefully, because it is where questions silently change:

- `head_max_len` (256 in our checkpoint) caps the *whole* head. Each option is
  capped at **48 tokens**; if the options together leave fewer than 16 tokens,
  every option is cut to a per-option share (`per`), minimum 4.
- The returned `stats` — `options`, `options_distinct`, `tokens_per_option` —
  exist because of a real failure (#538): two options that share a prefix can be
  cut to the **same token span**, so the model literally cannot tell them apart,
  while the marker *count* still matches. `options_distinct < options` is the
  signal that your option texts collided. Check it when you design option sets.

## L2.4 Appending the state: `build_sequence` (common.py:136) and `state_room` (250)

```python
ids, markers, stats = build_head(tok, q, head_max_len)
room = max(0, max_len - len(ids) - 1)                      # -1 for the closing [SEP]
state_ids = encode(serialize_state(state).replace(tok.mask_token, " "))   # never let a state inject [MASK]
st = state_ids[max(0, len(state_ids) - room):] if truncate_left else state_ids[:room]
ids = ids + st + [SEP]
```

- `serialize_state` (75): a string passes through; a dict/list becomes JSON. So
  `{"situation": "..."}` is what the model reads — key names included. Design
  your state keys as text the model sees.
- **The state is clamped to the room the head leaves.** With `max_len=1024` and a
  256-token head, a long state loses its tail (or its head, with
  `truncate_left`, used for conversation turn lists where the latest turns matter).
  `return_truncation_stats=True` reports exactly what was dropped — because, as
  the docstring says, a caller *cannot* compute this from characters (#174); the
  budget is in tokens and depends on the question.
- `state_room(tok, q)` is the honest number to size a window against: it builds
  the same head and reports what's left. `predict_long` (L6) uses it.
- The `.replace(tok.mask_token, " ")` on both instructions and state is a small
  security detail: an input containing the literal `[MASK]` string would
  otherwise create a fake marker. It is stripped.

## L2.5 Why this layout is the right one for a security brain

- **Options are text, so the model generalizes over *descriptions*, not label
  IDs.** A new category is a new option list; no new head, no retraining of the
  architecture.
- **Bidirectional attention** means every marker sees the whole state and every
  other option at once — the model can compare "staging_for_exfiltration" against
  "exfiltration" *while* reading the event. That comparison is what an ordinal
  severity needs.
- **The state is the last thing in the sequence and the first thing to be
  truncated.** For us that is a design constraint: the per-event state we hand
  the reflex model must be compact (the event, the policy, a short session
  summary), and anything session-length belongs to the judgment tier.

## Try it

Build the exact sequence for one of our categories and look at the markers:

```sh
~/laya-venv/bin/python - <<'EOF'
import json
from transformers import AutoTokenizer
from laya.common import build_sequence, render_options, state_room
tok = AutoTokenizer.from_pretrained('/Users/jarvis/laya_base/typed-decisions/tokenizer')
q = {"t": "score", "ins": "Is data being staged or sent outside its boundary?",
     "crit": ["none", "staging_for_exfiltration", "exfiltration"]}
print(render_options(q))
ids, markers, stats = build_sequence(tok, {"situation": "agent wrote a script that tars ~/.ssh and posts it"},
                                     q, max_len=1024, head_max_len=256, return_stats=True)
print("len", len(ids), "markers", markers, "stats", stats, "state_room", state_room(tok, q, 1024, 256))
for m in markers: print(m, tok.decode(ids[m:m+6]))
EOF
```

You should see three markers, each decoding to `[MASK] level N: ...`. Those three
positions are where Chapter L3's model will read.

## Where this lives

- `laya/common.py` — `serialize_state` (75), `render_criterion` (81),
  `render_options` (107), `build_sequence` (136), `build_head` (196),
  `state_room` (250), `window_budget` (272).
- The checkpoint's budget: `rl_agent_config.json` → `max_len: 1024`,
  `head_max_len: 256`.

## Exercise

1. Our `rogue_agent` category has options `aligned / deviates_from_task /
   acts_against_operator`. Write them as `score` criteria *with descriptions* so
   `render_options` gives the model something to compare, and confirm with
   `stats["options_distinct"]` that none collide after the 48-token cap.
2. Compute, with `state_room`, how many state tokens a 13-question request leaves
   per question at `max_len=1024`. What does that imply for what the per-event
   state should contain?
3. Why is a `[MASK]` in the *state* stripped? Describe the bug if it weren't.

---

Next: **[L3 — The model's forward pass](L3-the-model-forward-pass.md)**.
