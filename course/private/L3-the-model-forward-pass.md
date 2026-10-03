# L3 — The model's forward pass

> **Laya track, chapter 3 of 10.** Goal: read `DecisionModel.forward` and be
> able to narrate, tensor by tensor, how a batch of sequences from L2 becomes
> one logit per option — plus the second output almost everyone misses: the
> **act head** that decides whether to answer at all. Read `common.py` 472–602
> alongside this.

## L3.1 The parts (`DecisionModel.__init__`, common.py:472)

```python
self.encoder   = encoder                       # ModernBERT-large (421M) — the backbone
self.head      = nn.TransformerEncoder(layer, head_layers)   # 2 extra layers on top (head_layers=2)
self.type_emb  = nn.Embedding(3, d)            # one vector per question type: choice/score/noul
self.scorer    = Sequential(LayerNorm(d), Linear(d,d), GELU(), Linear(d,1))   # hidden -> 1 logit
self.act_head  = Sequential(Linear(d+4, 256), GELU(), Linear(256, n_act))     # answer vs escalate
self.register_buffer("temperature", torch.ones(3))   # per-type temperature, filled by calibration
```

`n_act = len(cfg["act_costs"]) + 1` (`build_model`, 578): with
`act_costs: {escalate: 0.5}` that is **2 actions — answer, or escalate.**

A detail worth knowing: the head's attention layer is swapped for
`_DynamicMultiheadAttention` (403). Same parameters, same maths — but the stock
module reshapes with sizes captured at trace time, so an ONNX export from a short
dummy input would only run at that length. The replacement uses constant-shape
ops so the exported graph keeps `seq_len` dynamic. This is why L9's export works
at any length. (Also: with `no_init=True` the head is materialised on the `meta`
device and filled by `load_state_dict` — no RNG draw, no wasted init.)

## L3.2 The forward pass, line by line (common.py:498)

```python
h = self.encoder(input_ids, attention_mask).last_hidden_state   # [B, L, d]
h = h + self.type_emb(qtype)[:, None, :]                        # tell every position the question TYPE
for layer in self.head.layers:                                  # 2 more bidirectional layers
    h = layer(h, src_key_padding_mask=~attention_mask.bool())
idx = marker_pos.clamp(min=0)[:, :, None].expand(-1, -1, d)
m = torch.gather(h, 1, idx)                                     # [B, K, d]: the hidden state AT each marker
logits = self.scorer(m).squeeze(-1).float()                     # [B, K]: one logit per option
logits = logits.masked_fill(~marker_mask, -1e4)                 # padded option slots -> -inf
```

That is the entire decision: **gather the hidden vector at each `[MASK]`, run a
small MLP, get one number per option.** Softmax over those K numbers is the
distribution. There is no decoding, no sampling, no loop.

Three things to internalize:

- **`type_emb` is how one scorer serves three question types.** The same hidden
  state is nudged by "this is a `score` question" before the head layers, so the
  head can learn that `score` options are ordered and `noul` options are a pair.
- **The gather is why markers matter.** `marker_pos` from L2 is literally an index
  into the sequence. Shift a marker by one token and you score the wrong thing.
- **`-1e4` not `-inf`** for padded slots keeps the softmax finite and the ONNX
  graph free of NaNs; `marker_mask` carries which slots are real.

## L3.3 The second output: the act head

Immediately after the logits, the model computes features *about its own
distribution* and feeds them to a second head:

```python
p    = softmax(logits.detach())                                 # detached: the act head doesn't train the scorer
k    = marker_mask.sum(-1).clamp(min=2)
ent  = -(p * log p).sum(-1) / log(k)                            # normalized entropy in [0,1]
top2 = p.topk(2).values
feats = stack([top2[:,0], top2[:,0] - top2[:,1], ent, k / 255.0])   # [B, 4]
pooled = h[:, 0]                                                # the [CLS] vector
act_logits = self.act_head(cat([pooled, feats]))                # [B, n_act]: answer vs escalate
return logits, act_logits
```

This is the paper's meta-learning module, made concrete: a tiny network looks at
*how peaked the answer is* (top-1, margin, entropy, how many options) plus a
summary of the input, and decides between **answering** and **escalating**. The
runtime surfaces it as `action.act_probability` (L6), and the config prices the
two mistakes asymmetrically — `act_costs: {escalate: 0.5}` versus
`cost_wrong_act: 3.0` — i.e. a wrong confident answer costs six times a
needless escalation. **That asymmetry is exactly the shape of our tiers:**
cheap to contain-and-review, expensive to be confidently wrong.

## L3.4 The temperature buffer

`temperature` is a 3-vector buffer (one per type) saved *inside the checkpoint*;
the runtime also carries a finer `temperature_by_options` map in
`rl_agent_config.json`. The forward pass does **not** apply it — raw logits come
out, and the runtime divides by the right temperature at decode time (L5). Keep
that separation in mind: the model produces evidence; calibration is applied
after, and can be re-fitted without touching weights.

## L3.5 The shipped config, decoded (`rl_agent_config.json`)

```
encoder: answerdotai/ModernBERT-large   head_layers: 2
max_len: 1024   head_max_len: 256   max_prefixes: 6
act_costs: {escalate: 0.5}   cost_wrong_act: 3.0
temperature: [1.015, 1.037, 1.058]            # choice, score, noul
temperature_by_options: {choice:2: 1.91, choice:3-5: 1.76, score:3-5: 1.25, noul:2: 1.98, choice:6-10: 1.00, choice:11+: 0.10}
training: {updates: 7313, epochs: 1, hours: 1.96}   fine_tuned: true
```

Note `choice:11+: 0.10` — a temperature *below* 1 **sharpens** rather than
softens, turning a 0.24 top probability into a published 0.99. L5 explains why
the runtime refuses to apply it (`TEMP_MIN = 0.5`) and why you saw a warning
about exactly this when we evaluated the base checkpoint.

## Try it

Run the forward pass by hand on the sequence from L2 and read the two outputs:

```sh
~/laya-venv/bin/python - <<'EOF'
import json, torch
from safetensors.torch import load_file
from transformers import AutoTokenizer
from laya.common import build_model, build_sequence, collate_items, QTYPES
d = '/Users/jarvis/laya_base/typed-decisions'
cfg = json.load(open(f'{d}/rl_agent_config.json'))
model = build_model(cfg, encoder_dir=f'{d}/encoder'); model.load_state_dict(load_file(f'{d}/model.safetensors'), strict=True); model.eval()
tok = AutoTokenizer.from_pretrained(f'{d}/tokenizer')
q = {"t":"score","ins":"Is data being staged or sent outside its boundary?","crit":["none","staging_for_exfiltration","exfiltration"]}
ids, markers = build_sequence(tok, {"situation":"agent wrote a script that tars ~/.ssh and posts it"}, q, 1024, 256)
b = collate_items([[{"ids":ids,"markers":markers,"qtype":QTYPES["score"]}]], tok.pad_token_id)
with torch.no_grad():
    logits, act = model(b["input_ids"], b["attention_mask"], b["marker_pos"], b["marker_mask"], b["qtype"])
print("option logits:", logits[0,:3].tolist()); print("probs:", torch.softmax(logits[0,:3],-1).tolist())
print("act (answer, escalate):", torch.softmax(act[0],-1).tolist())
EOF
```

## Where this lives

- `laya/common.py` — `_DynamicMultiheadAttention` (403), `DecisionModel` (472),
  `forward` (498), `build_model` (578), `_apply_rope_config` (546).
- `rl_agent_config.json` in any checkpoint dir — the architecture knobs and the
  fitted temperatures.

## Exercise

1. Narrate the forward pass for a batch of 2 sequences with 3 and 2 options
   respectively: give the shape of `h`, `m`, `logits`, `act_logits`, and say
   which logit entries are `-1e4` and why.
2. The act head's input includes `top1 - top2` and normalized entropy. Explain
   why each is a better "should I escalate?" signal than `top1` alone.
3. Why is the temperature *not* applied inside `forward`? Name one operational
   advantage of applying it at decode time.

---

Next: **[L4 — The objective: proper scoring rules and RLCD](L4-the-objective-proper-scoring-and-rlcd.md)**.
