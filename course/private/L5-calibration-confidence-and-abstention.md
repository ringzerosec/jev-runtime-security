# L5 — Calibration, confidence, and abstention

> **Laya track, chapter 5 of 10.** Goal: know exactly which number in a Laya
> answer you may put a threshold on, how temperatures are fitted and applied,
> why there is a separate temperature per *option count*, and what the model does
> when it is not sure. This chapter is the bridge between "the model emits a
> distribution" and "we can give a 0.95 real authority." Read `common.py`
> 651–730, `agent.py` `_decode_answers`, `calibrate.py`, and `confidence.py`.

## L5.1 Two confidences — only one is calibrated

Every answer carries two numbers that look alike and are not:

| Field | Definition | Calibrated? | Threshold on it? |
|---|---|---|---|
| `answer_confidence` | `max(p)` — probability mass on the reported answer (`answer_confidence`, common.py:664) | **Yes** — this is what temperature scaling fits and what every ECE figure measures | **Yes** |
| `confidence` | `1 − H(p)/log k` — normalized entropy (`confidence_from_probs`, 684) | **No** — "useful, but not calibrated" and it does not transfer across option counts | **No** |

The docstrings are unusually blunt about this, because the mistake is easy: the
entropy number is a different quantity on a different scale. `confidence.py`
refuses to ever report the entropy under the `answer_confidence` name "because
the name is what a caller filters on." For noul the two coincide (`max(p_true,
1−p_true)`), which is why both are returned on every type: so a caller can gate
across types on **one** number — `answer_confidence`.

The property you are buying: *of the answers returned at confidence c, about c
of them are right.* `answer_confidence`'s docstring states the condition under
which that holds — **only after temperatures are fitted and validated on
held-out data for this checkpoint and this option count.** It is not a free
property of the architecture.

## L5.2 Temperatures: one per type, then one per option-count bucket

Decoding (`agent.py` `_decode_answers`):

```python
k = len(items[j]["markers"]); qt = QTYPES[q["t"]]
t_scale = self.temperature_by_options.get(temp_bucket(qt, k), self.temperature[qt])
z = raw_logits / t_scale
p = softmax(z); p = unpermute_probs(p, q.get("option_order"))
```

`temp_bucket` (697) spells buckets as `"<type>:<size>"` with size ∈
`{2, 3-5, 6-10, 11+}`. The reason for buckets is issue #394: **one temperature
does not transfer across option counts.** A 2-option question and a 12-option
question with the same raw logit spread have very different natural confidence;
fitting one scalar makes one of them lie. So a checkpoint carries both a
per-type vector (`temperature: [choice, score, noul]`) and a per-bucket map, and
the bucket wins when present.

`clamp_temperature` (710) confines any temperature to `[TEMP_MIN=0.5,
TEMP_MAX=5.0]`. The comment above it is a case study: the shipped `choice:11+`
temperature is **0.1006** — below 1, which *sharpens* the logits ~10× — so a
0.24 top probability would be published as 0.99 and "a caller gating on
confidence is told a coin flip is a certainty." The runtime refuses to apply it
and warns. That is the `RuntimeWarning: this checkpoint ships invalid
temperatures … using choice:11+=0.10 -> 0.5` you saw when we evaluated the base
checkpoint in L7. A model that *sharpens* under calibration is a model whose
confidence you cannot use; the clamp is the guard.

## L5.3 How a temperature is fitted (the trainer, and `calibrate.py`)

The trainer (L7) holds out ~10% of items, runs the trained model on them, and
fits one temperature per type by minimizing NLL with L-BFGS over `log T`,
clamped to `[0.1, 10]` — `fit_temperature`; under 10 samples it returns 1.0 and
an empty group gets a default of 1.2. (That is why our 9-row smoke run reported
temperatures `[1.2, 1.2, 1.2]`: no calibration rows at all.)

`calibrate.py` is the production version of the same idea, per bucket:

- `fit_one_temperature(pairs, min_n)` (101) — one bucket's temperature from
  (logits, target) pairs, with a minimum sample count.
- `fit_temperature_map(records, compute_ece)` (250) — fits the per-type vector
  *and* the per-bucket map from calibration records; optionally reports ECE on a
  split (`_ece_split`, 196) so you see the before/after.
- `records_from_labeled(agent, pairs)` (444) — collects the raw per-option logits
  (via the same `_option_logits` slice the decoder uses, so "a fitted map sees the
  option width the decoder scales") from labelled examples.
- `calibration_payload` / `apply_calibration_payload` (485, 576) — serialize the
  fitted temperatures with a config identity, and install them on an `Agent` or
  `ONNXAgent` (`_install_temperatures`, 547) with a warning if the checkpoint
  identity doesn't match. `Agent.load_calibration(path)` is the entry point.

Calibration is therefore **data you can re-fit without touching weights** —
fit on your own held-out rows, ship the payload next to the checkpoint.

## L5.4 ECE — the number that says whether calibration is real

`ece_score(conf, correct, bins=15)` (651): bin answers by confidence, and
average `|mean confidence − accuracy|` per bin, weighted by bin mass. Zero means
"at every confidence level, that many were right." Laya reports **0.081**
post-temperature-scaling on its benchmark; the bar in `models/README.md` is
that *we* report it on *our* held-out rows, never inherit it.

## L5.5 Abstention: what happens when the model isn't sure

Two mechanisms, at two levels:

**The act head** (L3) emits `action.act_probability` — the model's own
"answer vs escalate" decision, trained under asymmetric costs (`escalate: 0.5`
vs `cost_wrong_act: 3.0`).

**The confidence gate** (`confidence.py`, pure Python, torch-free so the Router
and structured decisions can import it):

- `check_min_confidence(v)` (937) validates a threshold — a float in [0, 1] **or
  a per-bucket map** (`{"choice:3-5": 0.7, "score:3-5": 0.8, "default": 0.6}`),
  again because one threshold does not transfer across option counts (#394). Fit
  one with `calibrate.fit_abstention_thresholds(records, temperature,
  target_error)` (338), which selects a cut per bucket for a target error rate.
- `flag_low_confidence(results, min_confidence)` (982) marks
  `low_confidence: True` on answers whose `answer_confidence` falls below the
  bucket's threshold. The raw answer stays intact — the gate annotates, it never
  erases.
- `apply_confidence_gate` (1024) writes an explicit state onto every answer when
  a gate was configured: **`passed`**, **`abstained`**, or **`unevaluated`** (the
  gate ran but the answer carried no usable confidence — "reporting that as a
  pass is the same lie as reporting it as a flag"), plus `abstention_threshold`.
  With no `min_confidence` set it writes *nothing*, so the presence of the field
  is how a caller knows a gate ran.

Hold these three states next to our tiers: `passed` at high confidence →
enforce; `passed` at moderate → contain; `abstained` / `unevaluated` → review.
The gate is the mechanism; the tiers are the policy on top of it.

## Try it

```sh
~/laya-venv/bin/python - <<'EOF'
import laya, json
a = laya.load('/Users/jarvis/laya_v1_out', device='cpu')
q = {"exfil": {"type":"score","instructions":"Is data being staged or sent outside its boundary?",
               "criteria":["none","staging_for_exfiltration","exfiltration"]}}
r = a.predict({"situation":"agent wrote a script that tars ~/.ssh and posts it"}, q,
              min_confidence={"score:3-5": 0.8, "default": 0.6})
ans = r["answers"]["exfil"]
print({k: ans[k] for k in ("score","probabilities","confidence","answer_confidence","action",
                            "low_confidence","abstention","abstention_threshold") if k in ans})
print("temps:", a.temperature, a.temperature_by_options)
EOF
```

Compare `confidence` and `answer_confidence` on the same answer, and read the
`abstention` state the gate wrote.

## Where this lives

- `laya/common.py` — `ece_score` (651), `answer_confidence` (664),
  `confidence_from_probs` (684), `temp_bucket` (697), `TEMP_MIN/MAX` (706),
  `clamp_temperature` (710), `resolve_lang_temperatures` (728).
- `laya/agent.py` — `_decode_answers` (temperature applied at decode),
  `load_calibration` (1866).
- `laya/calibrate.py` — `fit_one_temperature` (101), `fit_temperature_map`
  (250), `fit_abstention_thresholds` (338), `fit_binning_map` (384),
  `records_from_labeled` (444), `calibration_payload` (485),
  `apply_calibration_payload` (576).
- `laya/confidence.py` — `check_min_confidence` (937), `flag_low_confidence`
  (982), `apply_confidence_gate` (1024), `GATE_*` states.

## Exercise

1. Which field do you threshold, and under what condition does "about c of the
   answers at c are right" actually hold? Quote the condition.
2. Explain why a temperature below 1 is dangerous and what the clamp does about
   the shipped `choice:11+` value. Then explain why a per-bucket temperature
   exists at all.
3. Design the `min_confidence` map for our 13 `score` questions (all `score:3-5`)
   and say what you would need to *fit* it rather than guess it.
4. Map `passed` / `abstained` / `unevaluated` onto enforce / contain / review,
   and name the one state a boolean flag could never have expressed.

---

Next: **[L6 — The runtime: load, predict, decide](L6-the-runtime-load-predict-decide.md)**.
