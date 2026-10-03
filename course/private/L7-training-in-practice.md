# L7 — Training in practice

> **Laya track, chapter 7 of 10.** Goal: run a fine-tune on this machine and
> know what every stage of the upstream trainer does to your data — the item
> cache, the gold contract, the calibration split, the checkpoint layout — and
> what our feeder (`models/laya_feed.py`) does to put *our* rows into it. The
> objective itself (the reward and the loss step) is left to the source:
> `common.py:604–650` and the trainer's step at
> `laya_finetune_typed_decisions_mps.py` ~300–337. Read those two spans yourself
> and answer the exercise questions at the end — that is deliberate.

## L7.1 The trainer, stage by stage

The upstream Apple-Silicon script
(`notebooks/laya_finetune_typed_decisions_mps.py`, a copy sits in this
session's scratchpad) is the whole loop. Its stages, in order:

1. **`prepare_model(model_dir)`** — `snapshot_download("convaiinnovations/laya")`
   if `model.safetensors` is missing, then `_fix_tokenizer_config`. Pass
   `--model-dir ~/laya_base/typed-decisions` to start from the decision-tuned
   checkpoint rather than the raw English one (we did).
2. **`prepare_items(model_dir, items_path)`** — reads `rl_agent_config.json`
   (`max_len`, `head_max_len`), downloads the public dataset
   (`DATASET_ID = "LocalLLaMA/typed-decisions"`), and for every row turns each
   (state, question, gold) into a **training item** via
   `build_training_item`, then `torch.save(items, train_items.pt)` next to a
   `.meta.json` cache key. **If `train_items.pt` already exists with no
   `.meta.json`, it is used as a "legacy cache" and nothing is downloaded** —
   that is the hook our feeder uses to train on our rows instead.
3. **`train(...)`** — loads cfg + tokenizer + model (`build_model` +
   `load_state_dict(strict=True)` + `.float()`), enables gradient checkpointing
   on the encoder and head, shuffles items with a fixed seed, and **holds out
   `min(--calib-max, len(items)//10)` items for calibration**; the rest train.
   AdamW with two learning rates — encoder params 2.5e-5, head params 1e-4 —
   weight decay 0.01, cosine schedule to 1e-6, gradient clip 1.0, micro-batch ×
   grad-accum. Per epoch it writes `checkpoint_latest/`.
4. **Temperature calibration** — runs the calibration items, groups logits by
   question type, fits one temperature per type with L-BFGS
   (`fit_temperature`; <10 samples → 1.0, empty group → 1.2).
5. **`save_checkpoint(..., final=True)`** — writes `model.safetensors`,
   `rl_agent_config.json` (now carrying the fitted `temperature`), `tokenizer/`,
   `encoder/`, `checkpoint_meta.json`. The output dir is a loadable checkpoint:
   `laya.load("<output_dir>")`.

CLI: `--epochs` (4) `--micro-batch` (2) `--grad-accum` (16) `--calib-max` (400)
`--device auto|mps|cpu` `--items` `--force-preprocess` `--no-checkpointing`.

## L7.2 The gold contract: `build_training_item`

This function (in the trainer, importing `build_sequence`/`render_options` from
`laya.common`) is the only place the *data format* is defined, so read it
exactly:

```python
qtype = question["type"]; criteria = question.get("criteria", {})
if qtype == "choice":  target = [gold["probabilities"].get(k, 0.0) for k in criteria.keys()]
elif qtype == "noul":  target = [gold["probabilities"].get("false", .5), gold["probabilities"].get("true", .5)]
elif qtype == "score": n = len(criteria) if isinstance(criteria, list) else 4
                       target = [gold["probabilities"].get(str(i), 0.0) for i in range(n)]
target = normalized(target)  (or uniform if all zero)
label  = argmax(target)
sequence, markers = build_sequence(tok, state, {"t": qtype, "ins": question["instructions"], "crit": criteria}, max_len, head_max_len)
if len(markers) != n_options: return None            # a question whose options got cut: skipped
return {"ids": sequence, "markers": markers, "qtype": QTYPES[qtype], "target": target, "label": label}
```

Three consequences:

- **Gold is a probability distribution, not a label.** A hard label is one-hot:
  `{"probabilities": {"2": 1.0}}`. Soft targets (e.g. two annotators disagreeing)
  are allowed and used as-is — the objective supports them.
- **For `score`, criteria must be a list** and the gold keys are the string
  indices `"0".."k-1"` — i.e. the **rank**. This is why our schema's
  benign→severe option order *is* the label.
- **Items whose marker count ≠ option count are dropped**, which happens when the
  head budget cuts options (L2). Our feeder reports `skipped` so you notice.

## L7.3 Our feeder: `models/laya_feed.py`

The feeder builds the same item cache from our rows and writes it **without a
`.meta.json`**, so the trainer takes the legacy-cache path and never fetches the
public set:

- Source 1: `models/misses/misses.jsonl` — oracle-confirmed rows
  `{category, state, label, ...}` → one `score` question per row with
  `criteria = OPTIONS[category]` (a list, ordered) and
  `gold = {"probabilities": {str(rank): 1.0}}`.
- Source 2 (`--rows`): any JSONL already in Laya shape (`state` / `questions` /
  `gold` as JSON strings) — exported pilot traces.
- It prints items per category and per source, and warns when there are fewer
  than 10 items (the calibration split would be empty).
- `--dump-rows` also writes the rows in dataset shape so they can be inspected
  or reused.

```sh
~/laya-venv/bin/python models/laya_feed.py \
  --model-dir ~/laya_base/typed-decisions \
  --out models/data/laya_v1/train_items.pt --dump-rows models/data/laya_v1/rows.jsonl
~/laya-venv/bin/python <scratchpad>/laya_finetune_typed_decisions_mps.py \
  --model-dir ~/laya_base/typed-decisions --output-dir ~/laya_v1_out \
  --items models/data/laya_v1/train_items.pt --epochs 2 --micro-batch 1 --grad-accum 2 --device mps
```

## L7.4 What happened when we ran it (measured, 2026-10-03)

Apple M5, 16 GB, MPS, 9 rows (4 oracle + 5 seed), from `typed-decisions`:

- `Training items: 9; calibration items: 0` — `9 // 10 = 0`, so **no
  calibration rows**; temperatures defaulted to `[1.2, 1.2, 1.2]`.
- Epoch 1 avg loss **1.018**, epoch 2 **0.370**; minutes; ~9 GB peak (weights
  + grads + AdamW states for 421M params fp32, plus activations at micro-batch 1).
- Evaluated with `models/laya_eval.py` (L8): base → v1 **4/9 → 9/9**, mean
  P(gold) **0.42 → 0.85**, shuffled-context delta **+0.22 → +0.56**.

The honest label, which is also in `ROSTER.md`: **a smoke test on the training
rows, not a benchmark** — no held-out set, no calibration. It proves the
pipeline. Real numbers need: ≥10 rows for any calibration at all; a few hundred
for a held-out test set; and, for the question that matters, **held-out attack
families** (L8).

## L7.5 Hardware notes

- Full fine-tune of 421M params in fp32 with AdamW: ~1.7 GB weights + ~1.7 GB
  grads + ~3.4 GB optimizer states + activations ≈ **8–9 GB** — fits a 16 GB
  Mac with `--micro-batch 1`. `gradient_checkpointing` (on by default) is what
  keeps activations small.
- CPU (`--device cpu`) works but is slow; a 9 GB VM is tight. The 322M
  multilingual checkpoint is the lighter fallback.
- The upstream Kaggle notebook targets 2×T4; the same loop, more memory.

## Where this lives

- Trainer: `laya_finetune_typed_decisions_mps.py` (`prepare_model` 49,
  `build_training_item` 58, `prepare_items` 103, `collate` 169,
  `fit_temperature` 198, `save_checkpoint` 221, `train` 237, `main` 371).
- Objective (read it yourself): `laya/common.py` — `proper_reward` (604),
  `td_lambda_targets` (633); the trainer's loss step (~300–337).
- Ours: `models/laya_feed.py`, `models/schema.py`, `models/misses/misses.jsonl`,
  `models/TRAINING-LOOP.md` (what may become a training row, and what may not).

## Exercise (the objective — from the source, in your own words)

1. Open `proper_reward`. Name the three scoring rules it combines, say which
   question type gets the third one and why an *ordinal* question needs it.
2. In the trainer's step, the logits are perturbed several times with Gaussian
   noise before being scored. Explain what quantity is being estimated by
   scoring the perturbations and normalizing across them, and why the
   perturbation scale shrinks across epochs.
3. There are two loss terms added together. State what each one anchors, and
   what would go wrong if either were removed.
4. Why does the trainer hold out `len(items)//10` for calibration *after*
   training rather than fitting temperatures on the training items?

---

Next: **[L8 — Evaluation](L8-evaluation.md)**.
