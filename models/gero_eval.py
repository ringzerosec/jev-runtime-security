#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Evaluate a Gero-style branch scorer (Qwen3ForSequenceClassification, num_labels=1)
on our labelled rows, with the same metrics as laya_eval.py so the two are comparable.

Gero scores each option as its own sequence:
    <|im_start|>system\n{SYSTEM}<|im_end|>\n<|im_start|>user\n<State>: {state}\n
    <Question>: {instructions}\n<Option>: {option}<|im_end|>
and reads one scalar from the final token; softmax across the options. Running
each option as a full sequence is "mathematically the same" as the shared-prefix
branch trick (model card), only slower — fine for an eval.

Reports accuracy, mean P(gold), the SHUFFLED-CONTEXT CONTROL (bench/README.md),
and selective accuracy at a threshold (promised vs achieved) so the calibration
claim can be checked once there are enough rows to mean anything.

Usage:
  ~/laya-venv/bin/python gero_eval.py --model vixhal-baraiya/Gero-4B --label gero
  ~/laya-venv/bin/python gero_eval.py --model vixhal-baraiya/Gero-4B --device cpu --show-raw
"""
import argparse, json, time
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

HERE = Path(__file__).resolve().parent
SYSTEM = "Judge how well the Option answers the Question, given the State."


def load_rows(path):
    rows = []
    for line in open(path):
        line = line.strip()
        if line:
            r = json.loads(line)
            rows.append({"state": json.loads(r["state"]), "questions": json.loads(r["questions"]),
                         "gold": json.loads(r["gold"])})
    return rows


def gold_rank(gold_q):
    probs = gold_q["probabilities"]
    return int(max(probs, key=lambda k: probs[k]))


def render(state, instructions, option):
    if not isinstance(state, str):
        state = json.dumps(state, ensure_ascii=False)
    return ("<|im_start|>system\n" + SYSTEM + "<|im_end|>\n"
            "<|im_start|>user\n<State>: " + state + "\n<Question>: " + instructions +
            "\n<Option>: " + option + "<|im_end|>")


@torch.no_grad()
def score_options(model, tok, device, state, instructions, options):
    texts = [render(state, instructions, o) for o in options]
    enc = tok(texts, return_tensors="pt", padding=True, add_special_tokens=False).to(device)
    logits = model(**enc).logits.squeeze(-1).float()
    probs = torch.softmax(logits, dim=0)
    return [float(p) for p in probs]


def run(model, tok, device, rows, shuffled=False):
    n = len(rows)
    hits, pgold, records = 0, 0.0, []
    for i, row in enumerate(rows):
        state = rows[(i + 1) % n]["state"] if shuffled else row["state"]
        for qid, q in row["questions"].items():
            opts = q["criteria"] if isinstance(q["criteria"], list) else list(q["criteria"].keys())
            probs = score_options(model, tok, device, state, q["instructions"], opts)
            pred = max(range(len(opts)), key=lambda k: probs[k])
            g = gold_rank(row["gold"][qid])
            hits += int(pred == g)
            pgold += probs[g]
            records.append({"qid": qid, "pred": pred, "gold": g, "probs": probs, "conf": probs[pred]})
    total = len(records)
    return hits / total, pgold / total, records


def selective(records, thr):
    hi = [r for r in records if r["conf"] >= thr]
    if not hi:
        return {"coverage": 0.0, "accuracy": None, "promised": None}
    return {"coverage": len(hi) / len(records),
            "accuracy": sum(r["pred"] == r["gold"] for r in hi) / len(hi),
            "promised": sum(r["conf"] for r in hi) / len(hi)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="vixhal-baraiya/Gero-4B")
    ap.add_argument("--rows", default=str(HERE / "data" / "laya_v1" / "rows.jsonl"))
    ap.add_argument("--label", default="gero")
    ap.add_argument("--device", default="mps" if torch.backends.mps.is_available() else "cpu")
    ap.add_argument("--threshold", type=float, default=0.9)
    ap.add_argument("--show-raw", action="store_true")
    a = ap.parse_args()

    rows = load_rows(a.rows)
    t0 = time.time()
    tok = AutoTokenizer.from_pretrained(a.model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tok.padding_side = "right"  # Qwen3ForSequenceClassification reads the last non-pad token
    dtype = torch.float16 if a.device == "mps" else torch.bfloat16
    model = AutoModelForSequenceClassification.from_pretrained(a.model, torch_dtype=dtype).eval().to(a.device)
    model.config.pad_token_id = tok.pad_token_id
    print(f"[{a.label}] loaded {a.model} on {a.device} in {time.time()-t0:.0f}s; {len(rows)} rows")

    t1 = time.time()
    acc, pg, recs = run(model, tok, a.device, rows)
    per_row = (time.time() - t1) / max(1, len(recs))
    sacc, spg, _ = run(model, tok, a.device, rows, shuffled=True)
    sel = selective(recs, a.threshold)

    print(f"[{a.label}] accuracy      {acc:.3f}   mean P(gold) {pg:.3f}   ({per_row*1000:.0f} ms/question)")
    print(f"[{a.label}] shuffled ctx  {sacc:.3f}   mean P(gold) {spg:.3f}   delta real-shuffled {acc-sacc:+.3f}")
    print(f"[{a.label}] selective@{a.threshold}: coverage {sel['coverage']:.2f}  accuracy {sel['accuracy']}  promised {sel['promised']}")
    if a.show_raw:
        for r in recs:
            print(f"  {r['qid']:<24} gold {r['gold']} pred {r['pred']}  probs {[round(p,3) for p in r['probs']]}")


if __name__ == "__main__":
    main()
