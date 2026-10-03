#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Feed our labelled rows into Laya's fine-tune loop.

Laya's Apple-Silicon trainer (notebooks/laya_finetune_typed_decisions_mps.py)
normally downloads the public typed-decisions dataset and caches tokenised
"items" to train_items.pt. This script builds that same cache from OUR rows
instead, so the trainer runs on the brain's data with `--items` and never
touches the public set.

Sources (both oracle-labelled; see TRAINING-LOOP.md):
  * misses/misses.jsonl — kernel- or human-confirmed rows: {category, state, label, ...}
  * --rows FILE.jsonl   — rows already in Laya shape: state / questions / gold
                          (JSON strings), e.g. exported pilot traces.

Mapping (schema.py): one `score` question per category; criteria = the
category's options in benign→severe order; gold = one-hot on the label's rank.
So the gold score IS the severity rank — tighten-only by construction.

Usage:
  ~/laya-venv/bin/python laya_feed.py --model-dir ~/laya_base/typed-decisions \
      --out data/laya_v1/train_items.pt --dump-rows data/laya_v1/rows.jsonl
"""
import argparse, json, os, sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from schema import OPTIONS, QUESTION  # noqa: E402


def load_misses(path):
    rows = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        m = json.loads(line)
        cat, label = m.get("category"), m.get("label")
        if cat not in OPTIONS or label not in OPTIONS[cat]:
            print(f"  skip {m.get('session_id')}: unknown category/label {cat}/{label}")
            continue
        rows.append({
            "state": {"situation": m["state"]},
            "questions": {cat: {"type": "score",
                                "criteria": list(OPTIONS[cat]),
                                "instructions": QUESTION[cat]}},
            "gold": {cat: {"probabilities": {str(OPTIONS[cat].index(label)): 1.0}}},
            "source": m.get("label_source", "oracle"),
        })
    return rows


def load_laya_rows(path):
    rows = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        rows.append({
            "state": json.loads(r["state"]) if isinstance(r["state"], str) else r["state"],
            "questions": json.loads(r["questions"]) if isinstance(r["questions"], str) else r["questions"],
            "gold": json.loads(r["gold"]) if isinstance(r["gold"], str) else r["gold"],
            "source": r.get("source", "rows"),
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", required=True, help="dir with rl_agent_config.json + tokenizer/")
    ap.add_argument("--misses", default=str(HERE / "misses" / "misses.jsonl"))
    ap.add_argument("--rows", default=None, help="extra JSONL already in Laya shape")
    ap.add_argument("--out", default=str(HERE / "data" / "laya_v1" / "train_items.pt"))
    ap.add_argument("--dump-rows", default=None, help="also write the rows in dataset shape")
    args = ap.parse_args()

    import torch
    from transformers import AutoTokenizer
    from laya.agent import _fix_tokenizer_config
    # the trainer's own item builder — import it from the script sitting next to the venv
    sys.path.insert(0, str(Path.home()))
    sys.path.insert(0, "/private/tmp/claude-501/-Users-jarvis-rgs/f4cbe26b-f922-4e58-beda-761db01217c0/scratchpad")
    from laya_ft_mps import build_training_item  # noqa: E402

    model_dir = Path(args.model_dir).expanduser().resolve()
    _fix_tokenizer_config(str(model_dir))
    cfg = json.load(open(model_dir / "rl_agent_config.json"))
    cfg = {**cfg, "max_len": cfg.get("max_len", 1024), "head_max_len": cfg.get("head_max_len", 256)}
    tokenizer = AutoTokenizer.from_pretrained(model_dir / "tokenizer")

    rows = load_misses(args.misses) if os.path.exists(args.misses) else []
    if args.rows:
        rows += load_laya_rows(args.rows)

    items, skipped, per_cat, per_src = [], 0, Counter(), Counter()
    for r in rows:
        for qid, q in r["questions"].items():
            if qid not in r["gold"]:
                continue
            it = build_training_item(tokenizer, cfg, r["state"], q, r["gold"][qid])
            if it is None:
                skipped += 1
                continue
            items.append(it)
            per_cat[qid] += 1
            per_src[r["source"]] += 1

    out = Path(args.out).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    torch.save(items, out)              # no .meta.json on purpose: trainer's "legacy cache" path
    if args.dump_rows:
        with open(args.dump_rows, "w") as f:
            for r in rows:
                f.write(json.dumps({"state": json.dumps(r["state"]),
                                    "questions": json.dumps(r["questions"]),
                                    "gold": json.dumps(r["gold"]),
                                    "source": r["source"]}) + "\n")

    print(f"items: {len(items)}  skipped: {skipped}  -> {out}")
    print("per category:", dict(per_cat))
    print("per source:  ", dict(per_src))
    n_calib = len(items) // 10
    if n_calib == 0:
        print("!! fewer than 10 items: the trainer's calibration split will be EMPTY — "
              "this is a loop smoke test, not a model. Add oracle-labelled rows.")
    else:
        print(f"trainer will hold out ~{n_calib} item(s) for temperature calibration")


if __name__ == "__main__":
    main()
