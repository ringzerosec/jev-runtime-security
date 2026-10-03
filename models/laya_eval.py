#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Evaluate a Laya checkpoint on our labelled rows — the "test" half of the loop.

Reports, per bench/README.md Axis 2:
  * accuracy of the predicted severity rank vs the gold rank
  * the calibrated probability the model put on the gold option (mean)
  * the SHUFFLED-CONTEXT CONTROL: score each row's question against a
    DIFFERENT row's state. A model that does as well here is reading option
    priors, not the situation, and does not ship.

With a handful of rows this is a smoke signal, not a benchmark — it proves the
loop (feed -> train -> calibrate -> predict) end to end. Numbers become real
when the review queue / pilots fill rows.jsonl.

Usage:
  ~/laya-venv/bin/python laya_eval.py --model ~/laya_base/typed-decisions --label base
  ~/laya-venv/bin/python laya_eval.py --model ~/laya_v1_out --label v1 --show-raw
"""
import argparse, json
from pathlib import Path

HERE = Path(__file__).resolve().parent


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


def predicted(result_q, n_levels):
    """Be defensive about the result schema: prefer a distribution, else a level."""
    if not isinstance(result_q, dict):
        return None, None
    dist = None
    for k in ("probabilities", "distribution", "probs", "scores"):
        v = result_q.get(k)
        if isinstance(v, (list, tuple)) and len(v) == n_levels:
            dist = [float(x) for x in v]; break
        if isinstance(v, dict) and len(v) >= n_levels:
            try: dist = [float(v[str(i)]) for i in range(n_levels)]
            except Exception: dist = [float(x) for x in v.values()][:n_levels]
            break
    if dist is not None:
        return max(range(n_levels), key=lambda i: dist[i]), dist
    for k in ("score", "level", "answer", "choice", "expected"):
        if k in result_q:
            try: return int(round(float(result_q[k]))), None
            except Exception: pass
    return None, None


def run(agent, rows, shuffle=False):
    n = len(rows); correct = 0; gold_p = []; raw_first = None
    for i, r in enumerate(rows):
        state = rows[(i + 1) % n]["state"] if shuffle else r["state"]
        res = agent.predict(state, r["questions"])
        if raw_first is None:
            raw_first = res
        for qid, q in r["questions"].items():
            n_levels = len(q["criteria"]); g = gold_rank(r["gold"][qid])
            # Laya nests per-question results under "answers"
            answers = res.get("answers", res) if isinstance(res, dict) else {}
            rq = answers.get(qid) if isinstance(answers, dict) else None
            p, dist = predicted(rq, n_levels)
            if p == g: correct += 1
            if dist: gold_p.append(dist[g])
    acc = correct / max(1, n)
    mgp = sum(gold_p) / len(gold_p) if gold_p else float("nan")
    return acc, mgp, raw_first


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--rows", default=str(HERE / "data" / "laya_v1" / "rows.jsonl"))
    ap.add_argument("--device", default="mps")
    ap.add_argument("--label", default="model")
    ap.add_argument("--show-raw", action="store_true")
    args = ap.parse_args()

    import laya
    agent = laya.load(str(Path(args.model).expanduser()), device=args.device)
    rows = load_rows(args.rows)

    acc, mgp, raw = run(agent, rows)
    sacc, smgp, _ = run(agent, rows, shuffle=True)
    print(f"[{args.label}] rows={len(rows)}")
    print(f"  accuracy (rank == gold):        {acc:.3f}")
    print(f"  mean P(gold option):            {mgp:.3f}")
    print(f"  SHUFFLED-context accuracy:      {sacc:.3f}   (if ~= real accuracy -> reading priors; does not ship)")
    print(f"  shuffled mean P(gold):          {smgp:.3f}")
    print(f"  delta real - shuffled:          {acc - sacc:+.3f}")
    if args.show_raw:
        print("  raw first result:", json.dumps(raw, default=str)[:600])


if __name__ == "__main__":
    main()
