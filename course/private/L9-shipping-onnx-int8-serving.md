# L9 — Shipping: ONNX, int8, serving

> **Laya track, chapter 9 of 10.** Goal: take a fine-tuned checkpoint and turn
> it into the artifact that actually runs on an endpoint — a single int8 ONNX
> file — and know the runtime that executes it, the GPU fast path, and the HTTP
> surface. Everything here was run on this machine; the numbers are measured.

## L9.1 Why export at all

`laya.load()` + PyTorch is the development path: a Python process, torch, the
full fp32 graph. The endpoint path has different rules — no Python stack
required, no network, small footprint, predictable latency on CPU. ONNX +
onnxruntime gives that: a static graph, dynamic quantization to int8, a C++
runtime with a Python/TS/Rust binding. For the sealed sandbox (`ROSTER.md`,
"Serving") this is the *only* path.

## L9.2 `scripts/export_onnx.py`

```sh
~/laya-venv/bin/python export_onnx.py --model ~/laya_v1_out \
    --output ~/laya_v1_out/laya_v1.onnx --quantize [--per-channel]
```

What it does (`export_to_onnx`, line 57; `quantize_model`, 8):

1. Loads the PyTorch `Agent` from the checkpoint dir.
2. Builds dummy inputs and calls **`torch.onnx.export`** with **dynamic
   shapes** for `batch_size`, `seq_len`, `num_markers`. Under torch ≥ 2.x this is
   the dynamo-based exporter (`torch.export`, then "translate the graph into
   ONNX", then an optimize pass — you saw those four ✅ lines).
3. Writes **`laya_v1.onnx`** (the graph, ~3 MB) **plus `laya_v1.onnx.data`**
   (the fp32 weights, ~1.6 GB) — large models are written with *external data*.
4. With `--quantize`: `onnxruntime.quantization.quantize_dynamic(…,
   op_types_to_quantize=["MatMul"])` — **weight-only int8** on the MatMuls,
   dynamic activation quantization at run time, so **no calibration dataset is
   needed**. Output: **`laya_v1.int8.onnx`**, named by `int8_output_path` (51).

Two things that bit us, so you don't repeat them:

- The dynamo exporter needs **`onnxscript`** (and `onnx`); without it the export
  dies with `ModuleNotFoundError: No module named 'onnxscript'`. Install both.
- Why the export works at *any* sequence length: L3's
  `_DynamicMultiheadAttention`. The stock attention bakes the traced length into
  the graph; the replacement uses constant-shape ops so `seq_len` stays
  dynamic. This is the single most important "shipping" decision inside the
  model code.

## L9.3 The artifact, measured (Apple M5 CPU, onnxruntime, 2026-10-03)

| | size | self-contained? |
|---|---|---|
| `laya_v1.onnx` + `.onnx.data` (fp32) | 3 MB + 1,607 MB | no (two files) |
| **`laya_v1.int8.onnx`** | **571 MB** | **yes — one file** |

Why 571 MB and not ~421 MB (421M × 1 byte): only the **MatMul weights** are
int8; embeddings, LayerNorms, the type embedding, the scorer/act-head biases and
every non-MatMul tensor stay fp32, and the graph carries them. Still a single
file under 600 MB.

**Behaviour:** on item 0 of our set the int8 graph produced probabilities
`[0.065, 0.378, 0.557]` → argmax 2 = gold; the fp32 PyTorch model gave 0.599 on
the same option. Same decision, small quantization drift.
**Latency:** **~160 ms median (152 ms min)** for a single 68-token row,
batch 1, CPU. That is the on-device number — hundreds of milliseconds, not
seconds — and in precompute-then-bit (L10) the kernel never waits on it.

Inputs and outputs of the graph (read them from the session, never assume):

```
inputs : input_ids[b,L]  attention_mask[b,L]  marker_pos[b,K]  marker_mask[b,K]  qtype[b]
outputs: logits[b,K]     act_logits[b,n_act]
```

These are exactly `collate_items`' tensors (L2/L3), so the same preprocessing
feeds both runtimes.

## L9.4 `ONNXAgent` (onnx_agent.py)

`ONNXAgent` (38) is the drop-in runtime for the exported graph: same
`predict`/`predict_batch` surface, same `_decode_answers` semantics — it applies
the **same temperatures** (per type + per bucket, clamped) and the same
`resolve_lang_temperatures` so "both promise the same confidences," accepts the
same `calibration` payload, and carries the same hooks. The point: *calibration
and gating are runtime behaviour, not weights*, so they survive the export.
Choose the provider (`CPUExecutionProvider`, CoreML, CUDA) per host.

## L9.5 The GPU fast path (`fast.py`, `tl_kernels.py`) and `compile`

For a GPU server (not the endpoint): `laya.load(..., fast=True)` installs
**TileLang** fused kernels — fused GEMM, fused attention, CUDA graphs
(`pip install laya[fast]`) — which is where the headline **~33 ms** figure comes
from. `compile=True` uses `torch.compile` instead. Neither applies to the
int8-CPU endpoint path; they're for the judgment tier's box or a batch scorer.

## L9.6 Serving: `serve.py` and `/v1/systemone`

`laya-serve` (`pip install laya[serve]`) exposes an HTTP server whose main
endpoint is **`/v1/systemone` — compatible with TypeSafe's System One (Jev)
clients**, so an existing Jev integration can be pointed at a self-hosted Laya
unchanged. Worth reading in `serve.py`:

- `_project_jev_strict` (128) — projects Laya's richer answer into the strict Jev
  response shape when a client asks for it.
- Request limits that a public endpoint needs: `_check_request_limits` /
  `_check_batch_limits` (536, 597) on state length and question count,
  `_resolve_max_token_budget` (213), `_resolve_max_concurrent` (201),
  `_validate_min_confidence` (290), surrogate-safety checks (`_has_lone_surrogate`,
  621), a thread limit (`_apply_thread_limit`, 690), and `/health` exposing the
  OOM-fallback counters from L6.
- `build_router` / `create_app` (709, 737): a `Router` behind the app, so one
  server can hold several checkpoints (`max_loaded`) and route by language.

This is also the contract our `checks/src/registry.rs` `HttpEndpoint` speaks
(L10): Laya, Kev, or hosted Jev are interchangeable behind it.

## L9.7 `router.py`

`Router(models=…, max_loaded=2, default="english")` lazily loads checkpoints
and sends each request to the right one — by explicit model, by alias
(`resolve_model_spec`, the same table `load()` uses), or by detected language
(`lang.py`). It keeps two resident by default; for the sealed endpoint set
`max_loaded=1` and ship one checkpoint (`ROSTER.md`).

## Try it

```sh
cd ~/laya-venv && export PATH="$HOME/.local/bin:$PATH"
uv pip install --python ~/laya-venv/bin/python onnxscript onnx onnxruntime
~/laya-venv/bin/python <scratchpad>/export_onnx.py --model ~/laya_v1_out --output ~/laya_v1_out/laya_v1.onnx --quantize
~/laya-venv/bin/python - <<'EOF'
import onnxruntime as ort, torch, numpy as np, time
from pathlib import Path
import sys; sys.path.insert(0, "<scratchpad>")
from laya_ft_mps import collate
from transformers import AutoTokenizer
out = Path.home()/"laya_v1_out"; tok = AutoTokenizer.from_pretrained(out/"tokenizer")
items = torch.load("/Users/jarvis/rgs/rgs-linux-oss/models/data/laya_v1/train_items.pt", weights_only=False)
ids, att, pos, mask, target, qtype = collate([items[0]], tok.pad_token_id)
s = ort.InferenceSession(str(out/"laya_v1.int8.onnx"), providers=["CPUExecutionProvider"])
feed = {"input_ids": ids.numpy(), "attention_mask": att.numpy(), "marker_pos": pos.numpy(), "marker_mask": mask.numpy(), "qtype": qtype.numpy()}
s.run(None, feed); t=time.perf_counter(); r=s.run(None, feed); print("ms", (time.perf_counter()-t)*1000)
z = r[0][0,:len(items[0]["markers"])]; p=np.exp(z-z.max()); print("probs", (p/p.sum()).round(3), "gold", items[0]["label"])
EOF
```

## Where this lives

- `scripts/export_onnx.py` (upstream) — `quantize_model` (8),
  `int8_output_path` (51), `export_to_onnx` (57), CLI (130).
- `laya/onnx_agent.py` — `ONNXAgent` (38). `laya/fast.py`, `laya/tl_kernels.py`.
- `laya/serve.py` — `_project_jev_strict` (128), limits (201–621),
  `build_router` (709), `create_app` (737), `main` (1081). `laya/router.py`.
- `laya/common.py` — `_DynamicMultiheadAttention` (403): why the export is
  shape-dynamic.

## Exercise

1. Explain why the int8 file is 571 MB rather than ~421 MB, and which tensors
   you would quantize next if you had to get under 400 MB — and what you'd have
   to re-measure afterwards.
2. The int8 model put 0.557 on the gold option where fp32 put 0.599. Is the
   *calibration* still valid after quantization? What would you do before
   trusting a threshold on the int8 artifact?
3. Why can hosted Jev, self-hosted Kev, and Laya all sit behind the same
   `HttpEndpoint`? Name the contract and the field that makes "tighten-only"
   possible across all three.

---

Next: **[L10 — The bridge to Ring Zero](L10-the-bridge-to-ring-zero.md)**.
