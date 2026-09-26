# Data governance and the model flywheel

> How Ring Zero earns a training-data advantage no one else can, **without ever
> becoming the breach it's meant to prevent.** For a security product, the data
> story is the trust story. This document is the contract, not marketing.

## 1. The flywheel (and where we actually are)

```
  deploy enforcement  ──►  it produces ground-truth traces  ──►  humans label
  denials (review queue)  ──►  DLP-redact  ──►  train  ──►  better models
  ──►  more adoption  ──►  more deployments  ──►  (repeat, compounding)
```

**Where we are: at the start.** We have *no* training data yet
(`models/README.md`). What we have is the **position** to earn the best
cybersecurity training data on earth. This document is how we convert that
position into data **safely**, because doing it carelessly turns the moat into a
scandal.

## 2. Why the data, once earned, is unmatchable

- **Kernel ground truth.** Captured below the agent, at the syscall — it cannot be
  faked, spoofed, or evaded by the thing being observed. Others train on
  self-reported or public traces; we train on what actually crossed the boundary.
- **Attempt paired with outcome.** Every trace carries the enforcement result —
  *attempted-and-blocked* vs *completed*. Nobody else has "the agent tried X, the
  kernel refused, here is the full context."
- **Human-labelled denials.** The review queue turns each block into a labelled row.
- **Real agents, real environments** — production behaviour, not benchmark traces.

## 3. The gate: consent, tiered and explicit

No customer data enters any training process without an explicit, revocable
choice. Default is the most private tier. Tiers:

| Tier | What leaves the box | What it trains |
| --- | --- | --- |
| **0 — Off (default)** | nothing | nothing; product works fully, no contribution |
| **1 — Local only** | nothing | a **per-customer model** trained on their own data, on their infra; weights stay theirs |
| **2 — Aggregate signal** | privacy-safe *signals* only (see §5), never raw content | shared models, from derived features not content |
| **3 — Redacted corpus** | DLP-redacted, minimised trace rows under a DPA | shared/released models |

The product is fully functional at Tier 0. Contribution is a choice a customer
makes with their eyes open, per deployment, reversible at any time.

## 4. Redact before train — and this is why the DLP model matters twice

Nothing is written to a training corpus until it passes redaction. Two layers,
same floor-not-ceiling rule as enforcement:

1. **Deterministic redactor** (ships today) — the `[webhooks.redaction]` layer;
   pattern-based secret/PII stripping.
2. **DLP model** (the GLiNER-family model we're building) — catches secrets/PII
   the patterns miss (obfuscated keys, unpatterned PII). **Raise-only:** it can
   redact *more*, never *less* — a model miss still falls back to the patterns, so
   a miss never becomes a leak into training data.

Redaction is **verified, not assumed**: a row that cannot be fully redacted (the
redactor errors, or the DLP flags residual risk it can't resolve) is **dropped
from the corpus**, not shipped partially. Same posture as "if the redactor can't
be built, capture doesn't run" — fail closed on the data path.

## 5. Minimise: references and decisions, not content

Aligned with the OpenAI CISO guidance ("preserve the references and decision
metadata needed to review, minimise and protect content"):

- **Kept by default:** the *shape* — which boundary fired, the action class, the
  category, the decision, the outcome, timing, non-secret evidence fragments,
  `session_id`. This is what a model needs to learn "this pattern of behaviour is
  an exfiltration attempt."
- **Minimised/redacted:** raw file contents, prompts, transcripts, secrets, PII.
- **Tier-2 "signals"** are derived features (embeddings/labels/structure), never
  reconstructable to raw content.

A model that learns from *decision structure* is often stronger than one that
memorises raw payloads anyway — and it's the safe thing.

## 6. Local-first and federation

The strongest privacy story is also a strong product story:

- **Tier 1 (local model):** a customer's model trains on their own redacted data,
  on their own infrastructure, and the weights are theirs. Their data never leaves.
  This is the enterprise default we lead with.
- **Federation (later):** improve shared models from many customers' *gradients or
  signals* (Tier 2), never their data. Explored only after the local path is solid
  and the privacy accounting (what a gradient can leak) is measured — same
  discipline as "measure the taint false-positive rate before widening it."

## 7. Red lines (never, regardless of tier)

- **A released/shared model is never trained on raw, unconsented customer content.**
- **Secrets never leave the box** — not to training, not to telemetry, not to a
  hosted scorer. The redaction floor applies to every egress of data.
- **No cross-customer leakage.** One tenant's data never trains another tenant's
  model. Local models are isolated by construction.
- **Deletion propagates.** A customer's export/delete request removes their rows
  from corpora and schedules retraining without them. Right to delete is real, not
  cosmetic.
- **No model output is a syscall verdict.** The flywheel makes the *brain* better;
  the *hands* stay deterministic (the one rule, unchanged).

## 8. The release track (what's trained on what)

- **Open models** (small specialists, the DLP) — trained on **synthetic +
  consented, provably-safe public data**. Free, local, auditable; they build the
  community and the adoption that spins the wheel. Shippable regardless of customer
  data, because they never touch it.
- **Enterprise models** — Tier-1 local (their data, their weights) or Tier-3
  shared under a DPA. This is the revenue and the compounding edge.
- **Never** a publicly-released model carrying unconsented customer content. The
  open line and the customer-data line are kept separate by policy and by build.

That separation is the whole trick: **"we train on customer data" becomes a
selling point** — *your model, your data, redacted, never shared* — instead of a
liability.

## 9. How this maps to the code we already have

- **Review queue** (`review/`) — the labelling front-end; each denial + trace + one
  human label is a training row.
- **Redaction** (`agent/src/secrets/`, `[webhooks.redaction]`) — the deterministic
  floor; the DLP model raises it.
- **Journal carve-out** (`agent/src/transcript_taint.rs`) — the precedent that the
  agent's own state is excluded; the corpus honours the same carve-outs.
- **Trace schema** (`trace/schema/v1.json`) — the versioned shape that becomes the
  training row; §5's "keep structure, drop content" is a schema-level decision.

## 10. Sequencing

1. **Now:** ship enforcement + the pluggable model interface + the local
   specialists/DLP (trained on synthetic/public — the open line). Build the review
   queue → **redacted** corpus plumbing with Tier-0 default.
2. **As deployments run:** Tier-1 local models on consented customer data.
3. **Once the wheel turns and privacy accounting is measured:** Tier-2/3 shared
   models and the public cybersecurity model release.

We do not release a customer-data-trained model before the consent, redaction,
deletion, and isolation guarantees above are real and tested. The data advantage
is worth nothing if the first headline is a leak.
