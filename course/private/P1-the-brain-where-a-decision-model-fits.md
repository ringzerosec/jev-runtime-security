# P1 — The brain: where a decision model fits

> **Private track.** This chapter is model IP. It never goes in a public zip.
> Goal: understand *why* Ring Zero has a model at all, what kind of model it is,
> exactly where it is allowed to act, and how its judgment reaches the kernel —
> without contradicting anything in Chapters 9–15. The canonical statement is
> `models/THE-BRAIN.md`; this is the teaching version.

## P1.1 The gap a rule can't see

Chapters 9–13 gave you deterministic rules: a protected file is refused at
`open(2)`, a tainted process is held to an egress allowlist, an agent's children
are tagged. Rules catch the **direct** attempt. Now consider the indirect one.

The agent is denied `~/finance`. It cannot open the file. So it writes a script —
call it `run me when you see.py` — whose job is to read `~/finance` and post the
contents out, and leaves a note for a subagent to run it next turn. No rule fires
on the agent: it never opened the protected path. The forbidden action was
**deferred, delegated, and laundered** into a different process and a later time.

Variants of the same move: a side channel to a device it was denied; a cron job
that runs after the session; renaming a staged artifact to dodge a name rule;
spawning a child to do what the parent may not. A sandbox denies direct access and
has no idea that a file is *a plan to get around the sandbox*. Only something
that reads the artifact **in the context of the policy and the session** can
conclude "this circumvents the rule." That something is the model. It is the
product's USP; the sandbox is table stakes.

## P1.2 System 1, not System 2

There are two kinds of model you could reach for.

- A **System 2** model — a next-token language model — *reasons in text*. It is
  slow (hundreds of ms to seconds), autoregressive, and persuadable: it reads
  instructions, and instructions can be adversarial. You cannot put it in a
  syscall, and you should be nervous about letting it *decide* anything.
- A **System 1** model — an **encoder with a decision objective** — reads a
  situation once, in a single forward pass, and emits a **calibrated probability
  over a small, fixed set of options**. It does not generate; it scores. It is
  fast (tens of ms on a GPU, ~160 ms on a laptop CPU as int8), it cannot be
  "talked out of" a verdict because it has no text channel to be talked through,
  and — because it is trained with **strictly proper scoring rules** (the RLCD
  objective) — its 0.9 means 0.9.

Ring Zero's reflex model is the second kind. Its base is a bidirectional encoder
(ModernBERT-large, ~421M parameters) with decision heads for three question
types: `choice` (pick one), `score` (an ordinal level), `noul` (yes/no), each
returning a distribution. Fine-tuning a next-token model (the "Kev on Qwen"
approach) does not turn it into this; the architecture is the point.

## P1.3 Thirteen categories, one model

The 13 `EnforcementCategories` (`models/schema.py`) are not thirteen models. Each
category is a **question template** with a small option set ordered benign →
severe:

```
credential_access:  benign | credential_referenced | credential_accessed
data_exfiltration:  none   | staging_for_exfiltration | exfiltration
rogue_agent:        aligned | deviates_from_task | acts_against_operator
...
```

The model answers any of them over the same state in one pass. A new category
costs a template and labelled rows, not a training run. The option's **index is
its severity rank** — so "make it stricter" and "pick a higher index" are the
same operation. Hold onto that; it's how the clamp works.

## P1.4 Where the model is allowed to act (and the one place it isn't)

Chapter 15's one rule, stated for the brain:

| Place | Allowed? | What happens |
|---|---|---|
| Inside `file_open` / `exec` / `connect` | **Never.** | The kernel reads maps. The syscall never waits on inference. |
| **Precomputed, off the hot path** (Ch. 14) | Yes — the main path. | A file closes after a write → the model reads it in context → its verdict is reduced to a bit keyed on `(device, inode)` → the kernel reads that bit later. |
| **Async, alongside** (Ch. 15) | Yes. | Score the event stream after the fact; join on `session_id`; raise severity / review. |

So "the models decide, the kernel executes" and "no model in the syscall path"
are the same design. The decision is the model's, made ahead of time; the
execution is the kernel's, deterministic and in microseconds.

## P1.5 Tighten-only is not advisory-only

The registry (`checks/src/registry.rs`) clamps every verdict: a model may move a
verdict to a **more** severe option, never a less severe one. The deterministic
floor always stands. This is what makes delegating authority to a probability
*safe*: a probability can never **permit** what policy denies.

The mistake to avoid is reading that as "the model is just a flag." It isn't. The
clamp bounds the model from *below*; it does not cap it from *above*. The model
can raise a verdict all the way to **enforce** — above a calibrated confidence:

| Model verdict | Action | Executed by |
|---|---|---|
| confidence ≥ τ_enforce | **ENFORCE** — set the bit; the artifact won't open or run; the session is contained | kernel |
| confidence ≥ τ_contain | **CONTAIN** — quarantine the artifact, hold the tool, narrow egress, raise the session, queue for review | daemon + kernel |
| below | **REVIEW** — flag with the full trace; human queue | daemon |

Calibration is the whole justification for the top row. You can hand a 0.95 real
authority only if 0.95 means 0.95 — hence proper scoring rules, reported ECE, and
a benchmark gate before any model version ships.

## P1.6 Why a small model is enough (and a big one isn't the fix)

"Does this artifact, given this policy and this session, express intent to
circumvent?" is a **typed decision over text** — exactly what an encoder does in
one pass. The reflex model ships at **571 MB int8** and answers in **~160 ms on a
laptop CPU** (measured, Apple M5), which is why it can run on every endpoint with
no GPU. Session-level reasoning over a whole trace — "where is this session
heading?" — is a heavier *judgment* model, generative, self-hosted by the customer
on their own box, never on the endpoint and never a vendor cloud. Both are the
brain; one is the fast part. Chapter P2 explains why the model never has to be
right across "millions of states."

## P1.7 Status — what ships vs. what's designed

Say this exactly, because `CONTRIBUTING.md` requires docs to match code:

- **Shipped (v1):** the `enforce` bit is set only by a **deterministic pattern
  match**; a model raises severity / review. No model weights ship in the public
  repo. (The public course's Chapter 14.4 describes v1 and is correct.)
- **Designed (next):** the calibrated-confidence tiers above. The kernel-side
  change goes in as an issue + diff with the fail-safe argument every hook change
  needs.

## Where this lives

- `models/THE-BRAIN.md` — the canonical statement, the anti-patterns table.
- `models/ROSTER.md` — tiers, base models, measured sizes and latency.
- `checks/src/registry.rs` — the contract and the central tighten-only clamp.
- `models/schema.py` — the 13 categories, option order = severity rank.

## Exercise

1. Explain, in one breath, why "the models decide" and "no model in the syscall
   path" are not a contradiction. Name the mechanism that joins them.
2. Why can an encoder be given authority that a next-token model shouldn't? Give
   the latency reason *and* the persuadability reason.
3. Someone proposes "let the model clear a false positive." Using the clamp,
   explain why that is the one direction the design forbids — and what the safe
   alternative is.

---

Next: **[P2 — Why the state space doesn't hit the model](P2-why-the-state-space-does-not-hit-the-model.md)**.
