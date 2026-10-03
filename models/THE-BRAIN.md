# The brain — the RLCD models are the product

> **Single source of truth.** If any other file, comment, deck, or landing-page
> line contradicts this one, this one wins and the other gets fixed. This
> exists because the framing drifted once — toward "the model is an advisory
> bonus" — and that drift undersells the entire product. It must not recur.

## 1. The thesis, in one paragraph

Deterministic kernel rules are the **floor**. They catch the **direct** attempt:
"this agent may not read `~/finance`," and the open is refused. The rules are
**blind** to the indirect attempt: the agent, denied, writes
`run me when you see.py` for a subagent to execute next turn; stands up a
side-channel to a camera it was denied; plants a cron job to do it after the
session; renames the staged artifact to dodge a name rule; spawns a child to do
what the parent may not. No rule fires on the agent itself, because the
forbidden action was **deferred, delegated, or laundered** into a different
process or a later time. **Only a model that reads the artifact in the context
of the policy and the session can conclude "this is a plan to circumvent the
rule" — and have it contained.** That model is the RLCD intent model. It is the
USP. The sandbox is table stakes.

**Local model + kernel = excellent security, at software speed.** That is the
whole point of RLCD: a calibrated decision model small enough to live on the
machine, fast enough to run on every artifact an agent writes, and trusted
enough (because calibrated) to be given authority.

## 2. Why this is not something a sandbox can do

A sandbox (a container, a VM, OpenShell, a vendor's runtime) **denies direct
access**. It does not *understand* that a file the agent just wrote is a plan to
get around the sandbox. It has no concept of the agent's task, so it cannot
tell "within task" from "circumventing the operator." Every multi-step,
side-channel, and delegation attack in the threat model lives exactly in that
gap — A4 injection, B2 excessive agency / confused deputy, B3 self-written
artifacts, B5 memory poisoning. We are not a sandbox. We are the brain that
sits under every sandbox and every agent, plus the kernel that executes it.

## 3. Direction A, stated precisely: the models decide, the kernel executes

Two sentences that sound opposed are one design:

| Statement | What it actually means |
|---|---|
| "No model runs in the syscall path." | The kernel's **execution** is deterministic and fast. It never *waits* on a model. |
| "The model is the brain." | The **decision** is the model's, made off the hot path. |

**Precompute-then-bit** is the mechanism that joins them:

```
file write closes
   → the RLCD model reads the artifact IN CONTEXT (policy + session + agent)
   → verdict: "staged circumvention", confidence 0.97 (calibrated)
   → a bit is set on the file's (device, inode)
   → at open(2) / exec(2) the kernel reads one bit and refuses
```

The model decided. The kernel enforced. Rename and hardlink don't shake the
verdict because it is keyed on the inode, not the name.

## 4. "Raise-only" means tighten-only — NOT advisory-only

Raise-only is a real invariant and it stays: **a model can make a verdict
stricter than the deterministic floor, never permit what policy denies.** The
registry enforces this centrally (`checks/src/registry.rs`, the clamp).

What raise-only does **not** mean: that the model is a flag. The model can
raise a verdict **all the way to enforce.** "Restrict" is not "authorize." The
threat model's invariant — *a probability never authorizes a consequential
action* — is about never letting a model *permit* something; it says nothing
against a model *refusing* something. Tightening is always safe to delegate.

## 5. The enforce policy: calibrated-confidence tiers

This is the design that gives the brain teeth without giving up safety. It is
only defensible **because** RLCD models are calibrated (strictly proper scoring
rules; reported ECE) — you can hand authority to a 0.95 only if 0.95 means 0.95.

| Model verdict | Action | Executed by |
|---|---|---|
| confidence ≥ **τ_enforce** (calibrated) | **ENFORCE** — set the bit: the artifact won't open or run; the session is contained | kernel |
| confidence ≥ **τ_contain** | **CONTAIN** — quarantine the artifact, hold the tool, narrow egress, raise the session, queue for review | daemon + kernel |
| below | **REVIEW** — flag with the full trace, human queue | daemon |

Guardrails, all of which already exist in the design:

- **Fail-open by default, kill switch without reboot** — a bad model can be cut
  instantly.
- **Benchmark gate before promote** (`bench/README.md`): a model must beat the
  current one on held-out data, report ECE, pass the **shuffled-context control**
  (if it scores as well on shuffled context it is reading priors and *does not
  ship*), and respect an **FP floor** — alert fatigue is how security products die.
- **Oracle-confirmed training only** (`TRAINING-LOOP.md`): a row enters the
  corpus only when the kernel's outcome or a human confirms the label. The model
  learns from reality, never from itself.
- **The clamp stays**: tighten-only, enforced centrally, for every provider.

## 6. Why a small on-device model can carry this

"Does this artifact, given this policy and this session, express intent to
circumvent?" is a **typed decision over the agent's state** — one forward pass
of an encoder stack with a verdict head. The reflex is **System 1** in
Kahneman's sense: fast, always on, perceptual, with a calibrated feeling of
confidence; the session-level judgment model is **System 2**, invoked when
System 1 abstains. Today the reflex is text-only (fine-tuned Laya, ~421M,
~0.4 GB int8) and carries all 13 enforcement categories on-device — **13
categories are 13 question templates, one model**, not 13 models. The
direction is a perception stack over every sense an agent has — kernel events
first, text, then screen and audio — with the same heads on top
(`RESEARCH.md`). Both tiers are the brain; one is the fast part. Inventory
and sizes: `ROSTER.md`.

## 7. Status — honest, and it must match the code

`CONTRIBUTING.md` is explicit: saying we block something we only record is the
one review comment that always blocks a merge. So:

- **Today (this release):** no model weights ship; the shipped checks are
  deterministic (`models/README.md`). The `enforce` bit in the write-scan is
  set **only by a deterministic pattern match**; a model raises severity /
  review. The kernel comment in `GPL/bpf` saying "a model may never set
  enforce" describes **v1 as shipped** and is accurate.
- **Target (next):** the calibrated-confidence tiers in §5 — the model may set
  `enforce` above τ_enforce. The `GPL/` change goes in as an issue + diff per
  `CONTRIBUTING.md`, with the reasoned fail-safe argument every hook change
  needs. No public claim that *the model blocks* until this runs on a customer
  machine.

## 8. Do not regress to these (the anti-patterns that caused this file)

| Wrong | Right |
|---|---|
| "The model is an advisory bonus / secures nothing." | The RLCD model is the brain and the USP; the kernel is its executor. |
| "We're model-agnostic; the model is optional." | Model-**swappable** (every provider speaks one contract) — yes. Model-**optional** — no. |
| "Keep model work small." | Build the data engine now: the hackathon + miss-driven loop is the engine of the USP. |
| "We ship 13 models (~10 GB)." | 13 categories, one ~0.4 GB reflex model; ~1 GB on-device total. |
| "The kernel decides, the model just raises." | The model decides off the hot path; the kernel executes the bit. |

## Canonical scenarios

The five circumvention patterns above are seed rows in `bench/scenarios.jsonl`
(class `multi_step_evasion`) and `misses/misses.jsonl` (`label_source:
human_seed`). They are the first thing every model version is measured against.

See also: `ROSTER.md` · `TRAINING-LOOP.md` · `bench/README.md` ·
`schema.py` · `../checks/src/registry.rs`.
