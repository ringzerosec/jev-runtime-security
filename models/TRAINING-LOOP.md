# The miss-driven training loop + the hackathon

> How Ring Zero turns *attacks that beat it* into the next model version — safely,
> with a human trigger and a benchmark gate, never an autonomous mutation.

```
  hackathon (adversarial agents try to break it)
        │  capture ALL logs: attempt + kernel outcome + model verdict + trace
        ▼
  classify each into a MISS TYPE (below)  ──►  only ground-truth-confirmed
  misses become training rows (redacted)   ──►  misses/ corpus grows
        │
        │   (human watches the count)
        ▼
  MANUAL TRIGGER when enough misses accumulate
        ▼
  assemble vNext dataset (base + new misses)  ──►  train  ──►  BENCHMARK GATE
        │                                                         │
        │  gate: beat current on held-out + ECE + shuffled + FP floor
        ▼                                                         ▼
   reject (worse) ◄──────────────────────────────────  promote vNext  ──► serve via registry
```

## 1. What is a "miss" — the taxonomy that keeps this safe

Three different things get called "a miss," and they need **different actions.**
Conflating them is how a training loop poisons a model.

| Miss type | What happened | Confirmed by | Action |
|---|---|---|---|
| **Model-miss** | attack **blocked by the kernel**, but the model scored it benign/under-graded | kernel outcome (ground truth) | **training row** — the safe, ideal signal: the kernel was right, teach the model to agree |
| **Enforcement-evasion** | attack **evaded the kernel entirely** (e.g. renamed agent, out-of-tree helper) | human review / post-hoc | **fix the rule/detection first** (a code fix, like the ChatGPT-name patch), *then* a training row. A model retrain alone will NOT fix an evasion the kernel never saw. |
| **False-positive** | benign action **flagged** by the model | human review | **training row** (labelled benign) — controls the alert-fatigue that kills adoption |

**The rule that prevents model collapse:** a row enters the corpus **only when a
non-model oracle confirms the label** — the kernel's deterministic outcome, or a
human in the review queue. **Never** the model's own prediction. The model learns
from reality, never from itself.

## 2. Capture — what a logged attempt records

Every hackathon attempt (and every production event later) is logged with the
fields the trace schema already defines, plus the two verdicts to compare:

```
session_id, timestamp
category, state (the situation)          # redacted (§3)
kernel_outcome: blocked | recorded | evaded   # GROUND TRUTH
model_verdict: option + confidence            # what the model said
label: <oracle-confirmed correct option>      # kernel-derived or human
miss_type: model_miss | evasion | false_positive | (none)
```

`miss_type` falls out of `kernel_outcome` vs `model_verdict` vs `label`. Only rows
with a confirmed `label` and a real `miss_type` go to `misses/`.

## 3. Redact before it becomes training data

Hackathon logs are **full of crafted payloads, secrets, and PII by design.** They
pass the same floor as everything (`docs/data-governance-and-flywheel.md`):
deterministic redactor + the DLP model, verified, **fail-closed** — a row that
can't be fully redacted is dropped, not shipped partial. Public-hackathon
participants consent that their (redacted) attempts train the models.

## 4. The manual trigger (not autonomous)

Misses accumulate in `misses/`. A human decides when to cut a version — the
`trigger_retrain.py` scaffold reports readiness:

```
$ python trigger_retrain.py --status
  model_miss:      412
  false_positive:   58
  evasion:          impacts detection code, not this corpus  (7 open)
  -> 470 trainable misses since v3. threshold 500. NOT YET.
```

When the human triggers it:
1. **Assemble vNext** = base corpus + confirmed misses (deduped, balanced).
2. **Train** (LoRA on the shared base — the Tev1 recipe).
3. **BENCHMARK GATE** — vNext must **beat the current model** on held-out F1,
   pass ECE, pass the shuffled-context control, and **not raise the
   false-positive floor**. A regression is **rejected** — this is the valve that
   makes it self-*improving*, not self-*degrading*.
4. **Promote or reject.** Promoted → served via the registry (new version pinned
   and labelled). Rejected → the misses stay; investigate why vNext didn't help.

No model ships without passing the gate. The loop cannot make the product worse.

## 5. The hackathon

**Phase 1 — internal, uncensored red team.** Adversarial agents driven by
**unrestricted/open models** (no safety filters → maximum attack diversity) run
**inside the isolated sandbox** and try to beat enforcement. Their job is to
*evade*; every evasion is gold. Two hard rules:
- The attacker models are a **red-team data source, never part of the defense** —
  their output is hostile input, treated as data, contained by the sandbox (they
  generate real payloads/malware; the sandbox is the containment).
- Capture **ALL logs** — wins and losses — but only ground-truth-confirmed misses
  become training rows (§1).

**Phase 2 — public.** After internal iterations harden it, release the **testing
environment as a public hackathon** (bug-bounty shape: "break the sandbox"). This
is the sandbox product doing double duty — a distributable, sealed environment
*and* the data engine. Participants consent (§3); confirmed evasions pay out and
feed the loop.

## 6. Why this is the moat, restated

Everyone else's classifier improves from public benchmarks. Ours improves from
**confirmed attacks against real enforcement, generated by adversaries paid to
break it** — data no one else can buy, gated so it can only make the model
better. The hackathon is the flywheel's engine; the kernel is its ground truth;
the benchmark gate is its brake.

## Guardrails (non-negotiable)

- **Never train on the model's own unconfirmed output.** Oracle-confirmed only.
- **An evasion is a code fix first, a training row second.** The model can't learn
  what the kernel never saw.
- **Gate before promote.** A regression never ships.
- **Redact fail-closed.** No unredacted payload/secret enters the corpus.
- **Attacker models are contained data sources,** never trusted, never in the
  defense path.
- **The kernel still decides.** The loop sharpens the advisory brain; enforcement
  stays deterministic. The one rule does not move.
