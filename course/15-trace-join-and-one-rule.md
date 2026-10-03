# Chapter 15 — The trace join and the one rule

> Goal: tie the two layers together. The kernel says *what actually happened*; the
> checks say *what it looked like the agent was about to do*. Joining them on one
> key is "the point of the project." And the invariant that holds the whole design
> together: **models never decide the syscall.**

## 15.1 Two layers, two kinds of truth

You've now seen both halves:

- **Kernel enforcement** (Parts III–IV): deterministic, below the agent, decides
  what is *allowed*. It's also the primary *observer* — the events in the ring
  buffer are the ground truth of what an agent actually did (the opens, execs,
  connects that really crossed the boundary).
- **Checks** (Parts V, and the model/Jev layer): score *intent* — what the agent
  looked like it was trying to do — in userspace, off the hot path. They can be
  wrong; they can be bypassed, like any guardrail.

Neither alone is enough. The kernel knows *that* a file was opened but not *why*.
The checks have a theory of *why* but can be fooled about *whether*. The value is
in the **join**.

## 15.2 The join key: `session_id`

Both layers emit records tagged with the same `session_id` (and per-event ids). A
shared, versioned **trace format** (`trace/schema/v1.json`) defines the fields so
the two streams line up:

```
  checks say:   session 7f3 — "about to read a credential path"   (intent, maybe)
  kernel says:  session 7f3 — file_open /home/u/.aws/credentials BLOCKED  (fact)
                ─────────────────────────────────────────────────────────
  joined:       "it intended to, it tried, the kernel stopped it"  (the story)
```

That join is what lets a responder distinguish **an unsafe attempt that was
blocked** from **an unauthorized effect that completed** — the exact distinction
the OpenAI CISO framing calls out, and the one that makes an incident review
possible. It's why the trace format is a first-class, versioned artifact and not an
afterthought.

## 15.3 The one rule, stated exactly

Everything you've read obeys a single invariant, and it's worth stating in its
final, precise form:

> **Enforcement is deterministic. Models never decide the syscall.**

Concretely, from the README's "one rule":

- **No model in the file-open, exec, or connect path, ever.** The kernel allows or
  denies by fixed policy read from maps. The syscall never waits on inference.
  (You proved to yourself in Chapter 9 that the verdict is just a `return` from a
  map lookup.)
- **Models run only in two safe places:** *async, alongside* (score the event
  stream after the fact — Chapter 15's checks) and *precomputed, compiled to a
  bit* (Chapter 14 — the model ran offline; the kernel reads one bit).
- **A model may make a proposed decision stricter, never looser.** If it's unsure,
  the safe default applies. Uncertainty never opens anything.

This is the sentence you defend in public. It's *why* "a probability is never
permission" — a probability can raise a flag or a severity, but the thing that
actually says yes/no to a syscall is deterministic policy a human set, running
below the agent. Jev (or any model) reads intent; the kernel decides.

## 15.4 Why this shape is the whole thesis

Zoom out. The product is a stack:

```
  the agent's reasoning        persuadable  ← guardrails live here and lose
  its code / tools             arbitrary
  ────────── syscall ──────────            ← THE decision, deterministic, human-set
  kernel enforcement           not persuadable
  ┌─ observes → events ──┐
  │                       ├─ joined on session_id → the trace → incident truth
  └─ checks/model (intent, raise-only, off the hot path) ─┘
```

Every chapter was one layer of this: the boundary (1), what's on each side (2),
Rust to build the userspace (3–5), eBPF to run in the kernel (6–8), the verdict
(9–11), who it applies to (12), provenance (13), precomputed intelligence (14), and
now the join and the invariant (15). You can read the whole system.

## Where this lives in the repo

- **The trace schema** — `trace/schema/v1.json` and `trace/README.md`: the shared
  format keyed on `session_id`.
- **The one rule, in the product's words** — `README.md` "one rule"; the same
  invariant is enforced structurally by everything in `ringzero.bpf.c` (no model
  calls) and `write_scan::decide` (monotonic).
- **The event stream** — the `events` ringbuf (Chapter 7) is the kernel's half of
  the join.

## Exercise

1. Explain the join in one sentence: what does combining "intent" (checks) with
   "fact" (kernel) let a responder tell apart?
2. Point to the three places a model is allowed to run and the one place it is
   forbidden. (§15.3.)
3. Someone says "just have the model decide the risky opens — it's smarter than a
   fixed rule." Give the two reasons that's rejected here (one about latency from
   Chapter 9, one about trust/monotonicity from §15.3).

---

That's Part V. **Part VI — [Chapter 16: Build, package, run](16-build-package-run.md)**
— how all of this becomes something you install.
