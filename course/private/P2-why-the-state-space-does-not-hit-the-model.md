# P2 — Why the state space doesn't hit the model

> **Private track.** Model IP; never in a public zip.
> Goal: be able to answer the objection every serious doubter raises — *"runtime
> security is millions of states, constantly changing context, OOD inputs, and
> state that must persist; a fine-tuned model doesn't change that"* — from the
> mechanisms you already learned, in your own words, without notes.

## P2.1 The objection, and the mistake inside it

The objection is correct about a **model-only** system. If a model had to be
right, at syscall time, across every state an agent can produce, you would need
something enormous and you still wouldn't trust it. The mistake is assuming Ring
Zero is model-only. It isn't. Chapters 9–15 are a list of mechanisms that
**partition the state space before the model sees anything** and **persist state
outside the model**. The model answers bounded, typed questions and can only
tighten. Go through the objection one clause at a time.

## P2.2 "Millions of states"

The model never faces the raw state space, because three deterministic layers
take most of it off the table first:

- **Who** (Ch. 12): "is this process an agent?" is `is_ai_agent(comm) ||
  agent_descendants[pid]` — an O(1) map lookup, no model.
- **What** (Ch. 9–10): every *direct* attempt on a protected file is refused by
  fixed policy read from maps — `open`, `create`, `rename`, `link`, `unlink` —
  regardless of how novel the surrounding situation is.
- **Join** (Ch. 15): the event firehose becomes structured records on
  `session_id`; kernel = fact, checks = intent.

What's left for the model is a **typed question over one artifact or one event,
with a session summary** — "does this file, given this policy, express intent to
circumvent?" — with a three-to-four option ordinal answer. That is not millions
of states. It is one decision, repeated, over structured input, with the floor
holding underneath it whether the model is right or wrong.

## P2.3 "Constantly changing context"

Context changes are handled by **provenance taint** (Ch. 13), not by model
judgment. When the agent ingests external content — a web fetch, a search, an
MCP tool result — userspace raises a **bit on the process tree**; the kernel's
`socket_connect` reads that bit and holds the tainted tree to an egress
allowlist. *Where it came from* is a deterministic fact; *what it means* is a
guess, and guesses don't gate syscalls. Taint is **raised, never lowered**
(§13.3). So "changing context" becomes a monotonic bit the model doesn't have to
re-derive on every step.

## P2.4 "State that needs to persist"

It persists — in **kernel maps and the trace**, not in model weights:

| State | Where it lives | Persists across |
|---|---|---|
| identity of the agent tree | `agent_descendants` (PID-keyed LRU) | fork, reparenting |
| untrusted provenance | `tainted_pids` (raise-only) | the whole process tree's life |
| a file's verdict | write verdicts keyed on `(device, inode)` | rename, hardlink, copy |
| the session's story | the trace, joined on `session_id` | the session; the incident review |

On the model side, the state *encoder* carries a recency-weighted session summary
with **incremental updates** (the pattern SalesRLAgent used to stay under 100 ms —
Chapter P3). Nothing in this requires the model's *architecture* to hold state.
The persistence the objection worries about is a maps-and-trace problem, and it's
already solved deterministically.

## P2.5 "OOD inputs"

Two answers, in order of importance:

1. **Uncertainty never opens anything.** Chapter 15: "if it's unsure, the safe
   default applies." The deterministic floor holds the direct attempt whether or
   not the model has ever seen anything like the situation. So an OOD input can
   make the model *unhelpful*; it cannot make the system *permissive*.
2. **The model is built to know when it doesn't know.** A calibrated encoder with
   a novelty/confidence signal (similarity to training data, ensemble agreement,
   unfamiliar structure) routes a novel situation to **contain + review**, not to
   a confident wrong verdict (P1.5's tiers). In an adversarial setting that is the
   only safe reading of novelty: unfamiliar ⇒ tighten.

## P2.6 "Fine-tuning Qwen doesn't change the architecture"

Agree — and it's why the reflex model isn't Qwen. The System 1 is an **encoder
with a proper-scoring decision objective** (P1.2). Fine-tuning changes *what it
reads*; the architecture is already the right one. A fine-tuned next-token model
was only ever a candidate for the off-device judgment tier, where its
long-context reasoning and ability to explain itself earn their cost.

## P2.7 Where the objection should actually land: the real gaps

Here's what makes you credible rather than defensive. The product's genuine
weaknesses are in Chapter 17, and **every one of them is about the decision to
apply enforcement — who and when — not about model capacity**:

- **Identity by name** (17.1): rename the binary; dodge descendant tagging.
- **Enforced vs recorded** (17.2): exec and network are recorded, not refused, in v1.
- **The scan window** (17.4): ~800 ms between a write closing and its verdict landing.
- **The `sudo` cache** (17.3).

A 3–8B model fixes none of these. The honest roadmap is **better identity**
(binary provenance, cgroup/session lineage) and **more labelled runtime states**
— a data-and-identity problem, not a parameter-count problem. When a doubter says
"you need a bigger model," the strongest answer is to show them this list.

## P2.8 The drill — answer these cold

If you can answer these without notes, you can answer anyone, because every
doubter's objection is one of them in disguise:

1. Where exactly does the model run, and where is it forbidden — and why does
   the forbidden place matter for latency *and* for trust?
2. Why is "a probability is never permission" true here, and what is the one
   thing a model is allowed to do to a verdict?
3. "Millions of states." What reduces the state space *before* the model sees
   anything? Name the mechanisms.
4. Where does state actually persist? Not in weights — then where?
5. An agent reads a web page. What happens, deterministically, and why don't we
   judge the page's content?
6. How does a model's judgment about a file reach the kernel without the kernel
   ever calling a model?
7. What are the product's *real* weaknesses — and why does a bigger model fix
   none of them?
8. "Fine-tuning Qwen doesn't change the architecture." Agree or disagree — and
   what *is* your architecture?

## Where this lives

- Ch. 9, 12, 13, 14, 15, 17 of the public course — the mechanisms.
- `models/THE-BRAIN.md` §3–§5 — decide/execute, tighten-only, the tiers.
- `GPL/bpf/ringzero.bpf.c` — `agent_descendants`, `tainted_pids`, the write
  verdict map keyed on `(dev, ino)`; `trace/schema/v1.json` — the join key.

## Exercise

1. Take the objection verbatim and write a reply under 150 words that cites a
   mechanism for each clause. Then delete every sentence that doesn't name one.
2. Pick one of the four real gaps and explain why *more model* doesn't touch it,
   then say what would.

---

Next: **[P3 — Research basis and the lab plan](P3-research-basis-and-the-lab-plan.md)**.
