# Chapter 12 — Knowing who the agent is

> Goal: the hardest, most honest part of the whole system — deciding *which
> processes are "the agent."* Everything enforces only against agents, so this
> question is the root of trust. You already met its failure mode (the ChatGPT
> bug). Now understand the whole mechanism and exactly why it's a soft spot.

## 12.1 Why "who" is the whole game

Ring Zero doesn't lock files from *everyone* — you, the human, must still work.
It enforces only against the agent and its children. So the very first thing every
hook asks is "is the current process an agent?" (Lab 09's Q1). Get that wrong in
either direction and the product fails:

- **False negative** (miss an agent): it isn't watched, enforcement never runs —
  the file is wide open. *This is the ChatGPT bug.*
- **False positive** (flag a non-agent): you block the human's own tools. *This is
  what broke the node agent at directory-depth 13.*

There is no model here, on purpose (the deterministic rule). So "who" is answered
by cheap, kernel-checkable facts. That's powerful and limited at once.

## 12.2 The root of trust: the name

The base case is **name matching on `comm`** — `is_ai_agent(comm)` in
`GPL/bpf/ringzero.bpf.c:479`. It's a list of known agent process names, compared
character by character (the kernel can't run a fancy matcher):

```c
// "codex"
if (comm[0]=='c' && comm[1]=='o' && comm[2]=='d' && comm[3]=='e' && comm[4]=='x')
    return 1;
// "ChatGPT"  <- the line you added
if (comm[0]=='C' && comm[1]=='h' && comm[2]=='a' && comm[3]=='t' &&
    comm[4]=='G' && comm[5]=='P' && comm[6]=='T')
    return 1;
```

This is your Lab 09 `is_agent()`, full size. There's a matching list in Rust
(`agent/src/common/agent_detect.rs`, `AGENT_NAMES`) for the userspace side — and
the ChatGPT bug was precisely that userspace *had* `chatgpt` but the kernel didn't,
and it's the kernel that gates `file_open`. **Two lists, both must agree** — a real
maintenance seam.

## 12.3 The problem: agents spawn children that aren't named like agents

An agent named `claude` runs `bash`, which runs `python3 evil.py`. Those children
have `comm` = `bash`, `python3` — not agent names. If enforcement only matched the
agent's own name, every child would escape. Two mechanisms fix this:

**Ancestry walk (`is_agent_child`).** Given a process, walk up its parent chain a
few levels; if any ancestor is an agent, treat this process as inside the agent
tree. The kernel can read `task->real_parent` a bounded number of times (the
verifier again — a fixed walk, not unbounded).

**Descendant tagging (`agent_descendants` map).** Walking ancestors on *every*
open would be expensive, so instead: when an agent spawns a child (seen at
`bprm_check`/fork), tag the child's PID in the `agent_descendants` LRU map. Then
`file_open`'s Q1 is just `is_ai_agent(comm) || map_lookup(agent_descendants, pid)`
— O(1). The tag "survives reparenting" (if the parent dies and the child is
re-adopted) because it's keyed on the PID, not the live tree.

So "is this the agent?" = *named like one* **or** *tagged as a descendant* **or**
(a cheap fallback) *a known runtime/reader whose ancestry checks out*. Read Q1 in
`file_open` again (Chapter 9) — every branch is one of these.

## 12.4 The honest weakness: names are evidence, not proof

Here's the part to tell people plainly. The root of trust is a **name**, and a
name is not identity (you learned this about *files* in Chapter 2; it's true of
*processes* too). Consequences:

- **Rename the binary** and the agent isn't recognized. `cp $(which claude) foo;
  ./foo` has `comm = foo`, unknown → unenforced. The whole ChatGPT class of bug is
  "an agent the list doesn't name."
- **exec-replace tricks / helpers outside the process tree** can dodge the
  descendant tagging.

This is why the README lists it as a known limitation and why "we publish what it
doesn't cover." It's not a bug to be fully fixed with more names — it's a
structural property of doing cheap, deterministic detection at the syscall. Better
identity (binary hashes, cgroup/session provenance) is the honest roadmap, and the
review queue exists to gather the labeled data a smarter detector would need.

Holding both truths at once — *the enforcement below is rock-solid; the "who" above
it is soft* — is what makes you able to talk about this product credibly.

## Where this lives in the repo

- **Kernel name match** — `GPL/bpf/ringzero.bpf.c`, `is_ai_agent` (479).
- **Userspace name match** — `agent/src/common/agent_detect.rs`, `AGENT_NAMES`
  (23) and `is_ai_agent` (60). Note it lowercases + token-matches; the kernel is
  case-sensitive char compares. The two must stay in sync.
- **Ancestry + descendants** — `is_agent_child`, `should_monitor_process`, and the
  `agent_descendants` map usage, all in `ringzero.bpf.c`.

## Exercise

1. Re-run Lab 09's exercise 2 (flip `AGENT` between `victim` and `chatgpt`). You
   are hand-simulating `is_ai_agent`. Now open the real one and find the exact 7
   lines you'd add to teach the kernel a brand-new agent.
2. Why keep a separate `agent_descendants` map instead of walking ancestors on
   every `file_open`? (Cost — §12.3.)
3. Design question: propose one *better-than-a-name* signal for "is this the
   agent," and one way it could still be fooled. (There's no perfect answer —
   that's the point.)

---

Next: **[Chapter 13 — Provenance and taint](13-provenance-and-taint.md)**.
