# Chapter 13 — Provenance and taint

> Goal: understand how Ring Zero handles the *untrusted context* problem — an
> agent that reads a web page or an MCP tool result has ingested content that can
> carry instructions. The answer is **taint by provenance**: mark the process as
> "has touched external content," and hold tainted processes to an egress
> allowlist. Two deterministic halves meeting through a map.

## 13.1 The idea: provenance, not judgment

You cannot reliably decide whether a fetched web page is *malicious* — that's a
probabilistic guess, and guesses don't gate syscalls (the one rule). So Ring Zero
doesn't try. It reasons about **provenance** — *where did this come from* — which
is a deterministic fact:

> "This agent just called `web_fetch` / `web_search` / an MCP tool. From now on,
> treat its process tree as having ingested untrusted external content."

That's it. No opinion about the content's intent. Just: external content entered,
so raise **taint** on the process tree. Taint is a bit that says "be stricter with
this process now."

## 13.2 The two halves

**Half 1 — userspace raises taint (the watcher).** `agent/src/transcript_taint.rs`
tails each agent's transcript (the record of what tools it called). When it sees a
tool call that pulls in external content, it raises taint on that agent's PID tree
by writing the `tainted_pids` map. The trigger list is deliberately narrow —
straight from the file:

```rust
name == "web_fetch"
    || name == "web_search"
    || name.starts_with("mcp__")     // any MCP server tool
```

Why so narrow? Because a *file read* would also be plausible provenance, but it's
the signal most likely to taint an ordinary coding session (which reads files
constantly) — a false-positive storm. So it's held back until measured. "A session
that only reads, writes and runs local commands is never tainted." That restraint
is a design choice you can point to.

**Half 2 — the kernel enforces (the socket hook).** `socket_connect` (Chapter 10)
reads the same `tainted_pids` map. With egress enforcement on, a **tainted**
process connecting to an address **not** on the allowlist (loopback, the LLM API,
operator-approved hosts) is refused with `-EACCES`. Everything else is allowed.

```
  agent calls web_fetch
        │  (userspace watcher sees it in the transcript)
        ▼
  tainted_pids[pid tree] = 1   ── map ──►  socket_connect hook:
                                             if tainted && dst not allowed -> DENY
```

The two halves never talk directly; they meet in a map — the same kernel/user
handshake as everything else (Chapter 8).

## 13.3 Taint is raised, never lowered

A subtle, important rule: **taint only goes up.** Once a process tree is tainted,
nothing in userspace clears it (the kernel drops the entry only when the process
exits, which isn't a "downgrade" — the process is gone). Why? Because "narrowing
authority" must be safe against a compromised agent: if the agent could *clear* its
own taint, the protection would be self-defeating. This is the same monotonic
principle as "a model can make a verdict stricter, never looser" (Chapter 15) —
authority narrows, never widens, from an untrusted source.

## 13.4 The journal carve-out (a real subtlety)

The agent's own transcript is the union of everything the session handled, so it
*always* looks sensitive and full of external content. If you naively scanned or
tainted based on it, you'd flag the agent's own journal harder than a real threat —
and, with quarantine on, the kernel would then refuse the very file the agent reads
to resume its session. So the agent's own journal/state files are **excluded** from
both the taint trigger and the write-scanner. Read the comment block at the top of
`transcript_taint.rs` — it's a good example of a defense that had to be carved
around normal operation.

## Where this lives in the repo

- **The watcher + trigger list** — `agent/src/transcript_taint.rs` (the
  `web_fetch`/`web_search`/`mcp__` matcher, ~line 62; the design rationale in the
  header comment).
- **The kernel side** — `socket_connect` in `GPL/bpf/ringzero.bpf.c` (1589) and
  the `tainted_pids` map; DNS-aware allowlisting lives near it.
- **The "raise-only" rule** — `raise_taint` in `ringzero.bpf.c` (search it): note
  it never downgrades an existing entry.
- **Config** — `[egress] enforce` in `agent/src/config.rs` / the daemon TOML;
  off by default.

## Exercise

1. In `transcript_taint.rs`, read the header comment. In your words: why taint on
   *provenance* (a web fetch happened) instead of on *content* (the page looks
   malicious)?
2. Why is a plain file-read deliberately **not** a taint trigger yet? What would go
   wrong in a normal coding session if it were?
3. Explain "taint is raised, never lowered" as a security property: what attack
   does letting an agent clear its own taint enable?

---

Next: **[Chapter 14 — Precompute-then-bit](14-precompute-then-bit.md)** — how a
model's judgment reaches the kernel without the kernel ever calling a model.
