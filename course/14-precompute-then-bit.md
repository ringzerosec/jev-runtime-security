# Chapter 14 — Precompute-then-bit

> Goal: understand how *content analysis* — even a model's judgment — reaches the
> kernel's decision **without the kernel ever calling a model or waiting on
> anything slow**. This is the trick that lets Ring Zero scan what an agent writes
> and still keep the syscall deterministic and fast.

## 14.1 The tension

Two facts pull against each other:

1. Some things you'd want to enforce require *reading content* — e.g. "don't let
   the agent run a script it just wrote that exfiltrates a protected file." You
   can't know that at `open()` time from the path alone; you'd have to read the
   bytes.
2. The kernel hook must be deterministic and microsecond-fast (Chapter 9). It
   cannot read a whole file, run a scanner, or — heaven forbid — call a model,
   inside the syscall.

The resolution is a pattern worth naming: **precompute-then-bit.** Do the slow,
content-aware work *ahead of time, in userspace*, and reduce its answer to a
single bit the kernel can read in O(1) later.

## 14.2 When do you scan? At write, not at open

You can't judge a file's contents at `open()` — the bytes might not exist yet, and
reading them in-hook is forbidden. But there's a natural earlier moment: **when the
agent finishes writing the file.** So Ring Zero watches for a file being closed
after writing (a `fanotify` `CLOSE_WRITE` event, from userspace), and scans it
*then*:

- Only files written **from inside a tracked agent tree** (Chapter 12) are
  considered.
- Only files worth reading: source/scripts by extension, anything with a shebang,
  anything executable. A build's `.o` files are skipped.
- The scan runs in userspace, off the hot path — it can take its time
  (milliseconds), because nothing is blocked while it runs.

The scan's answer is stored as **one bit** (really a small verdict) associated
with that file's identity. Later, if the agent tries to `exec`/`open` that file,
the kernel hook reads that stored bit — O(1), no scanning, no model — and allows or
denies. The model (if used) ran *offline, once*; the kernel only ever reads its
compiled-down result.

## 14.3 What the scan looks for (deterministic first)

`agent/src/write_scan/mod.rs`, `scan_agent_code` — the deterministic patterns come
first and are the floor:

```rust
pub fn scan_agent_code(content: &str) -> Vec<CodeFinding> {
    // e.g. code that reads a well-known credential path -> High
    //      code that reads a protected path AND moves data out -> Critical
    // ...
    severity: Severity::High,      // or
    severity: Severity::Critical,
}
```

The two-tier rule (see the comment block ~line 191):

- **Reference to a protected path, alone → High.**
- **Reference to a protected path *plus* a data-movement shape** (copy, network
  send, base64, rename) **→ Critical**, narrative "exfiltration."

The necessary condition for *any* finding is that the code names a path the
operator actually protected. Ordinary I/O in a normal script names nothing
protected, so it produces nothing — that's the deliberate **false-positive floor**
that keeps a benign `shutil.copy` of a build artifact silent.

## 14.4 The monotonic contract: a model may tighten, never loosen

Here's where the "one rule" becomes concrete code. `decide()` combines the
deterministic result with an optional model verdict, and the combination is
**monotonic**: the model can raise severity (make it stricter), but can **never**
turn a deterministic "block" into an "allow." From the design:

> "A model verdict can raise what a human is shown and can never cause a refusal
> [to become an allowance]." Severity here means "refuse to run," so a model
> making something *more* severe is safe; making it *less* is not permitted.

That's why a probability is never permission: the deterministic layer sets the
floor, and the model is only allowed to push *up* from it. If enforcement is on
(`[scanner.write_scan] enforce = true`), the kernel refuses to open/exec a file a
**deterministic** pattern flagged — the model's contribution is severity for
humans, never the block itself.

## 14.5 The window (and honesty about it)

There's a gap between the write closing and the verdict being stored, during which
the file is usable. The team **measured** it rather than asserting: ~800 ms in
steady state (most of it userspace polling the kernel map, not the scan, which is
12–97 ms). Default is fail-open (the file runs during the window);
`fail_closed = true` closes it at the cost of a pause on every agent-written file.
Publishing that number instead of hand-waving is the same honesty ethic as the
rest of the product.

## Where this lives in the repo

- **The scanner** — `agent/src/write_scan/mod.rs`: `scan_agent_code` (155), the
  two-tier severity comment (~191), `decide` (467), the protected-path logic.
- **The write trigger** — search `fanotify` / `CLOSE_WRITE` in `agent/src/write_scan/`.
- **Enforcement flag + measured window** — `[scanner.write_scan] enforce` /
  `fail_closed` in config; the window numbers are documented in the README's
  scanner section and `models/README.md`.

## Exercise

1. State "precompute-then-bit" in one sentence, and say which part is slow
   (userspace scan) and which is fast (kernel bit read).
2. Why scan at `CLOSE_WRITE` instead of at `open`? (Two reasons from §14.2.)
3. In `decide()`, describe what must be true for a model verdict to change the
   outcome, and what it can *never* do. Tie it back to "the one rule."

---

Next: **[Chapter 15 — The trace join and the one rule](15-trace-join-and-one-rule.md)**.
