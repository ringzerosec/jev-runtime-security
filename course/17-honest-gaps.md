# Chapter 17 — The honest gaps

> Goal: finish the way the product talks — by stating plainly what it does **not**
> do. Knowing the limits is what lets you deploy it wisely, extend it, and describe
> it credibly. "We publish the list of what it doesn't cover" is a feature, and now
> you understand every item on it.

## 17.1 Detection is by name (the big one)

You built the whole detection story in Chapter 12, so you know its floor: the root
of trust is a **process name**, and a name is evidence, not identity.

- Rename an agent's binary to something the list doesn't know, and it isn't
  enforced. (The ChatGPT bug was one instance; there are infinitely many names.)
- exec-replacement and out-of-tree helpers can dodge descendant tagging.

This isn't fixable by adding more names — it's structural to cheap, deterministic
detection at the syscall. The honest roadmap is *better identity* (binary
provenance, cgroup/session lineage), and the review queue exists to collect the
labeled data such a detector would need. **Say this out loud when you present the
product.**

## 17.2 Enforced vs recorded

From Chapter 10: file operations (open/create/delete/rename/link) are **refused**;
`exec` and network are **recorded, not refused** in this release. The deny
machinery is identical — the choice not to block execs/connections yet is about
false positives on normal developer work (Chapter 14's false-positive floor
concern, applied to the whole system). So an agent *can* still run programs and
open connections; you'll *see* them in the trace, but they aren't gated. Egress
gating exists (Chapter 13) but is off by default.

## 17.3 The `sudo`-timestamp hole

The enforcement authority (turning policy on/off, the full-scope token) is
root-only. But `sudo` caches your authentication for ~15 minutes per terminal. An
agent running in a terminal where **you** recently ran `sudo` inherits that cache
and can act as root with no prompt. This is a property of `sudo`, not something
Ring Zero introduced or can repeal. The daemon mitigates it (it refuses a
policy-changing call whose caller, or any ancestor, is an agent — a
name/ancestry check, so "evidence, not proof" again), but the real fix is
operational: don't run agents in a terminal you've `sudo`'d in, or turn off the
timestamp. `SECURITY.md` has the exact `sudoers` snippet.

## 17.4 The scan window

From Chapter 14: there's a measured ~800 ms window between an agent-written file
closing and its verdict being stored, during which the file is usable (default
fail-open). `fail_closed = true` closes it at a latency cost. The number is
published, not hidden.

## 17.5 v1 kernel scope

The kernel enforcement doesn't yet cover raw-disk reads, snapshots, or
hostname-level egress. And the whole thing is Linux-with-BPF-LSM only, by
construction (that's what the mechanism *is*).

## 17.6 How you'd try to break it — and why that's invited

Put your new knowledge to adversarial use. The interesting attacks all target the
**"who"** and the **timing**, never the kernel verdict itself:

- Rename/repackage an agent so `is_ai_agent` misses it (Chapter 12).
- Get a non-agent process to do the dirty work — write a file some *other*
  privileged process later reads (out of the agent tree).
- Race the scan window (Chapter 14) — use the file in the ~800 ms before the
  verdict lands.
- Reach root via the `sudo` cache (17.3).

None of these defeat the syscall verdict; they defeat the *decision to apply it*.
That's precisely the honest shape of the product: **the enforcement below is
solid; the identification above it is soft.** Finding a new instance of "an agent
the system didn't recognize" is the contribution the project asks for — which is
why it's open source and ships the gap list.

## 17.7 What you can now do

You started not knowing what a syscall was. You can now:

- read every `SEC("lsm/…")` hook in `GPL/bpf/ringzero.bpf.c` and say what it guards;
- read the Rust daemon that loads them and pushes rules (`agent/src/`);
- explain the maps ABI, provenance taint, precompute-then-bit, and the one rule;
- **write and attach your own LSM enforcer** (you did — Lab 09);
- reproduce and fix the ChatGPT-class bug from first principles;
- and state the product's guarantees *and* its gaps without overclaiming either.

That last one — holding "the enforcement is rock-solid" and "the detection is soft"
at the same time — is the mark of actually understanding a security system rather
than marketing it.

## Where this lives in the repo

- **The published gaps** — `README.md` "Limitations we don't hide" and
  `SECURITY.md` (the `sudo`/token model in full, and where to report a bypass).
- **The mitigations** — the caller-identity check in `agent/src/` (search for the
  IPC/`SO_PEERCRED` and `/proc/net/tcp` resolution), the `fail_closed` option, the
  egress allowlist.
- **The review queue** — `review/` — the data pipeline for the better detector
  that closes 17.1.

## Exercise (capstone)

1. Pick one gap (say 17.1). Write a paragraph a security engineer could act on:
   what's exposed, why, the mitigation, and how you'd detect an attempt.
2. Reproduce a gap on the VM: use Lab 09's `is_agent` to show that renaming the
   "agent" defeats detection — then propose the smallest change that would catch
   *that* rename (and note how it, too, could be dodged).
3. Write the one paragraph you'd put at the top of a launch post that is honest
   about both the strength (deterministic enforcement below the agent) and the
   limit (name-based identification). You now know enough to write it truthfully.

---

**You've finished the book.** Re-read `GPL/bpf/ringzero.bpf.c` start to end — it
should now read like prose. Back to the **[syllabus](README.md)**.
