# From Rust to the Kernel — learning systems by building Ring Zero

A course that starts with zero assumptions about Rust, C, or Linux internals and
takes you to reading (and modifying) every important line of **Ring Zero
Security** — a real product that stops AI coding agents at the system call using
eBPF.

You don't learn eBPF by reading about eBPF. You learn it by watching a program
you wrote *deny an open() call* and understanding every layer that made that
possible. This book is built around one real codebase so every concept has a
place it actually lives.

## How to read this

- **The repo** it teaches lives at `../rgs-linux-oss/` (paths below are relative
  to that root, e.g. `GPL/bpf/ringzero.bpf.c`).
- **The lab machine.** eBPF only runs on Linux with the right kernel. The Lima VM
  named `rgs` has the whole toolchain (clang, bpftool, rust, a BPF-LSM kernel).
  Every "**Try it**" box is meant to run there:
  `limactl shell rgs` then `cd /Users/jarvis/rgs/rgs-linux-oss`.
- Each chapter ends with **Where this lives** (the real file + lines) and a small
  **Exercise**.
- Read in order for the first pass. The parts are: systems → Rust → eBPF →
  enforcement → the agent-aware layer → shipping it.

## Syllabus

### Part I — The ground: how a Linux program actually runs
1. **Syscalls and the kernel boundary** — what `open`, `execve`, `connect`
   really are, user space vs kernel space, and why the syscall is the one place
   you can't be lied to. *(the whole premise of the product)*
2. **Processes, files, inodes, dentries** — PID, `comm`, file descriptors, and
   why a file is identified by `(device, inode)`, not its name. *(why a hardlink
   can't dodge a rule)*

### Part II — Rust from zero (for people who've programmed before)
3. **Ownership, borrowing, structs, enums** — the ideas that make Rust different,
   by example. *(anchored in `agent/src/config.rs`)*
4. **`Result`, `Option`, errors, traits, modules** — how Rust code is organized
   and how it handles failure. *(anchored in `cli/src/main.rs`)*
5. **Rust for a daemon** — `async`/Tokio, `unsafe`, and calling C (`libc`).
   *(anchored in `agent/src/main.rs`)*

### Part III — eBPF: running your code inside the kernel
6. **What eBPF is** — the in-kernel virtual machine, the verifier, program types,
   the compiled `.o`, and CO-RE/BTF/`vmlinux.h`. *(`GPL/bpf/Makefile`)*
7. **Your first program: observe an event** — ring buffers and sending facts to
   user space. *(the `events` ringbuf, `fill_process_info`)*
8. **Maps: the shared memory between kernel and user space** — hash, LRU, array,
   and the ABI both sides must agree on. *(`blocked_files`, `blocked_inodes`,
   `agent_descendants`)*

### Part IV — Enforcement: saying *no*
9. **The LSM hook that denies an open** — returning `-EACCES`, the hot path, and
   the directory walk. *(`SEC("lsm/file_open")`, line 940; the ChatGPT-detection
   story lives here)*
10. **All the other hooks** — create/unlink/rename/link, exec, connect, ptrace,
    mount, kill. *(the `SEC("lsm/…")` blocks)*
11. **Loading and attaching from Rust** — how the daemon puts your programs in the
    kernel. *(`agent/src/ebpf_loader.rs`)*

### Part V — What makes it *agent-aware*
12. **Knowing who the agent is** — name-match as the root of trust, tagging
    descendants at fork, and the honest weakness of both. *(`agent_detect.rs` +
    kernel `is_ai_agent`)*
13. **Provenance and taint** — untrusted context, tainting a process tree, and the
    egress allowlist. *(`agent/src/transcript_taint.rs`)*
14. **Precompute-then-bit** — scanning what an agent writes off the hot path and
    leaving the kernel one bit to read. *(`agent/src/write_scan/mod.rs`)*
15. **The trace join and the one rule** — correlating "what it looked like" with
    "what happened," and why a model never decides a syscall. *(`trace/`)*

### Part VI — Shipping it
16. **Build, package, run** — the Makefile, the `.deb`, the `rz` CLI, the demo.
    *(`build-deb.sh`, `examples/boundary-demo.sh`)*
17. **The honest gaps** — the limits we publish, and how you'd try to break it.

---

Start with [Chapter 1](01-syscalls-and-the-kernel-boundary.md).

---

### Part VII — Private research track (not in public zips)

The brain — the decision model, its research basis and the lab plan — lives in
[`private/`](private/README.md). It is model IP: it stays in the private fork and
is never included in a zip sent to learners. `private/README.md` has the zip
recipe that excludes it.
