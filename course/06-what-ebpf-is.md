# Chapter 6 — What eBPF is

> Goal: understand what eBPF actually is — a way to run *your* code *inside* the
> running kernel, safely — and the toolchain around it (the verifier, program
> types, the compiled `.o`, and CO-RE/BTF/`vmlinux.h`). No new code yet; this is
> the map before Chapters 7–11.

## 6.1 The problem eBPF solves

You want the kernel to run your logic at a specific moment — "when any file is
opened, ask my code." Historically you had two options:

1. **A kernel module**: your C compiled into the kernel. Full power, but a single
   bug **panics the whole machine**, and it's tied to exact kernel versions.
2. **Rewrite the kernel**: not a real option.

**eBPF** is a third way. You write a small program, and the kernel runs it in a
sandbox at chosen hook points. The magic is that the kernel **proves your program
is safe before it runs it**. A buggy eBPF program is *rejected*, not fatal.

Think of it as: the kernel embeds a tiny, restricted virtual machine, and lets you
load bytecode into it that fires at events — as long as a checker agrees the
bytecode can't hang, crash, or read where it shouldn't.

## 6.2 The verifier — why eBPF is safe to load

Before accepting your program, the kernel's **verifier** simulates every possible
path through it and rejects anything that could harm the kernel:

- **No unbounded loops.** It must prove your program terminates. (This is why the
  directory walk in Ring Zero is a `#pragma unroll` loop with a fixed bound like
  `MAX_DIR_WALK` — an unbounded `while` would be rejected.)
- **No out-of-bounds memory.** Every pointer access must be provably in-range;
  you check pointers before dereferencing.
- **Bounded size/complexity.** Programs are limited so verification is tractable.
- **Only approved "helpers."** Your program can't call arbitrary kernel
  functions — only a fixed set of **BPF helpers** (`bpf_map_lookup_elem`,
  `bpf_get_current_comm`, `bpf_probe_read_kernel`, …).

The upside: you can run code in the kernel with confidence. The cost: eBPF C is
*restricted* C. The verifier's "can't prove this is safe" errors are the eBPF
equivalent of Rust's borrow checker — annoying, then protective. (Some helpers are
**GPL-only**, which is *why* the BPF side of this repo must be GPL-2.0 — Chapter 1
of the licensing story, and the `char LICENSE[] SEC("license") = "GPL";` line you
wrote in Lab 00.)

## 6.3 Program types and hooks

An eBPF program has a **type** that decides where it can attach and what it
receives. The `SEC("...")` string at the top of each function declares it:

- `SEC("tracepoint/...")` / `SEC("kprobe/...")` — observation points (great for
  learning; Chapter 7).
- `SEC("lsm/...")` — **Linux Security Module** hooks. These are the enforcement
  ones: the kernel calls them at security decisions and **obeys their return
  value**. `lsm/file_open`, `lsm/bprm_check_security`, `lsm/socket_connect`. This
  is Ring Zero's whole enforcement surface.

An LSM program returns `0` to allow or a negative errno (like `-EACCES`) to deny.
That single number, returned from your sandboxed program, is how a syscall gets
refused. Everything in Part IV is variations on computing that number.

## 6.4 The build: from C to a loadable object

eBPF isn't compiled to your machine's CPU instructions — it's compiled to **BPF
bytecode**. The toolchain (which you ran in Lab 00):

```
ringzero.bpf.c  --clang -target bpf-->  ringzero.bpf.o   (BPF bytecode, an ELF)
                                              |
                                     Rust loader reads the .o,
                                     the verifier checks it,
                                     the kernel attaches it to hooks
```

`clang -target bpf -c foo.bpf.c -o foo.bpf.o` produces the object. Nothing runs
yet — a **loader** (Chapter 11, in Rust) hands it to the kernel.

## 6.5 CO-RE, BTF, and `vmlinux.h`

Your eBPF program reads kernel structs (a `struct file`, a `struct dentry`). But
those structs differ between kernel versions — field offsets move. How does one
`.o` work across kernels?

- **BTF** (BPF Type Format): a description of every type in the *running* kernel,
  exposed at `/sys/kernel/btf/vmlinux`.
- **`vmlinux.h`**: a giant header generated from BTF (`bpftool btf dump ... format
  c`) — 180k+ lines describing every kernel struct. You `#include "vmlinux.h"`
  instead of kernel headers. You generate it per-machine; never commit it.
- **CO-RE** ("Compile Once, Run Everywhere"): the compiler records *which fields*
  you read symbolically; at load time libbpf **relocates** them to the running
  kernel's actual offsets using BTF. So one `.o` loads on many kernels.

This is why the repo's `GPL/bpf/Makefile` generates `vmlinux.h` from
`/sys/kernel/btf/vmlinux` before compiling, and why CI needed BTF (the saga that
had you drop the BPF-compile step from CI — it belongs at packaging time on a real
kernel, not a generic runner).

## Where this lives in the repo

- **The build** — `GPL/bpf/Makefile`: see the `vmlinux.h:` target (dumps BTF) and
  the `clang ... -target bpf` compile. This is Lab 00 for real.
- **Program headers** — top of `GPL/bpf/ringzero.bpf.c`: `#include "vmlinux.h"`,
  the BPF helper headers, and `char LICENSE[] SEC("license") = "GPL";`.
- **The verifier's fingerprints** — search `#pragma unroll` and `MAX_DIR_WALK`:
  bounded loops written that way *because* the verifier forbids unbounded ones.

## Exercise

1. On the VM: `sudo bpftool prog list | head`. You're looking at every eBPF
   program currently loaded in your kernel — including, if the daemon runs, the
   `ringzero_*` ones. `sudo bpftool prog show name ringzero_file_open` if present.
2. `wc -l labs/00-setup/vmlinux.h` — that's how many kernel type definitions your
   programs get to reference. Open it and search for `struct file {` and `struct
   dentry {` — the types the hooks receive.
3. In `GPL/bpf/ringzero.bpf.c`, find one `#pragma unroll`. Explain in one sentence
   why the verifier requires the loop bound to be fixed.

---

Next: **[Chapter 7 — Your first program: observe an event](07-observe-an-event.md)**.
