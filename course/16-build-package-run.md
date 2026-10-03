# Chapter 16 — Build, package, run

> Goal: see how the two halves become one installable thing, and run the real
> product end to end. You've built the pieces in labs; now watch the repo's own
> build do it at full scale, and trace a rule from `rz` to a denied syscall in the
> shipping system.

## 16.1 The build has two compilers

Ring Zero is compiled by **two toolchains** because it's two languages targeting
two worlds:

1. **The kernel side** — `make -C GPL/bpf` runs `clang -target bpf` on
   `ringzero.bpf.c` → `GPL/bpf/build/ringzero.bpf.o`. Exactly your Lab 09 build,
   plus `vmlinux.h` generation. Needs a kernel with BTF (which is why this step
   lives at *packaging* time on a real machine, not on a generic CI runner — the
   saga you lived).
2. **The userspace side** — `cargo build --release` compiles the workspace
   (`agent`, `cli`, `checks`, the viewer) → the `ringzero-daemon` and `rz`
   binaries. This is what CI actually runs now.

`build-deb.sh` orchestrates both and lays out a `.deb`: the daemon binary, the
`rz` CLI, the **compiled** `ringzero.bpf.o` at `/usr/lib/ringzero/`, the systemd
unit, config, and the polkit policy for the desktop app. The BPF `.o` is shipped
**compiled** — no BPF source crosses into the Apache side, which is what keeps the
GPL/Apache split clean (Chapter 6's licence rule; the CI `licence-headers` job
enforces "no `.bpf.c` outside `GPL/`").

## 16.2 What "installed" looks like

After `apt install ./ringzero-security_*.deb`:

- `/usr/bin/ringzero-daemon` — the Rust daemon (runs as root, loads the BPF).
- `/usr/bin/rz` — the CLI you talk to.
- `/usr/lib/ringzero/ringzero.bpf.o` — the compiled kernel programs the daemon
  loads (Chapter 11). **This exact file is the one you rebuilt and `scp`'d when you
  fixed the ChatGPT bug.**
- a systemd service `ringzero-daemon.service` — starts the daemon at boot.
- the installer adds `bpf` to the kernel's LSM list (via GRUB) so BPF-LSM programs
  can attach — the `CONFIG_BPF_LSM` / `lsm=` requirement from Chapter 6.

`rz status` asks the daemon whether the kernel programs are loaded and active —
the same "are my programs in the kernel?" question you answered with `bpftool prog
list` in Lab 06.

## 16.3 Trace one rule through the shipping system

Put the whole book together with one real flow (`examples/boundary-demo.sh` is a
scripted version):

```
you:    rz file-access add ~/projects/secret.txt block
          │  (rz -> daemon over the local socket)
daemon: expand_tilde -> /home/you/projects/secret.txt
        stat() -> (dev, ino)
        write that key into the blocked_inodes MAP           [Ch 8, 11]
          │
agent:  opens /home/you/projects/secret.txt
          │  syscall crosses the boundary                     [Ch 1]
kernel: file_open hook:
          is_ai_agent(comm) || agent_descendants[pid] ?  yes [Ch 12]
          is_dentry_protected(file) ? (dev,ino) in map ? yes [Ch 2, 8, 9]
          return -EACCES                                      [Ch 9]
          reserve events ringbuf slot, record BLOCKED         [Ch 7]
          │
daemon: drains the event, logs it, shows it in the viewer     [Ch 11, 15]
```

Every label is a chapter. That single path is the entire course.

## 16.4 Run the real demo

On the VM, with the product installed (or from the repo build):

```sh
bash examples/boundary-demo.sh
```

It has an agent write a C program, compile it, and run the binary, which calls
`open()` on a protected file **with no shell and no tool in the way** — and the
kernel refuses the open. That's the demo worth running because a tool-layer filter
could not have produced it: the decision is below the program entirely, exactly
where Chapter 1 said it must be.

## Where this lives in the repo

- **Two-toolchain build** — `GPL/bpf/Makefile` (kernel), root `Cargo.toml` +
  `cargo build` (userspace), `build-deb.sh` (orchestration + layout).
- **Install-time changes** — `build-deb.sh` and the packaging scripts add the
  systemd unit, the BPF object path, and the GRUB `lsm=` edit.
- **The end-to-end demo** — `examples/boundary-demo.sh`.
- **`rz` CLI** — `cli/src/main.rs`.

## Exercise

1. `bash examples/boundary-demo.sh` on the VM. Map each line of its output to a
   chapter. Where exactly does the kernel say no?
2. In `build-deb.sh`, find where `ringzero.bpf.o` is copied into the package. Why
   is only the compiled `.o` shipped, never `ringzero.bpf.c`? (Licence split,
   Chapter 6.)
3. `rz status`. Then `sudo bpftool prog list | grep ringzero`. Confirm the CLI's
   "active" answer matches the programs actually loaded in your kernel.

---

Final chapter: **[Chapter 17 — The honest gaps](17-honest-gaps.md)**.
