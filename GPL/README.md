# GPL/ — the kernel-side code

Everything in this directory is **GPL-2.0** (see `GPL/LICENSE`). The rest of
the repository is Apache-2.0.

This split is not a preference. Linux refuses to load a BPF LSM program unless
it declares a GPL-compatible license, because these programs call GPL-only
kernel helpers. So `ringzero.bpf.c` declares `char LICENSE[] SEC("license") =
"GPL";` and carries an SPDX GPL-2.0 header, and it lives in its own directory
so the boundary is a directory boundary rather than a comment somebody has to
notice. The userspace loader links **compiled objects** only; no BPF source is
compiled into the Apache side.

## What the programs do

`ringzero.bpf.c` attaches LSM hooks and tracepoints. What they do differs, and
the difference matters:

**Refused in the kernel.** The hook returns `-EACCES` and the operation does
not happen:

- `file_open` — opening a protected file
- `inode_create`, `inode_unlink`, `inode_rename` — creating, deleting or
  renaming one

Protected files are matched by basename **and** by `(device, inode)`, so a
rename, a hardlink or a symlink reaches the same decision as the original path.

**Recorded, not refused.** The hook observes and emits an event, then returns
`0`. The action proceeds:

- `bprm_check_security` — process execution
- `socket_connect` — outbound connections
- `socket_sendmsg` — outbound sends
- `ptrace_access_check`, `task_kill`, `sb_mount`, `sb_umount`, `file_mprotect`
- `sched_process_fork`, `sched_process_exit` — process tree tracking

If you take one thing from this file: **exec and network connections are not
blocked in this release.** They are recorded and correlated. Anything that
tells you otherwise is wrong.

## Not covered in v1

- Raw-disk reads. A process reading the block device directly does not go
  through `file_open`.
- Snapshot-style reads, where a copy of the filesystem is read from elsewhere.
- Hostname-level egress control. Connections are recorded by address; there is
  no per-hostname allow-list in the kernel.

## Building

```sh
make -C GPL/bpf all      # → GPL/bpf/build/ringzero.bpf.o
```

Needs `clang`/`llvm` (14 or later), `bpftool`, `libbpf-dev`, and a kernel with
BTF at `/sys/kernel/btf/vmlinux` so `vmlinux.h` can be generated. `vmlinux.h`
is generated, never committed.

## Kernel requirements

- `CONFIG_BPF_LSM=y`
- `bpf` present in `/sys/kernel/security/lsm`, which usually means adding
  `lsm=...,bpf` to the kernel command line and rebooting
- `CONFIG_DEBUG_INFO_BTF=y`
- Kernel 6.4 or later

Loading needs root, or `CAP_BPF` plus `CAP_MAC_ADMIN`.

## Contributing here

Kernel-side changes are accepted as issues and suggestions, not pull requests,
until a CLA process exists. A mistake in this directory takes the machine down,
so the bar is higher than for the userspace side. See `CONTRIBUTING.md`.
