# Ring Zero — Linux kernel-side eBPF programs

This directory is the kernel component of Ring Zero. It is written in C,
compiled to BPF bytecode with clang, and loaded by `ringzero-daemon` at
startup (via the `aya` crate). Nothing else is loaded into the kernel: the
daemon, the desktop app, and any external detection system you connect over
webhooks only read events and return verdicts — they never run code in the
kernel.

License: GPL-2.0 (see `LICENSE` in this directory). Each program declares
`SEC("license") = "Dual BSD/GPL"`, which is what the kernel requires to use
GPL-only BPF helpers.

## Programs

| Object            | Source            | Attach points | What it does |
|-------------------|-------------------|---------------|--------------|
| `ringzero.bpf.o`  | `ringzero.bpf.c`  | LSM: `file_open`, `inode_create`, `inode_unlink`, `inode_rename`, `bprm_check_security`, `socket_connect`, `socket_sendmsg`, `file_mprotect`, `ptrace_access_check`, `task_kill`, `sb_mount`, `sb_umount`; tracepoints `sched_process_fork` / `sched_process_exit`; `cgroup/connect4`, `cgroup/connect6`, `sockops` | Identifies AI-agent processes and their descendants (taint at fork), emits file/exec/network events to a ring buffer, and enforces the policy maps below (blocked files by basename, by inode identity, by directory; blocked IPs; DLP taint). |
| `sslsniff.bpf.o`  | `sslsniff.bpf.c`  | uprobes/uretprobes on `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex` | Captures TLS plaintext at the library boundary for agent processes the daemon registers, so LLM request/response content can be inspected without a proxy or CA certificate. |
| `stdiocap.bpf.o`  | `stdiocap.bpf.c`  | tracepoints `sys_enter_read`/`sys_exit_read`, `sys_enter_write`/`sys_exit_write` | Captures terminal stdin/stdout of tracked agent processes (for agents whose TLS layer can't be probed). Loaded on demand. |

`ringzero.h` holds the event structs and enum values shared with the
daemon's Rust side (`daemon/src/ebpf_loader.rs`, `daemon/src/ssl_sniff.rs`,
`daemon/src/stdio_capture.rs`). The layouts must match exactly.

## Maps (daemon ⇄ kernel interface)

All maps are created by the daemon when it loads the objects and are only
reachable by processes with `CAP_BPF`/`CAP_SYS_ADMIN` (root). Policy maps are
written by the daemon; the kernel only reads them.

`ringzero.bpf.o`:

| Map | Type | Purpose |
|-----|------|---------|
| `events` | ringbuf (256 KiB) | file / exec / network / tamper events → daemon |
| `send_events` | ringbuf (512 KiB) | first 4 KiB of outbound sends for DLP inspection |
| `config_map` | array[1] | `enabled`, `monitor_all`, `enforce_blocks`, `dlp_enabled` |
| `blocked_files` | hash | basenames agents may not open/create/delete/rename |
| `blocked_inodes` | hash | (dev, ino) identities — closes rename/hardlink bypass |
| `blocked_dir_inodes` / `allowed_dir_inodes` | hash | directory-level block / "project directory only" restriction |
| `blocked_processes`, `monitored_processes` | hash | comm-keyed block / extra-monitor lists |
| `blocked_ips`, `key_allowed_ips`, `blocked_sends` | hash | network policy and DLP key routing |
| `agent_descendants` | LRU hash | PIDs tainted as part of an agent's process tree |
| `tainted_pids` | hash | DLP taint (process read sensitive data) |
| `contained_pids`, `contained_allowed_exec`, `daemon_pid_map` | hash / array | containment + tamper protection |
| `proxy_config_map`, `orig_dest_map`, `port_to_cookie` | array / hash | optional cgroup connect redirect (unused unless a local proxy is configured) |
| `rate_limit`, `drop_counters`, `file_open_block_dedup` | per-CPU array / LRU | flood control and drop accounting |

`sslsniff.bpf.o`: `ssl_events` (ringbuf), `ssl_traced_pids`, `ssl_config`,
per-thread scratch maps (`ssl_ptrs`, `bufs`, `readbytes_ptrs`), drop and
debug counters.

`stdiocap.bpf.o`: `stdio_events` (ringbuf), `tracked_pids`, `pending_io`,
`stdio_config`.

## Enforcement status

Blocking is enforced in the kernel (`-EACCES`) for file open / create /
delete / rename of protected files, inodes and directories when
`config_map.enforce_blocks = 1`. The network, exec, DLP-taint, containment
and tamper-protection hooks currently emit events only (the code paths that
would return `-EACCES` are marked `observe-only` in the source). Read the
source before relying on any hook for enforcement.

## Kernel requirements

- Linux 5.8 or newer (BPF LSM, ring buffers, CO-RE).
- `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y` in the running kernel.
- `bpf` present in the `lsm=` boot parameter (check
  `cat /sys/kernel/security/lsm`). Most distributions compile BPF LSM in but
  do not enable it by default; the `.deb` postinst adds it to GRUB and asks
  for a reboot. Without it the daemon runs in observe-only userspace mode.
- Tested on Ubuntu 24.04 (kernel 6.8) x86_64 and aarch64.

## Building

Build dependencies: `clang` and `llvm` (14 or newer), `bpftool` (Debian/Ubuntu:
`linux-tools-$(uname -r)` or the `bpftool` package), `libbpf-dev`.

```bash
sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r)
make            # generates vmlinux.h from /sys/kernel/btf/vmlinux, builds build/*.bpf.o
sudo make install   # copies the objects to /usr/lib/ringzero/
make clean
```

`vmlinux.h` is generated from the running kernel's BTF and is not checked in.
The objects use CO-RE relocations, so an object built on one kernel loads on
other kernels that ship BTF.

The daemon looks for the objects in `/usr/lib/ringzero/` (override with the
`RINGZERO_BPF_PATH` environment variable for `ringzero.bpf.o`).
