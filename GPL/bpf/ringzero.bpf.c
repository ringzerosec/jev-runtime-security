// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Ring Zero Security. Kernel-side component of Ring Zero for Linux.
//
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 as published by the
// Free Software Foundation. See LICENSE in this directory.
// Ring Zero Linux Driver - eBPF Programs
// Observe-first architecture: report events to daemon, block only what's in blocklist

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define EACCES 13
#define AF_INET 2
#define AF_INET6 10

#define MAX_PATH_LEN 128
#define MAX_COMM_LEN 16
#define MAX_ARGS_LEN 256

// Event types
enum event_type {
    EVENT_FILE_OPEN = 1,
    EVENT_FILE_CREATE = 2,
    EVENT_FILE_DELETE = 3,
    EVENT_FILE_RENAME = 4,
    EVENT_FILE_WRITE = 5,
    EVENT_PROCESS_EXEC = 10,
    EVENT_PROCESS_FORK = 11,
    EVENT_PROCESS_EXIT = 12,
    EVENT_NETWORK_CONNECT = 20,
    EVENT_NETWORK_SEND = 30,
    EVENT_MPROTECT_WX = 25,
};

// Event data sent to userspace
struct event {
    u32 type;
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 timestamp;
    char comm[MAX_COMM_LEN];
    char path[MAX_PATH_LEN];
    char parent_comm[MAX_COMM_LEN];
    u32 remote_ip;
    u16 remote_port;
    u16 local_port;
    u8 protocol;
    u8 blocked;  // 1 if we blocked this
    char args[MAX_ARGS_LEN];  // command-line args (exec events only)
};

// Ring buffer for events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// =============================================================================
// POLICY MAPS - Daemon populates these, kernel checks them
// =============================================================================

// Blocked file paths (exact match on filename)
// Key: filename (e.g., "id_rsa", "credentials", ".env")
// Value: 1 = blocked
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, char[MAX_PATH_LEN]);
    __type(value, u8);
} blocked_files SEC(".maps");

// Blocked files keyed by IDENTITY (device + inode), not basename. This closes
// the rename/hardlink bypass: `ln ~/.ssh/id_rsa /tmp/x; cat /tmp/x` reaches the
// SAME inode under a new basename, so a basename-only block (above) misses it.
// The daemon resolves each concrete sensitive file to (s_dev, i_ino) and seeds
// this map; the kernel reads the opened file's identity and matches here.
// dev is the kernel-encoded device (MKDEV: (major<<20)|minor) — the daemon must
// convert the userspace stat st_dev to this form. ino alone can collide across
// filesystems, so we key on the pair. Hardlinks are same-fs by definition and a
// within-fs `mv` preserves the inode, so (dev,ino) catches both bypass classes.
struct ino_key {
    __u64 ino;
    __u32 dev;
    __u32 _pad;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ino_key);
    __type(value, u8);
} blocked_inodes SEC(".maps");

// ── Quarantine: verdicts on files an agent wrote ────────────────────────────
//
// PRECOMPUTE THEN A BIT. Content cannot be judged at open time, because at open
// the bytes do not exist yet. So userspace scans a file when the write closes
// and stores the answer here; the kernel later reads one bit at kernel speed.
// No model is called from this path and the syscall never waits on anything.
//
// TWO PIECES OF STATE, NOT ONE, and the difference is the whole safety
// argument:
//
//   enforce  Refuse to open or exec this file. ONLY a deterministic pattern
//            match may set this. A model may never set it, directly or by
//            raising a severity, because here "more severe" means "refuse to
//            run" rather than "show a human".
//   review   A human should look at this. A model MAY set this, and may raise
//            `severity` in the record. Setting it changes nothing the kernel
//            does.
//
// Keyed like blocked_inodes, on (dev, ino), so a rename or a hardlink cannot
// shake the verdict off the content it was made about.
struct write_verdict {
    __u8 enforce;   // deterministic only
    __u8 review;    // model may set
    __u8 severity;  // 0..3, recorded, never enforced on
    __u8 _pad;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct ino_key);
    __type(value, struct write_verdict);
} agent_write_verdicts SEC(".maps");

// ── Who opened this file for writing ────────────────────────────────────────
//
// ATTRIBUTION HAS TO HAPPEN WHILE THE WRITER IS ALIVE. Userspace learns a write
// finished from fanotify CLOSE_WRITE, which arrives AFTER the close — and
// `cat > file` has exited by then. Worse, `handle_exit` below deletes the pid
// from `agent_descendants` on exit, so by the time the event is read there is
// nothing left to look the process up in. Not intermittently: for a
// short-lived writer it loses every time.
//
// So the decision is made here, at open, where the process is running and the
// agent test has already been done, and it is keyed on the FILE rather than on
// the process. Userspace then never has to resolve a dead pid.
//
// LRU, so a machine that writes a great many files cannot grow this without
// bound; an evicted entry means a write that cannot be attributed, which is the
// same as not being an agent write, which is the safe direction.
struct write_origin {
    /// The process that opened the file. Often a helper: `cp`, `tee`, `cat`.
    __u32 pid;
    /// The agent this write belongs to. `cp` on its own tells a reviewer
    /// nothing they can act on, and two agents both shelling out to `cp` are
    /// indistinguishable, so the root is recorded here at the same moment.
    __u32 agent_pid;
    __u64 opened_ns;
    char comm[MAX_COMM_LEN];
    char agent_comm[MAX_COMM_LEN];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ino_key);
    __type(value, struct write_origin);
} agent_write_origin SEC(".maps");

// From include/linux/fs.h. Defined here rather than relied on from vmlinux.h,
// which does not carry the FMODE_* enum on every kernel we build against.
#define RZ_FMODE_WRITE 0x2

// Blocked process names
// Key: comm (e.g., "curl", "wget")
// Value: 1 = blocked
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, char[MAX_COMM_LEN]);
    __type(value, u8);
} blocked_processes SEC(".maps");

// Blocked network destinations (IP:port)
// Key: IP address (network byte order)
// Value: 1 = blocked
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, u8);
} blocked_ips SEC(".maps");

// Monitored processes - only monitor these (if empty, monitor all)
// Key: comm (e.g., "node", "python")
// Value: 1 = monitor this process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, char[MAX_COMM_LEN]);
    __type(value, u8);
} monitored_processes SEC(".maps");

// PID-keyed taint for every process spawned within an AI agent's subtree.
// Tagged at FORK time (handle_fork) and persisted by PID, so it survives a child
// later reparenting to init (systemd-run/daemonize/double-fork/nohup move
// real_parent, but the PID stays tainted) — this is what makes the ancestry
// check evasion-resistant. Also makes file_open an O(1) lookup instead of a live
// parent walk. LRU so a missed exit can never leak the map.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, u32);
    __type(value, u8);
} agent_descendants SEC(".maps");

// Tainted process info (DLP)
struct taint_info {
    u8 tainted;           // 1 if process read sensitive data
    u8 has_keys;          // 1 if process accessed credential files
    u16 _pad;
    u32 taint_time;       // When tainted (ktime seconds)
};

// Configuration
struct config {
    u8 enabled;           // Master switch
    u8 monitor_all;       // If 1, monitor all processes. If 0, only monitored_processes
    u8 enforce_blocks;    // If 1, actually block. If 0, just observe/log
    u8 dlp_enabled;       // If 1, enable DLP taint tracking
    // Quarantine of agent-written files. SEPARATE from enforce_blocks on
    // purpose: this is a newer and sharper thing than the file blocks, it is
    // OFF by default, and an operator must be able to run every other kind of
    // enforcement without it. Takes the first reserved byte, so the struct
    // size and the Rust mirror in ebpf_loader.rs are unchanged.
    u8 quarantine_enforce;
    // Egress narrowing on taint. SEPARATE from enforce_blocks and OFF by
    // default, exactly like quarantine_enforce: this is the socket_connect
    // hook flipping from observe to enforce, and it must be an operator's
    // deliberate choice. Takes the second reserved byte, so the struct size
    // and the Rust mirror are unchanged.
    u8 egress_enforce;
    // Raise taint when an agent-tree process connects off-allowlist. This is
    // the PRIMARY provenance signal for external ingestion, and it lives here
    // rather than in userspace because a real agent reaches the network
    // through whatever is to hand — a fetch tool, curl in a shell, a script it
    // wrote a minute ago — and all of them must call connect(2). Matching tool
    // names in a transcript misses most of them; this cannot be routed around.
    // SEPARATE from egress_enforce so an operator can measure how often a
    // normal session taints before enforcing on it. Takes the third reserved
    // byte; the struct size and the Rust mirror are unchanged.
    u8 taint_on_egress;
    u8 _reserved[1];
};

// DLP: Tainted PIDs (processes that read sensitive/credential files)
// Key: PID
// Value: taint_info struct
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, struct taint_info);
} tainted_pids SEC(".maps");

// DLP: Allowed IPs for tainted processes (key routing whitelist)
// If a tainted process tries to connect to an IP NOT in this map, block it
// Key: IP address (network byte order)
// Value: 1 = allowed for tainted processes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, u8);
} key_allowed_ips SEC(".maps");

// Egress allowlist for tainted processes: destinations an operator has approved
// for a process that ingested external content. Loopback and the LLM API
// endpoints are allowed without appearing here (loopback inline, LLM IPs via
// key_allowed_ips, which the daemon already seeds), so this map is only the
// operator's additions. Value 1 = allowed.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, u8);
} egress_allowed_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct config);
} config_map SEC(".maps");

// =============================================================================
// TLS Proxy Redirect Maps (cgroup/connect + sockops)
// =============================================================================

// Proxy configuration (daemon controls this)
struct proxy_config {
    u32 proxy_ip4;        // Proxy IPv4 (network byte order), e.g., 127.0.0.1
    u16 proxy_port;       // Proxy port (host byte order), e.g., 8443
    u8 enabled;           // 1 = redirect AI agent HTTPS to proxy
    u8 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct proxy_config);
} proxy_config_map SEC(".maps");

// Original destination saved before connect4/connect6 rewrites
struct orig_dest_value {
    u16 family;           // AF_INET or AF_INET6
    u16 orig_port;        // Original port (host byte order)
    u32 orig_ip4;         // Original IPv4 (network byte order)
    u8 orig_ip6[16];      // Original IPv6 (network byte order)
};

// cookie -> original destination (so proxy can recover where to connect)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u64);
    __type(value, struct orig_dest_value);
} orig_dest_map SEC(".maps");

// client local_port -> socket cookie (proxy looks up accepted conn's peer port)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, u64);
} port_to_cookie SEC(".maps");

// =============================================================================
// DLP Content Inspection Maps
// =============================================================================

#define MAX_SEND_DATA 4096

// Send event: outbound data captured for content inspection
struct send_event {
    u32 type;             // EVENT_NETWORK_SEND
    u32 pid;
    u32 uid;
    u32 remote_ip;
    u16 remote_port;
    u16 data_len;         // Bytes captured (up to MAX_SEND_DATA)
    u32 total_len;        // Total send size
    u8 blocked;           // 1 if blocked by cache
    u8 _pad[3];
    char comm[MAX_COMM_LEN];
    char data[MAX_SEND_DATA];
};

// Separate ring buffer for send events (larger — 512KB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} send_events SEC(".maps");

// Block cache: (pid, dest_ip) → blocked (1 = block future sends)
struct block_key {
    u32 pid;
    u32 ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct block_key);
    __type(value, u8);
} blocked_sends SEC(".maps");

// Allowed directory inodes — when non-empty, agent file opens OUTSIDE these
// directories are blocked. Keyed by (dev, ino) of the directory. The daemon
// resolves the configured allowed path to its inode identity.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct ino_key);
    __type(value, u8);
} allowed_dir_inodes SEC(".maps");

// Blocked directory inodes — agent file opens of files INSIDE these directories
// are blocked. Keyed by (dev, ino) of the directory. Sentinel key (ino=0) flags
// that at least one blocked-dir rule is active.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct ino_key);
    __type(value, u8);
} blocked_dir_inodes SEC(".maps");

// =============================================================================
// File-open dedup — suppress repeated blocked file_open events per PID
// Key: PID, Value: 1 (already reported a block for this PID)
// =============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, u8);
} file_open_block_dedup SEC(".maps");

// =============================================================================
// Per-CPU rate limiter — prevents event flood from overwhelming daemon
// Key: 0 = current epoch second, 1 = event count this second
//
// Per-CPU instead of shared: the previous shared ARRAY raced across CPUs
// (two CPUs could both observe a new epoch, both reset, both increment from
// zero, double-counting the budget) AND every CPU contended a single counter
// on each event. With PERCPU_ARRAY each CPU has its own cell — no atomics,
// no contention. The effective cap becomes MAX_EVENTS_PER_SEC × num_online_cpus.
// =============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} rate_limit SEC(".maps");

// Per-CPU cap; system-wide effective cap = MAX_EVENTS_PER_SEC * num_cpus.
// Bumped from 50 to 500/CPU so realistic workloads don't get silently dropped.
#define MAX_EVENTS_PER_SEC 500

static __always_inline int rate_limit_ok(void) {
    u32 key_epoch = 0, key_count = 1;
    u64 now_sec = bpf_ktime_get_ns() / 1000000000ULL;

    u64 *last_epoch = bpf_map_lookup_elem(&rate_limit, &key_epoch);
    u64 *count = bpf_map_lookup_elem(&rate_limit, &key_count);
    if (!last_epoch || !count) return 1; // map not ready, allow

    if (*last_epoch != now_sec) {
        // New second — reset this CPU's bucket. No atomics needed: we're the
        // only writer on this per-CPU slot.
        *last_epoch = now_sec;
        *count = 0;
        return 1;
    }

    u64 cur = *count;
    *count = cur + 1;
    return (cur < MAX_EVENTS_PER_SEC) ? 1 : 0;
}

// =============================================================================
// Drop counters — tracks ring buffer overflow (events lost)
// =============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);  // [0] = events dropped, [1] = send_events dropped
    __type(key, u32);
    __type(value, u64);
} drop_counters SEC(".maps");

static __always_inline void inc_drop_counter(u32 idx) {
    u64 *cnt = bpf_map_lookup_elem(&drop_counters, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

// =============================================================================
// Helpers
// =============================================================================

static __always_inline struct config *get_config(void) {
    u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

static __always_inline struct proxy_config *get_proxy_config(void) {
    u32 key = 0;
    return bpf_map_lookup_elem(&proxy_config_map, &key);
}

// Check if this is an AI agent process or child of one
static __always_inline int is_ai_agent(const char *comm) {
    // Known AI agent process names

    // "claude" (matches claude, claude.real, claude-code, etc.)
    if (comm[0] == 'c' && comm[1] == 'l' && comm[2] == 'a' && comm[3] == 'u' && comm[4] == 'd' && comm[5] == 'e')
        return 1;

    // "cursor"
    if (comm[0] == 'c' && comm[1] == 'u' && comm[2] == 'r' && comm[3] == 's' && comm[4] == 'o' && comm[5] == 'r')
        return 1;

    // "copilot"
    if (comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'p' && comm[3] == 'i' && comm[4] == 'l' && comm[5] == 'o')
        return 1;

    // "codex"
    if (comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'e' && comm[4] == 'x')
        return 1;

    // "devin"
    if (comm[0] == 'd' && comm[1] == 'e' && comm[2] == 'v' && comm[3] == 'i' && comm[4] == 'n')
        return 1;

    // "aider"
    if (comm[0] == 'a' && comm[1] == 'i' && comm[2] == 'd' && comm[3] == 'e' && comm[4] == 'r')
        return 1;

    // "windsurf" (Codeium IDE)
    if (comm[0] == 'w' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'd' && comm[4] == 's')
        return 1;

    // "agy" (Antigravity CLI — Google Gemini successor)
    if (comm[0] == 'a' && comm[1] == 'g' && comm[2] == 'y')
        return 1;

    // "antigravity"
    if (comm[0] == 'a' && comm[1] == 'n' && comm[2] == 't' && comm[3] == 'i' && comm[4] == 'g')
        return 1;

    // "gemini" (legacy)
    if (comm[0] == 'g' && comm[1] == 'e' && comm[2] == 'm' && comm[3] == 'i' && comm[4] == 'n' && comm[5] == 'i')
        return 1;

    // "gemini" (Gemini CLI)
    if (comm[0] == 'g' && comm[1] == 'e' && comm[2] == 'm' && comm[3] == 'i' && comm[4] == 'n' && comm[5] == 'i')
        return 1;

    // "agent" — Cursor CLI binary (cursor-agent renames to "agent")
    if (comm[0] == 'a' && comm[1] == 'g' && comm[2] == 'e' && comm[3] == 'n' && comm[4] == 't' && comm[5] == '\0')
        return 1;

    // "MainThread" — Cursor/Python agent main process (Python renames comm via prctl).
    // Must be in is_ai_agent (not just is_runtime) because this IS the top-level
    // agent process — it has no agent ancestor, so is_agent_child() would fail.
    if (comm[0] == 'M' && comm[1] == 'a' && comm[2] == 'i' && comm[3] == 'n' &&
        comm[4] == 'T' && comm[5] == 'h' && comm[6] == 'r' && comm[7] == 'e')
        return 1;

    // "opencode"
    if (comm[0] == 'o' && comm[1] == 'p' && comm[2] == 'e' && comm[3] == 'n' && comm[4] == 'c')
        return 1;

    // "hermes"
    if (comm[0] == 'h' && comm[1] == 'e' && comm[2] == 'r' && comm[3] == 'm' && comm[4] == 'e' && comm[5] == 's')
        return 1;

    // Any "claw"-family agent: comm CONTAINS the substring "claw"
    // (nanoclaw, nemoclaw, openclaw, closedclaw, trustclaw, ...). Bounded
    // substring scan over the 16-byte comm; unrolled for the verifier.
    #pragma unroll
    for (int i = 0; i + 3 < MAX_COMM_LEN; i++) {
        if (comm[i] == '\0')
            break;
        if (comm[i] == 'c' && comm[i+1] == 'l' && comm[i+2] == 'a' && comm[i+3] == 'w')
            return 1;
    }

    return 0;
}

// Check if any ancestor (up to 4 levels) is an AI agent
// Raise taint on a pid. Raise-only: an existing entry is never downgraded, and
// has_keys is never cleared, because taint may narrow authority and never widen
// it. The kernel drops the entry on process exit, which is not a downgrade.
// Drop counter slot 1: taint insertions the map refused. `tainted_pids` is a
// plain HASH capped at 10000 with no eviction, so once it fills, new taint is
// silently lost — which would look exactly like a process that never ingested
// anything. Counted so the failure is visible instead of invisible.
#define DROP_TAINT_INSERT 1

static __always_inline void raise_taint(u32 pid, u32 now_s) {
    struct taint_info *ex = bpf_map_lookup_elem(&tainted_pids, &pid);
    if (!ex) {
        struct taint_info ni = {};
        ni.tainted = 1;
        ni.taint_time = now_s;
        if (bpf_map_update_elem(&tainted_pids, &pid, &ni, BPF_ANY) < 0)
            inc_drop_counter(DROP_TAINT_INSERT);
    } else if (!ex->tainted) {
        struct taint_info ni = *ex;
        ni.tainted = 1;
        bpf_map_update_elem(&tainted_pids, &pid, &ni, BPF_ANY);
    }
}

static __always_inline int is_agent_child(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Walk up to 4 levels: parent, grandparent, etc.
    // This catches chains like: claude -> snap-confine -> snap-exec -> curl
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (!parent) return 0;
        // Stop at init (PID 1) to avoid walking the entire tree
        u32 ppid = BPF_CORE_READ(parent, tgid);
        if (ppid <= 1) return 0;
        char pcomm[MAX_COMM_LEN] = {};
        bpf_probe_read_kernel_str(pcomm, sizeof(pcomm), BPF_CORE_READ(parent, comm));
        if (is_ai_agent(pcomm))
            return 1;
        task = parent;
    }
    return 0;
}

// Which agent does the current process belong to?
//
// `is_agent_child` above answers yes or no. This answers WHICH, because a
// finding that says `cp` names nothing a person can act on. The current process
// is checked first: an agent writing its own file is its own root.
//
// Returns 1 and fills the outputs when an agent is found, 0 otherwise.
static __always_inline int find_agent_root(u32 *root_pid, char *root_comm, int comm_len) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    char cur[MAX_COMM_LEN] = {};
    bpf_get_current_comm(cur, sizeof(cur));
    if (is_ai_agent(cur)) {
        *root_pid = bpf_get_current_pid_tgid() >> 32;
        bpf_probe_read_kernel_str(root_comm, comm_len, cur);
        return 1;
    }

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (!parent) return 0;
        u32 ppid = BPF_CORE_READ(parent, tgid);
        if (ppid <= 1) return 0;
        char pcomm[MAX_COMM_LEN] = {};
        bpf_probe_read_kernel_str(pcomm, sizeof(pcomm), BPF_CORE_READ(parent, comm));
        if (is_ai_agent(pcomm)) {
            *root_pid = ppid;
            bpf_probe_read_kernel_str(root_comm, comm_len, pcomm);
            return 1;
        }
        task = parent;
    }
    return 0;
}

// Check if process is a runtime (node/python) that might be an AI agent child
static __always_inline int is_runtime(const char *comm) {
    if (comm[0] == 'n' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'e')
        return 1;
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't' && comm[3] == 'h' && comm[4] == 'o' && comm[5] == 'n')
        return 1;
    if (comm[0] == 'e' && comm[1] == 'l' && comm[2] == 'e' && comm[3] == 'c' && comm[4] == 't' && comm[5] == 'r')
        return 1;
    // Sandbox wrappers used by AI agents (Codex uses bwrap for tool execution)
    if (comm[0] == 'b' && comm[1] == 'w' && comm[2] == 'r' && comm[3] == 'a' && comm[4] == 'p')
        return 1;
    if (comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'e' && comm[4] == 'x' && comm[5] == '-')
        return 1; // codex-linux-san, codex-main, etc.
    // bash/sh — tool commands run in shells
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h')
        return 1;
    if (comm[0] == 's' && comm[1] == 'h' && comm[2] == '\0')
        return 1;
    return 0;
}

// Process-laundering tools: an agent uses these to spawn work OUTSIDE its own
// process tree (the worker is started by systemd/atd/cron, so it has no agent
// ancestor and taint-at-fork can't reach it). A coding agent has no legitimate
// reason to invoke these — treat exec of one by an agent/descendant as evasion.
static __always_inline int is_launder_tool(const char *name) {
    // Only DELEGATED-spawn tools, where a system service (systemd/atd/cron) spawns
    // the worker with clean lineage that taint-at-fork can't reach. NOTE: setsid /
    // double-fork / nohup are deliberately NOT here — those daemonize within the
    // agent's own subtree, so the worker is already tainted at fork (proven by the
    // daemonize test) and blocking the (very common) setsid exec would be both
    // redundant and over-broad.
    // systemd-run (matches the "systemd-" prefix)
    if (name[0]=='s'&&name[1]=='y'&&name[2]=='s'&&name[3]=='t'&&name[4]=='e'&&name[5]=='m'&&name[6]=='d'&&name[7]=='-')
        return 1;
    // at / batch (atd-scheduled execution)
    if (name[0]=='a'&&name[1]=='t'&&name[2]=='\0')
        return 1;
    if (name[0]=='b'&&name[1]=='a'&&name[2]=='t'&&name[3]=='c'&&name[4]=='h')
        return 1;
    // crontab
    if (name[0]=='c'&&name[1]=='r'&&name[2]=='o'&&name[3]=='n'&&name[4]=='t')
        return 1;
    return 0;
}

static __always_inline int should_monitor_process(const char *comm) {
    struct config *cfg = get_config();
    if (!cfg)
        return 0;

    // If monitor_all is set, monitor everything (for debugging)
    if (cfg->monitor_all)
        return 1;

    // Check if this is a known AI agent binary
    if (is_ai_agent(comm))
        return 1;

    // Check if this is ANY child process spawned by an AI agent
    // (covers bash, touch, cat, grep, etc. — not just node/python)
    if (is_agent_child())
        return 1;

    // Otherwise check if this process is in the monitored list
    u8 *val = bpf_map_lookup_elem(&monitored_processes, comm);
    return val && *val;
}

// True if the CURRENT process should be monitored: a known agent by comm, a
// monitored runtime, OR a tainted agent-descendant (the fork-tagged tree, incl.
// pids the daemon marks via TrackAgentPid for cmdline-detected agents). The
// taint check is what captures a Node/Python agent's CHILD processes — the ones
// that actually create/delete files, connect out, and exec — whose comm isn't an
// agent name but whose pid is in agent_descendants. Without it, only the agent's
// own pid was monitored, so the session showed almost no activity.
static __always_inline int is_monitored_current(const char *comm) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    return is_ai_agent(comm) || should_monitor_process(comm)
        || bpf_map_lookup_elem(&agent_descendants, &pid) != 0;
}

// Is this dentry inside a blocked directory?
//
// FAILS CLOSED ON TRUNCATION, and that is the point. The walk is bounded at
// MAX_DIR_WALK because the verifier needs a fixed bound, and it used to simply
// fall out of the loop and report "not blocked". A file thirteen directories
// under a blocked root was therefore not blocked — the depth of a path decided
// whether policy applied to it, which is not a property anyone would choose.
//
// Running out of levels means we could not PROVE the file is outside a blocked
// directory. That is a denial, not a pass.
//
// Returns 1 to block, 0 to allow.
#define MAX_DIR_WALK 12
static __always_inline int dentry_under_blocked_dir(struct dentry *dentry) {
    struct ino_key bdir_probe = {};
    if (!bpf_map_lookup_elem(&blocked_dir_inodes, &bdir_probe))
        return 0; // no directory blocks configured at all

    struct dentry *walk = BPF_CORE_READ(dentry, d_parent);
    #pragma unroll
    for (int i = 0; i < MAX_DIR_WALK; i++) {
        if (!walk)
            return 0; // reached the top cleanly: genuinely not inside one
        struct dentry *wp = BPF_CORE_READ(walk, d_parent);
        if (wp == walk)
            return 0; // root reached cleanly
        struct inode *dir_inode = BPF_CORE_READ(walk, d_inode);
        if (dir_inode) {
            struct ino_key dk = {};
            dk.ino = BPF_CORE_READ(dir_inode, i_ino);
            dk.dev = BPF_CORE_READ(dir_inode, i_sb, s_dev);
            if (bpf_map_lookup_elem(&blocked_dir_inodes, &dk))
                return 1;
        }
        walk = wp;
    }
    // Ran out of levels with more path above us. Unproven, so denied.
    return 1;
}

// Check if a dentry is protected — either its basename is in blocked_files,
// its inode is in blocked_inodes, or it lives inside a blocked directory.
// Used by file_open, inode_create, inode_unlink, inode_rename to enforce
// protection on reads, writes, deletes, and moves.
static __always_inline int is_dentry_protected(struct dentry *dentry) {
    if (!dentry)
        return 0;

    // Check basename against blocked_files
    char name[MAX_PATH_LEN] = {};
    bpf_probe_read_kernel_str(name, MAX_PATH_LEN, BPF_CORE_READ(dentry, d_name.name));
    if (bpf_map_lookup_elem(&blocked_files, name))
        return 1;

    // Check inode against blocked_inodes (rename/hardlink-proof)
    struct inode *f_inode = BPF_CORE_READ(dentry, d_inode);
    if (f_inode) {
        struct ino_key ik = {};
        ik.ino = BPF_CORE_READ(f_inode, i_ino);
        ik.dev = BPF_CORE_READ(f_inode, i_sb, s_dev);
        if (bpf_map_lookup_elem(&blocked_inodes, &ik))
            return 1;
    }

    // Check if inside a blocked directory. Fails closed on truncation.
    if (dentry_under_blocked_dir(dentry))
        return 1;

    return 0;
}

// Check if filename is sensitive (worth reporting)
static __always_inline int is_sensitive_file(const char *filename) {
    // Check for sensitive filenames
    // id_rsa, id_ed25519, credentials, .env, config, passwd, shadow, etc.

    // SSH keys
    if (filename[0] == 'i' && filename[1] == 'd' && filename[2] == '_')
        return 1;

    // .env files (exact or prefix like .env.local)
    if (filename[0] == '.' && filename[1] == 'e' && filename[2] == 'n' && filename[3] == 'v')
        return 1;

    // Files ending in .env (e.g., test.env, prod.env)
    // Check common positions for ".env" suffix
    #pragma unroll
    for (int i = 1; i < 60; i++) {
        if (filename[i] == '\0' && i >= 4) {
            if (filename[i-4] == '.' && filename[i-3] == 'e' && filename[i-2] == 'n' && filename[i-1] == 'v')
                return 1;
            break;
        }
        if (filename[i] == '\0') break;
    }


    // credentials
    if (filename[0] == 'c' && filename[1] == 'r' && filename[2] == 'e' && filename[3] == 'd')
        return 1;

    // shadow (not passwd — too noisy, every getent reads it)
    if (filename[0] == 's' && filename[1] == 'h' && filename[2] == 'a' && filename[3] == 'd')
        return 1;

    // token / secret / key files
    if (filename[0] == 't' && filename[1] == 'o' && filename[2] == 'k' && filename[3] == 'e')
        return 1;
    if (filename[0] == 's' && filename[1] == 'e' && filename[2] == 'c' && filename[3] == 'r')
        return 1;
    if (filename[0] == 'k' && filename[1] == 'e' && filename[2] == 'y')
        return 1;

    // AWS credentials
    if (filename[0] == 'a' && filename[1] == 'w' && filename[2] == 's')
        return 1;

    // .npmrc, .netrc, .pypirc (dotfile RC configs with secrets)
    if (filename[0] == '.') {
        // .npmrc
        if (filename[1] == 'n' && filename[2] == 'p' && filename[3] == 'm' && filename[4] == 'r' && filename[5] == 'c')
            return 1;
        // .netrc
        if (filename[1] == 'n' && filename[2] == 'e' && filename[3] == 't' && filename[4] == 'r' && filename[5] == 'c')
            return 1;
        // .pypirc
        if (filename[1] == 'p' && filename[2] == 'y' && filename[3] == 'p' && filename[4] == 'i' && filename[5] == 'r')
            return 1;
        // .docker (docker config)
        if (filename[1] == 'd' && filename[2] == 'o' && filename[3] == 'c' && filename[4] == 'k' && filename[5] == 'e')
            return 1;
        // .kube (kube config)
        if (filename[1] == 'k' && filename[2] == 'u' && filename[3] == 'b' && filename[4] == 'e')
            return 1;
    }

    // authorized_keys, known_hosts
    if (filename[0] == 'a' && filename[1] == 'u' && filename[2] == 't' && filename[3] == 'h')
        return 1;
    if (filename[0] == 'k' && filename[1] == 'n' && filename[2] == 'o' && filename[3] == 'w' && filename[4] == 'n')
        return 1;

    // ld.so.preload — preload-based code injection / persistence (T1574.006).
    // Match "ld.so.pr" specifically so the loader's constant ld.so.cache reads
    // don't flood the daemon.
    if (filename[0] == 'l' && filename[1] == 'd' && filename[2] == '.'
        && filename[3] == 's' && filename[4] == 'o' && filename[5] == '.'
        && filename[6] == 'p' && filename[7] == 'r')
        return 1;

    // "config" in a sensitive context (kube/docker config files)
    // Only exact "config" to avoid matching random config files
    if (filename[0] == 'c' && filename[1] == 'o' && filename[2] == 'n' && filename[3] == 'f'
        && filename[4] == 'i' && filename[5] == 'g' && filename[6] == '\0')
        return 1;

    return 0;
}

static __always_inline void fill_process_info(struct event *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent) {
        e->ppid = BPF_CORE_READ(parent, tgid);
        bpf_probe_read_kernel_str(&e->parent_comm, sizeof(e->parent_comm),
                                   BPF_CORE_READ(parent, comm));
    }
}

// =============================================================================
// LSM Hooks
// =============================================================================

// Mark the current PID as DLP-tainted: it has read sensitive data, so the
// exfil vectors (spawning a child, egressing to a non-whitelisted IP) are now
// barred for it and its forked descendants. Idempotent.
static __always_inline void dlp_taint_current(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct taint_info ti = {};
    ti.tainted = 1;
    ti.has_keys = 1;
    ti.taint_time = (u32)(bpf_ktime_get_ns() / 1000000000ULL);
    bpf_map_update_elem(&tainted_pids, &pid, &ti, BPF_ANY);
}

SEC("lsm/file_open")
int BPF_PROG(ringzero_file_open, struct file *file) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 0;

    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    // Only monitor AI agent processes and their direct file-reading children.
    // We use a tighter filter here than bprm_check because file_open is called
    // for EVERY file open syscall on the system — full should_monitor_process()
    // ancestry walk is too expensive and generates too much noise from snap/getent.
    // Monitored if this is an agent process itself OR a PID tainted as an
    // agent descendant (tagged at fork — survives reparenting, O(1) lookup).
    u32 cur_pid = bpf_get_current_pid_tgid() >> 32;
    int agent = is_ai_agent(comm) || bpf_map_lookup_elem(&agent_descendants, &cur_pid);
    if (!agent) {
        // Self-healing fallback for trees that predate the daemon (or a restart),
        // where the fork tag was never recorded: language runtimes (node/python/
        // electron — IDE extension hosts) and read utilities (cat/head/tail/ssh)
        // get a one-time ancestry walk; if an AI-agent ancestor is found we TAINT
        // the PID so every later open is O(1) and survives reparenting. Everything
        // else is rejected cheaply so this hot path stays fast.
        int is_reader = (comm[0] == 'c' && comm[1] == 'a' && comm[2] == 't' && comm[3] == '\0')
                     || (comm[0] == 'h' && comm[1] == 'e' && comm[2] == 'a' && comm[3] == 'd')
                     || (comm[0] == 't' && comm[1] == 'a' && comm[2] == 'i' && comm[3] == 'l')
                     || (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h'); // SSH for lateral movement
        if (!is_reader && !is_runtime(comm))
            return 0;
        if (!is_agent_child())
            return 0;
        u8 one = 1;
        bpf_map_update_elem(&agent_descendants, &cur_pid, &one, BPF_ANY);
    }

    // ── Record an agent opening a file for writing ────────────────────────
    //
    // Everything above has already established this process is in an agent
    // tree, so this costs nothing for ordinary processes. The entry is what
    // lets userspace attribute the CLOSE_WRITE it will see later, after this
    // process may well have exited.
    {
        unsigned int f_mode = BPF_CORE_READ(file, f_mode);
        if (f_mode & RZ_FMODE_WRITE) {
            struct inode *w_inode = BPF_CORE_READ(file, f_inode);
            if (w_inode) {
                struct ino_key wk = {};
                wk.ino = BPF_CORE_READ(w_inode, i_ino);
                wk.dev = BPF_CORE_READ(w_inode, i_sb, s_dev);
                struct write_origin wo = {};
                wo.pid = cur_pid;
                wo.opened_ns = bpf_ktime_get_ns();
                bpf_get_current_comm(wo.comm, sizeof(wo.comm));
                // Who this write belongs to, not just who performed it.
                u32 root_pid = 0;
                char root_comm[MAX_COMM_LEN] = {};
                if (find_agent_root(&root_pid, root_comm, sizeof(root_comm))) {
                    wo.agent_pid = root_pid;
                    bpf_probe_read_kernel_str(wo.agent_comm, sizeof(wo.agent_comm), root_comm);
                } else {
                    // Tainted as a descendant but no named agent within reach.
                    wo.agent_pid = cur_pid;
                    bpf_probe_read_kernel_str(wo.agent_comm, sizeof(wo.agent_comm), wo.comm);
                }
                bpf_map_update_elem(&agent_write_origin, &wk, &wo, BPF_ANY);
            }
        }
    }

    // Get filename into path field directly via ring buffer reservation
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { inc_drop_counter(0); return 0; }

    e->type = EVENT_FILE_OPEN;
    e->blocked = 0;
    fill_process_info(e);
    __builtin_memset(e->path, 0, MAX_PATH_LEN);

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry) {
        bpf_probe_read_kernel_str(e->path, MAX_PATH_LEN,
                                   BPF_CORE_READ(dentry, d_name.name));
    }

    // Skip noisy proc/sys/pipe files that fire thousands of times per second
    char c0 = e->path[0];
    if (c0 == 's' && e->path[1] == 't' && e->path[2] == 'a') {
        // stat, statm, status — /proc/self/* health checks
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    if (c0 == 'f' && e->path[1] == 'd') {
        // fd, fdinfo — proc fd polling
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    if (c0 == 'n' && e->path[1] == 'u' && e->path[2] == 'l' && e->path[3] == 'l') {
        // /dev/null
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    if (c0 == 'p' && e->path[1] == 'i' && e->path[2] == 'p' && e->path[3] == 'e') {
        // pipe:[...]
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // Check if file is blocked — by basename (broad net) OR by identity (dev+ino).
    // The identity check defeats rename/hardlink: the basename in e->path may be
    // innocuous ("/tmp/x") while the underlying inode is a registered secret.
    u8 *blk = bpf_map_lookup_elem(&blocked_files, e->path);
    if (!blk) {
        struct inode *f_inode = BPF_CORE_READ(file, f_inode);
        if (f_inode) {
            struct ino_key ik = {};
            ik.ino = BPF_CORE_READ(f_inode, i_ino);
            ik.dev = BPF_CORE_READ(f_inode, i_sb, s_dev);
            blk = bpf_map_lookup_elem(&blocked_inodes, &ik);
        }
    }
    if (blk && *blk && cfg->enforce_blocks) {
        // Dedup: only emit the block event once per PID to avoid flooding
        u32 caller_pid = e->pid;
        u8 *already = bpf_map_lookup_elem(&file_open_block_dedup, &caller_pid);
        if (already) {
            // Already reported a block for this PID — just block, no event
            bpf_ringbuf_discard(e, 0);
            return -EACCES;
        }
        u8 one = 1;
        bpf_map_update_elem(&file_open_block_dedup, &caller_pid, &one, BPF_ANY);
        e->blocked = 1;
        bpf_ringbuf_submit(e, 0);
        return -EACCES;
    }

    // ── Quarantine: a file this agent tree wrote, already scanned ─────────
    //
    // Checked HERE as well as at exec on purpose. `python3 evil.py` execs
    // python3 and only OPENS evil.py, so an exec-only check misses every
    // interpreted case — the script, the module, the config the agent wrote.
    //
    // The verdict was computed in userspace when the write closed. Nothing is
    // judged here: this reads one bit that was already decided.
    {
        struct inode *q_inode = BPF_CORE_READ(file, f_inode);
        if (q_inode) {
            struct ino_key qk = {};
            qk.ino = BPF_CORE_READ(q_inode, i_ino);
            qk.dev = BPF_CORE_READ(q_inode, i_sb, s_dev);
            struct write_verdict *v = bpf_map_lookup_elem(&agent_write_verdicts, &qk);
            if (v && v->enforce && cfg->quarantine_enforce) {
                e->blocked = 1;
                bpf_ringbuf_submit(e, 0);
                return -EACCES;
            }
            if (v) {
                // Off by default: record that a quarantined file was opened
                // and let it through, which is what the observe paths do.
                e->blocked = 0;
            }
        }
    }

    // ── Directory restriction ─────────────────────────────────────────────
    // If the user configured "Project Directory Only", the allowed_dir_inodes
    // map contains the inode(s) of allowed directories. Walk up the dentry
    // parent chain; if NO ancestor matches, block the open.
    // Skip system paths (proc/sys/dev/lib/usr) to avoid breaking the runtime.
    if (cfg->enforce_blocks && dentry) {
        // Quick check: is the map populated? (avoid the walk if unused)
        struct ino_key probe_key = {};
        // We use a sentinel key (ino=0) to check if dir restriction is active.
        // The daemon inserts (ino=0, dev=0) as a flag when any dir rules exist.
        u8 *dir_active = bpf_map_lookup_elem(&allowed_dir_inodes, &probe_key);
        if (dir_active) {
            // Skip system files — only restrict user content paths
            char c0 = e->path[0];
            int is_system = 0;
            // /proc, /sys, /dev, /lib, /usr, /etc, /run, /tmp paths have
            // characteristic basenames we can't distinguish here, but these are
            // already filtered above (stat/fd/null/pipe). For the rest, check
            // if any parent dir is in the allowed set.
            int in_allowed = 0;
            struct dentry *walk = BPF_CORE_READ(dentry, d_parent);
            #pragma unroll
            for (int i = 0; i < 12; i++) {
                if (!walk) break;
                struct dentry *wp = BPF_CORE_READ(walk, d_parent);
                if (wp == walk) break; // reached root
                struct inode *dir_inode = BPF_CORE_READ(walk, d_inode);
                if (dir_inode) {
                    struct ino_key dk = {};
                    dk.ino = BPF_CORE_READ(dir_inode, i_ino);
                    dk.dev = BPF_CORE_READ(dir_inode, i_sb, s_dev);
                    if (bpf_map_lookup_elem(&allowed_dir_inodes, &dk)) {
                        in_allowed = 1;
                        break;
                    }
                }
                walk = wp;
            }
            if (!in_allowed) {
                e->blocked = 1;
                bpf_ringbuf_submit(e, 0);
                return -EACCES;
            }
        }
    }

    // ── Blocked directory restriction ────────────────────────────────────
    // If the user configured "Block Directory", the blocked_dir_inodes map
    // contains directory inodes. Walk the dentry parent chain; if ANY
    // ancestor matches, block the open.
    if (cfg->enforce_blocks && dentry) {
        struct ino_key bdir_probe = {};
        u8 *bdir_active = bpf_map_lookup_elem(&blocked_dir_inodes, &bdir_probe);
        if (bdir_active) {
            // Same helper, so truncation denies here too rather than in only
            // one of the three places this walk used to be written out.
            int in_blocked = dentry_under_blocked_dir(dentry);
            if (in_blocked) {
                e->blocked = 1;
                bpf_ringbuf_submit(e, 0);
                return -EACCES;
            }
        }
    }

    // Only report sensitive file opens to avoid flooding the daemon
    // with millions of shared lib / locale / config reads per second.
    // Blocked files are always reported (above). Non-sensitive files are discarded.
    if (!is_sensitive_file(e->path)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // DLP taint (defense-in-depth, gated on dlp_enabled): this is a sensitive
    // file the hard-block layer let through. The READ stays allowed — but the
    // reader is now tainted, so bprm_check bars it from spawning a child and
    // socket_connect bars it from egressing to a non-whitelisted IP (the two
    // exfil vectors). Hard-blocked credentials never reach here — they returned
    // -EACCES above, so legitimately-denied reads don't taint.
    if (cfg->dlp_enabled)
        dlp_taint_current();

    // Global rate limit — prevent overwhelming the daemon event channel
    if (!rate_limit_ok()) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(ringzero_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 0;

    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_monitored_current(comm))
        return 0;

    // Block agent creating files in protected directories or with protected names
    if (cfg->enforce_blocks && dentry && is_dentry_protected(dentry)) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_FILE_CREATE;
            e->blocked = 1;
            fill_process_info(e);
            __builtin_memset(e->path, 0, MAX_PATH_LEN);
            bpf_probe_read_kernel_str(e->path, MAX_PATH_LEN, BPF_CORE_READ(dentry, d_name.name));
            bpf_ringbuf_submit(e, 0);
        }
        return -EACCES;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { inc_drop_counter(0); return 0; }
    e->type = EVENT_FILE_CREATE;
    e->blocked = 0;
    fill_process_info(e);
    __builtin_memset(e->path, 0, MAX_PATH_LEN);
    if (dentry)
        bpf_probe_read_kernel_str(e->path, MAX_PATH_LEN, BPF_CORE_READ(dentry, d_name.name));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(ringzero_inode_unlink, struct inode *dir, struct dentry *dentry) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 0;

    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_monitored_current(comm))
        return 0;

    // Block agent deleting protected files or files in protected directories
    if (cfg->enforce_blocks && dentry && is_dentry_protected(dentry)) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_FILE_DELETE;
            e->blocked = 1;
            fill_process_info(e);
            __builtin_memset(e->path, 0, MAX_PATH_LEN);
            bpf_probe_read_kernel_str(e->path, MAX_PATH_LEN, BPF_CORE_READ(dentry, d_name.name));
            bpf_ringbuf_submit(e, 0);
        }
        return -EACCES;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { inc_drop_counter(0); return 0; }
    e->type = EVENT_FILE_DELETE;
    e->blocked = 0;
    fill_process_info(e);
    __builtin_memset(e->path, 0, MAX_PATH_LEN);
    if (dentry)
        bpf_probe_read_kernel_str(e->path, MAX_PATH_LEN, BPF_CORE_READ(dentry, d_name.name));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Block agent renaming (mv) protected files or files in/out of protected dirs
SEC("lsm/inode_rename")
int BPF_PROG(ringzero_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, unsigned int flags) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled || !cfg->enforce_blocks)
        return 0;

    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_monitored_current(comm))
        return 0;

    // Block if EITHER source or destination is protected
    int src_protected = old_dentry && is_dentry_protected(old_dentry);
    int dst_protected = new_dentry && is_dentry_protected(new_dentry);

    if (src_protected || dst_protected) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_FILE_RENAME;
            e->blocked = 1;
            fill_process_info(e);
            __builtin_memset(e->path, 0, MAX_PATH_LEN);
            // Report the source filename
            if (old_dentry)
                bpf_probe_read_kernel_str(e->path, MAX_PATH_LEN,
                                           BPF_CORE_READ(old_dentry, d_name.name));
            bpf_ringbuf_submit(e, 0);
        }
        return -EACCES;
    }

    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(ringzero_bprm_check, struct linux_binprm *bprm) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 0;

    // Get parent process info to check if spawned by AI agent
    char parent_comm[MAX_COMM_LEN] = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent) {
        bpf_probe_read_kernel_str(parent_comm, sizeof(parent_comm),
                                   BPF_CORE_READ(parent, comm));
    }

    // Get executable name (use short buffer to save stack)
    char exec_name[MAX_COMM_LEN] = {};
    struct file *file = BPF_CORE_READ(bprm, file);
    if (file) {
        struct path f_path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = f_path.dentry;
        if (dentry) {
            bpf_probe_read_kernel_str(exec_name, sizeof(exec_name),
                                       BPF_CORE_READ(dentry, d_name.name));
        }
    }

    // ── Quarantine: refuse to exec a file this agent tree wrote ───────────
    //
    // A NEW denial path, and deliberately not one of the ones that were backed
    // out. The `return 0; // observe-only: was -EACCES` lines elsewhere in this
    // file are untouched; this is gated by its own config flag,
    // quarantine_enforce, which is OFF unless an operator turns it on.
    //
    // Only the `enforce` bit is read, and only a deterministic pattern match in
    // userspace may ever set it. A model verdict cannot reach this branch.
    if (cfg->quarantine_enforce && file) {
        struct inode *q_inode = BPF_CORE_READ(file, f_inode);
        if (q_inode) {
            struct ino_key qk = {};
            qk.ino = BPF_CORE_READ(q_inode, i_ino);
            qk.dev = BPF_CORE_READ(q_inode, i_sb, s_dev);
            struct write_verdict *v = bpf_map_lookup_elem(&agent_write_verdicts, &qk);
            if (v && v->enforce) {
                struct event *qe = bpf_ringbuf_reserve(&events, sizeof(*qe), 0);
                if (qe) {
                    __builtin_memset(qe, 0, sizeof(*qe));
                    qe->type = EVENT_PROCESS_EXEC;
                    qe->blocked = 1;
                    qe->pid = bpf_get_current_pid_tgid() >> 32;
                    qe->uid = bpf_get_current_uid_gid();
                    qe->timestamp = bpf_ktime_get_ns();
                    bpf_get_current_comm(qe->comm, sizeof(qe->comm));
                    bpf_probe_read_kernel_str(qe->path, sizeof(qe->path), exec_name);
                    bpf_ringbuf_submit(qe, 0);
                }
                return -EACCES;
            }
        }
    }

    // Anti-evasion: an AI agent (or one of its tainted descendants) must not
    // launder a process through a system service (systemd-run/at/batch/crontab/
    // setsid) to escape the agent process tree. The laundered worker would be
    // spawned by systemd/atd/cron with clean lineage, so taint-at-fork can't tag
    // it — so we stop the agent from invoking the launderer in the first place.
    {
        u32 self_pid = bpf_get_current_pid_tgid() >> 32;
        // Agent lineage at exec time: already-tainted PID, OR a live ancestry walk
        // (the agent ancestor is still the real_parent — the launder tool hasn't
        // escaped the tree yet, that's exactly what we're stopping).
        int agent_lineage = bpf_map_lookup_elem(&agent_descendants, &self_pid) != 0
                         || is_ai_agent(parent_comm)
                         || is_agent_child();
        if (cfg->enforce_blocks && agent_lineage && is_launder_tool(exec_name)) {
            struct event *le = bpf_ringbuf_reserve(&events, sizeof(*le), 0);
            if (le) {
                le->type = EVENT_PROCESS_EXEC;
                le->blocked = 0; // observe-only
                fill_process_info(le);
                __builtin_memset(le->path, 0, MAX_PATH_LEN);
                __builtin_memcpy(le->path, exec_name, MAX_COMM_LEN);
                bpf_ringbuf_submit(le, 0);
            }
            return 0; // observe-only: was -EACCES
        }
    }

    // DLP exfil-spawn block (defense-in-depth, gated on dlp_enabled): a process
    // that has read sensitive data must not spawn a child — piping a secret to
    // a freshly-exec'd curl/nc/python is the canonical exfil move. The child
    // inherits the taint at fork, so by the time it reaches exec here its PID is
    // tainted; deny the exec. This complements the read-deny (the secret can't
    // be read at all for the hard-block set) and the egress-block (socket_connect).
    if (cfg->dlp_enabled && cfg->enforce_blocks) {
        u32 self_pid = bpf_get_current_pid_tgid() >> 32;
        struct taint_info *ti = bpf_map_lookup_elem(&tainted_pids, &self_pid);
        if (ti && ti->tainted && ti->has_keys) {
            struct event *te = bpf_ringbuf_reserve(&events, sizeof(*te), 0);
            if (te) {
                te->type = EVENT_PROCESS_EXEC;
                te->blocked = 0; // observe-only
                fill_process_info(te);
                __builtin_memset(te->path, 0, MAX_PATH_LEN);
                __builtin_memcpy(te->path, exec_name, MAX_COMM_LEN);
                bpf_ringbuf_submit(te, 0);
            }
            return 0; // observe-only: was -EACCES
        }
    }

    // A process exec'ing an AI-agent binary IS an agent — tag its PID into the
    // taint map so its descendants (handle_fork) and its own launder-tool checks
    // resolve via the map, even when it was launched from a plain (untainted)
    // shell and never forked.
    if (is_ai_agent(exec_name)) {
        u32 ap = bpf_get_current_pid_tgid() >> 32;
        u8 one = 1;
        bpf_map_update_elem(&agent_descendants, &ap, &one, BPF_ANY);
    }

    // Track: AI agent parents spawning children, OR new AI agent processes
    // starting, OR a tainted agent-descendant exec (the spawning pid is in
    // agent_descendants — captures the agent tree's process spawns even when the
    // parent comm isn't an agent name, e.g. node→child→tool).
    {
        u32 self_pid = bpf_get_current_pid_tgid() >> 32;
        if (!is_ai_agent(parent_comm) && !should_monitor_process(parent_comm)
            && !is_ai_agent(exec_name)
            && !bpf_map_lookup_elem(&agent_descendants, &self_pid))
            return 0;
    }

    // Rate limit to prevent event flood
    if (!rate_limit_ok())
        return 0;

    // Send event - AI agent spawning a child process
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { inc_drop_counter(0); return 0; }
    e->type = EVENT_PROCESS_EXEC;
    e->blocked = 0;
    fill_process_info(e);
    __builtin_memset(e->path, 0, MAX_PATH_LEN);
    __builtin_memset(e->args, 0, MAX_ARGS_LEN);
    // Try to get full executable path from bprm->filename (kernel 5.8+)
    const char *filename = BPF_CORE_READ(bprm, filename);
    if (filename) {
        bpf_probe_read_kernel_str(e->path, MAX_PATH_LEN, filename);
    } else {
        // Fallback to short exec name from dentry
        __builtin_memcpy(e->path, exec_name, MAX_COMM_LEN);
    }

    // Capture command-line arguments from bprm->p (user-space arg string).
    // bprm->p points to the current top of the user stack where argv strings
    // are laid out contiguously with NUL separators. Read up to MAX_ARGS_LEN
    // bytes starting from argv[0]. We replace NUL separators with spaces
    // so the daemon sees a single readable string.
    unsigned long arg_start = BPF_CORE_READ(bprm, p);
    unsigned int argc = BPF_CORE_READ(bprm, argc);
    if (arg_start && argc > 0) {
        // bprm->p points to the END of the arg+env area; argv starts at
        // current->mm->arg_start. Read from mm->arg_start instead.
        struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
        struct mm_struct *mm = BPF_CORE_READ(cur, mm);
        if (mm) {
            unsigned long argv_start = BPF_CORE_READ(mm, arg_start);
            unsigned long argv_end   = BPF_CORE_READ(mm, arg_end);
            if (argv_start && argv_end > argv_start) {
                unsigned long len = argv_end - argv_start;
                // Clamp BEFORE reading. The previous `len & (MAX_ARGS_LEN - 1)`
                // pattern looked like a verifier-friendly mask but silently
                // truncates to 0 when `len == MAX_ARGS_LEN` (256 & 255 == 0),
                // dropping argv entirely for any process whose argv fills the
                // whole buffer.
                if (len >= MAX_ARGS_LEN)
                    len = MAX_ARGS_LEN - 1;
                bpf_probe_read_user(e->args, len, (void *)argv_start);
                // Replace NUL separators between args with spaces
                #pragma unroll
                for (int i = 0; i < MAX_ARGS_LEN - 1; i++) {
                    if (e->args[i] == '\0' && e->args[i + 1] != '\0')
                        e->args[i] = ' ';
                }
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 0;
    // Propagate agent taint down the tree AT FORK TIME. If the forking parent is
    // an AI agent or already tainted, tag the child PID. Doing it here (not via a
    // live ancestry walk at access time) is what makes it evasion-resistant: the
    // taint is recorded while the agent is still the real parent, so it persists
    // even after the child reparents to init (daemonize / double-fork / nohup /
    // setsid). No event is emitted — this is pure bookkeeping, so it's cheap.
    // At this tracepoint the CURRENT task is the forking parent, so
    // bpf_get_current_comm() gives the parent's comm (the ctx's parent_comm is a
    // __data_loc field and awkward to read).
    char pcomm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(pcomm, sizeof(pcomm));
    u32 ppid = (u32)ctx->parent_pid;
    if (!is_ai_agent(pcomm) && !bpf_map_lookup_elem(&agent_descendants, &ppid))
        return 0;
    u32 cpid = (u32)ctx->child_pid;
    u8 one = 1;
    bpf_map_update_elem(&agent_descendants, &cpid, &one, BPF_ANY);

    // Propagate DLP taint down the fork too: a child forked by a process that
    // holds sensitive data inherits the taint. This is what makes the exfil
    // chain catchable — the parent reads the secret, then fork()s; the child is
    // the one that execs curl/nc, and bprm_check checks the CHILD's PID. Without
    // this the child would look clean. (Survives reparenting, same as above.)
    struct taint_info *pti = bpf_map_lookup_elem(&tainted_pids, &ppid);
    if (pti && pti->tainted) {
        struct taint_info cti = *pti;
        bpf_map_update_elem(&tainted_pids, &cpid, &cti, BPF_ANY);
    }
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(void *ctx) {
    // Drop the taint when the process exits (LRU also bounds the map, so a missed
    // exit can't leak). Pure bookkeeping, no event.
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&agent_descendants, &pid);
    bpf_map_delete_elem(&tainted_pids, &pid); // drop DLP taint too (HASH, not LRU)
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(ringzero_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 0;

    u16 family = address->sa_family;
    if (family != AF_INET && family != AF_INET6)
        return 0;

    // Extract port early for the agent-discovery path below
    u32 ip = 0;
    u16 port = 0;

    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
        ip = BPF_CORE_READ(addr4, sin_addr.s_addr);
        port = __bpf_ntohs(BPF_CORE_READ(addr4, sin_port));
    } else {
        // IPv6: extract port, use 0 for ip (can't fit in u32)
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
        port = __bpf_ntohs(BPF_CORE_READ(addr6, sin6_port));
    }

    // Track network from AI agents OR any process connecting to port 443 (HTTPS).
    // Port 443 connections from unknown processes trigger daemon-side agent detection
    // by destination (e.g., process connecting to api.openai.com = AI agent).
    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_monitored_current(comm) && port != 443)
        return 0;

    // Check if IP is blocked (IPv4 only for now) — observe only, never block
    int should_block = 0;
    if (family == AF_INET) {
        u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &ip);
        should_block = blocked && *blocked && cfg->enforce_blocks;
    }

    // DLP: If this process is tainted (read sensitive files), check key routing
    // This applies to BOTH IPv4 and IPv6 — tainted processes can't connect anywhere unauthorized
    if (!should_block && cfg->dlp_enabled && cfg->enforce_blocks) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        struct taint_info *ti = bpf_map_lookup_elem(&tainted_pids, &pid);
        if (ti && ti->tainted && ti->has_keys) {
            if (family == AF_INET) {
                // IPv4: check if destination is in allowed list
                u8 *allowed = bpf_map_lookup_elem(&key_allowed_ips, &ip);
                if (!allowed || !*allowed) {
                    should_block = 1;
                }
            } else {
                // IPv6: tainted process trying IPv6 = block (allowed IPs are IPv4 only)
                // This prevents bypass via IPv6 connections
                should_block = 1;
            }
        }
    }

    // EGRESS NARROWING ON TAINT. A process that ingested external content is
    // held to the egress allowlist: loopback, the LLM API endpoints, and
    // whatever the operator approved. This is the new deterministic rule —
    // taint narrows authority, and a heuristic elsewhere may raise taint but
    // never clear it. Gated on egress_enforce, which is off by default.
    if (!should_block && cfg->egress_enforce) {
        u32 tpid = bpf_get_current_pid_tgid() >> 32;
        struct taint_info *ti = bpf_map_lookup_elem(&tainted_pids, &tpid);
        if (ti && ti->tainted) {
            int ok = 0;
            if (family == AF_INET) {
                // Loopback (127.0.0.0/8): the first octet is the low byte of
                // the network-order address, so (ip & 0xff) == 127.
                if ((ip & 0xff) == 127)
                    ok = 1;
                if (!ok && bpf_map_lookup_elem(&key_allowed_ips, &ip))
                    ok = 1;
                if (!ok && bpf_map_lookup_elem(&egress_allowed_ips, &ip))
                    ok = 1;
            }
            // IPv6: the allowlist is IPv4 for now, so a tainted process gets
            // loopback ::1 only. Everything else is off-allowlist.
            if (!ok)
                should_block = 1;
        }
    }

    // EXTERNAL INGESTION RAISES TAINT — the primary provenance signal.
    //
    // A connection by an agent-tree process to anything that is not loopback,
    // not the model API and not operator-approved IS external content arriving.
    // That is a structural fact, visible right here, with no tool name to match
    // and nothing to evade: a fetch tool, `curl` in a shell, `wget`, a python
    // one-liner or a script the agent wrote thirty seconds ago all have to call
    // connect(2) to reach the network.
    //
    // Deliberately placed AFTER the narrowing decision above, so the very
    // connection that does the ingesting still completes. Losing the exfil
    // channel is the consequence of having ingested, not a refusal of the
    // ingestion itself.
    //
    // Two carve-outs, both necessary or the rule taints everything instantly
    // and therefore means nothing. DNS is excluded, because a resolver is
    // usually off-allowlist and every name lookup would taint. And the
    // allowlisted model endpoints are excluded, because the agent talks to them
    // constantly and would otherwise be tainted within a second of starting.
    //
    // Raise-only. Nothing here ever clears taint.
    if (cfg->taint_on_egress && port != 53 && is_monitored_current(comm)) {
        int external = 1;
        if (family == AF_INET) {
            if ((ip & 0xff) == 127)
                external = 0;
            if (external && bpf_map_lookup_elem(&key_allowed_ips, &ip))
                external = 0;
            if (external && bpf_map_lookup_elem(&egress_allowed_ips, &ip))
                external = 0;
        }
        if (external) {
            u32 now_s = (u32)(bpf_ktime_get_ns() / 1000000000ULL);
            u32 ipid = bpf_get_current_pid_tgid() >> 32;
            raise_taint(ipid, now_s);

            // AND THE AGENT ITSELF. This is the part that matters, and it was
            // not obvious until it was measured. Asked to read a web page, the
            // agent ran `curl` through a shell. `curl` connected, got tainted,
            // and exited in the same breath, so sched_process_exit dropped the
            // entry before anything could act on it — the map read empty and
            // the rule looked broken.
            //
            // The helper is not the thing whose authority should narrow. It
            // fetched on the agent's behalf and handed the bytes back up the
            // pipe, so the agent is what ingested external content. Taint the
            // root, which outlives every helper it spawns.
            u32 root_pid = 0;
            char root_comm[MAX_COMM_LEN] = {};
            if (find_agent_root(&root_pid, root_comm, sizeof(root_comm))
                && root_pid != ipid) {
                raise_taint(root_pid, now_s);
            }
        }
    }

    // ENFORCE, but only behind the new flag. When egress_enforce is off this
    // stays exactly what it was: observe-only, return 0. The other
    // observe-only returns in this file were backed out deliberately and are
    // not touched.
    int enforce_now = cfg->egress_enforce && should_block;

    // Determine event type: DNS query (UDP port 53) or regular connect
    u32 evt_type = EVENT_NETWORK_CONNECT;
    if (port == 53) {
        evt_type = 40; // EVENT_DNS_QUERY — detected at connect time
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = evt_type;
        e->blocked = enforce_now ? 1 : 0;
        fill_process_info(e);
        e->remote_ip = ip;
        e->remote_port = port;
        bpf_ringbuf_submit(e, 0);
    } else {
        inc_drop_counter(0);
    }

    return enforce_now ? -EACCES : 0;
}

// =============================================================================
// DLP: Outbound Content Inspection (socket_sendmsg)
// Captures first 4KB of outbound data for API key detection in daemon
// =============================================================================

SEC("lsm/socket_sendmsg")
int BPF_PROG(ringzero_socket_sendmsg, struct socket *sock,
             struct msghdr *msg, int size) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled || !cfg->dlp_enabled)
        return 0;

    // Only inspect AI agent processes
    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_monitored_current(comm))
        return 0;

    // Get socket info — extract destination IP
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;  // IPv4 only for content inspection (IPv6 handled by taint blocking)

    u32 dest_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    u16 dest_port = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Skip small packets (TLS handshakes, ACKs etc < 32 bytes)
    if (size < 32)
        return 0;

    // Check block cache first — if we already decided to block this (pid, ip) pair, block immediately
    if (cfg->enforce_blocks) {
        struct block_key bk = { .pid = pid, .ip = dest_ip };
        u8 *cached = bpf_map_lookup_elem(&blocked_sends, &bk);
        if (cached && *cached) {
            return 0; // observe-only: was -EACCES
        }
    }

    // Reserve space in send_events ring buffer for content inspection
    struct send_event *se = bpf_ringbuf_reserve(&send_events, sizeof(*se), 0);
    if (!se) {
        inc_drop_counter(1);
        return 0;
    }

    se->type = EVENT_NETWORK_SEND;
    se->pid = pid;
    se->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    se->remote_ip = dest_ip;
    se->remote_port = dest_port;
    se->total_len = (u32)size;
    se->blocked = 0;
    __builtin_memcpy(se->comm, comm, MAX_COMM_LEN);

    // Copy first 4KB of outbound data from msghdr iovec
    // msg->msg_iter contains the data buffers
    u32 to_copy = (u32)size;
    if (to_copy > MAX_SEND_DATA)
        to_copy = MAX_SEND_DATA;
    se->data_len = to_copy;

    // Read from the user iovec in msg_iter
    struct iov_iter *iter = &msg->msg_iter;
    const struct iovec *iov = BPF_CORE_READ(iter, __iov);
    if (iov) {
        unsigned long base = (unsigned long)BPF_CORE_READ(iov, iov_base);
        if (base) {
            long ret = bpf_probe_read_user(se->data, to_copy & (MAX_SEND_DATA - 1), (void *)base);
            if (ret < 0) {
                se->data_len = 0;
            }
        }
    }

    bpf_ringbuf_submit(se, 0);

    return 0;  // Allow for now — daemon will populate blocked_sends cache if violation detected
}

// =============================================================================
// TLS Proxy: Traffic Redirection (cgroup/connect + sockops)
// Redirects AI agent HTTPS (port 443) to local TLS proxy for content inspection
// =============================================================================

// cgroup/connect4: Intercept IPv4 connect() and redirect port 443 to proxy
SEC("cgroup/connect4")
int ringzero_connect4(struct bpf_sock_addr *ctx) {
    struct proxy_config *pcfg = get_proxy_config();
    if (!pcfg || !pcfg->enabled)
        return 1;  // Allow (1 = allow in cgroup/connect)

    // Only redirect connections to port 443 (HTTPS)
    u16 dst_port = bpf_ntohs(ctx->user_port);
    if (dst_port != 443)
        return 1;

    // Prevent self-redirect: don't redirect connections already going to the proxy
    // (e.g., if monitor_all is enabled and the daemon's upstream connect hits this)
    if (ctx->user_ip4 == pcfg->proxy_ip4)
        return 1;

    // Only redirect AI agent processes
    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    // Never redirect the daemon itself (ringzero-daem* after 15-char truncation)
    if (comm[0] == 'r' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'g' &&
        comm[4] == 'z' && comm[5] == 'e' && comm[6] == 'r' && comm[7] == 'o')
        return 1;

    if (!is_monitored_current(comm))
        return 1;

    // Save original destination before rewriting
    u64 cookie = bpf_get_socket_cookie(ctx);
    struct orig_dest_value odv = {};
    odv.family = AF_INET;
    odv.orig_ip4 = ctx->user_ip4;
    odv.orig_port = dst_port;
    bpf_map_update_elem(&orig_dest_map, &cookie, &odv, BPF_ANY);

    // Rewrite destination to proxy: 127.0.0.1:proxy_port
    ctx->user_ip4 = pcfg->proxy_ip4;
    ctx->user_port = bpf_htons(pcfg->proxy_port);

    return 1;  // Allow (with rewritten dest)
}

// cgroup/connect6: Intercept IPv6 connect() and redirect port 443 to proxy
SEC("cgroup/connect6")
int ringzero_connect6(struct bpf_sock_addr *ctx) {
    struct proxy_config *pcfg = get_proxy_config();
    if (!pcfg || !pcfg->enabled)
        return 1;

    u16 dst_port = bpf_ntohs(ctx->user_port);
    if (dst_port != 443)
        return 1;

    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    // Never redirect the daemon itself. Linux truncates comm to 15 chars,
    // so "ringzero-daemon" becomes "ringzero-daemo". Match the prefix.
    if (comm[0] == 'r' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'g' &&
        comm[4] == 'z' && comm[5] == 'e' && comm[6] == 'r' && comm[7] == 'o')
        return 1;

    if (!is_monitored_current(comm))
        return 1;

    // Save original destination (IPv6)
    u64 cookie = bpf_get_socket_cookie(ctx);
    struct orig_dest_value odv = {};
    odv.family = AF_INET6;
    odv.orig_port = dst_port;
    // Copy 16-byte IPv6 address (stored as 4x u32 in user_ip6[])
    odv.orig_ip6[0]  = (ctx->user_ip6[0] >> 0)  & 0xFF;
    odv.orig_ip6[1]  = (ctx->user_ip6[0] >> 8)  & 0xFF;
    odv.orig_ip6[2]  = (ctx->user_ip6[0] >> 16) & 0xFF;
    odv.orig_ip6[3]  = (ctx->user_ip6[0] >> 24) & 0xFF;
    odv.orig_ip6[4]  = (ctx->user_ip6[1] >> 0)  & 0xFF;
    odv.orig_ip6[5]  = (ctx->user_ip6[1] >> 8)  & 0xFF;
    odv.orig_ip6[6]  = (ctx->user_ip6[1] >> 16) & 0xFF;
    odv.orig_ip6[7]  = (ctx->user_ip6[1] >> 24) & 0xFF;
    odv.orig_ip6[8]  = (ctx->user_ip6[2] >> 0)  & 0xFF;
    odv.orig_ip6[9]  = (ctx->user_ip6[2] >> 8)  & 0xFF;
    odv.orig_ip6[10] = (ctx->user_ip6[2] >> 16) & 0xFF;
    odv.orig_ip6[11] = (ctx->user_ip6[2] >> 24) & 0xFF;
    odv.orig_ip6[12] = (ctx->user_ip6[3] >> 0)  & 0xFF;
    odv.orig_ip6[13] = (ctx->user_ip6[3] >> 8)  & 0xFF;
    odv.orig_ip6[14] = (ctx->user_ip6[3] >> 16) & 0xFF;
    odv.orig_ip6[15] = (ctx->user_ip6[3] >> 24) & 0xFF;
    bpf_map_update_elem(&orig_dest_map, &cookie, &odv, BPF_ANY);

    // Rewrite to IPv4-mapped IPv6: ::ffff:127.0.0.1 on proxy_port
    ctx->user_ip6[0] = 0;
    ctx->user_ip6[1] = 0;
    ctx->user_ip6[2] = bpf_htonl(0x0000FFFF);
    ctx->user_ip6[3] = pcfg->proxy_ip4;  // Already network byte order
    ctx->user_port = bpf_htons(pcfg->proxy_port);

    return 1;
}

// sockops: After connection is established, record local_port -> cookie mapping
// so proxy can look up the original destination from the accepted connection
SEC("sockops")
int ringzero_sockops(struct bpf_sock_ops *skops) {
    // Only handle active established (client side connected)
    if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
        return 0;

    struct proxy_config *pcfg = get_proxy_config();
    if (!pcfg || !pcfg->enabled)
        return 0;

    // Check if this connection was redirected to our proxy
    // (remote IP == proxy IP and remote port == proxy port)
    u16 remote_port = bpf_ntohl(skops->remote_port) >> 16;
    if (skops->remote_ip4 != pcfg->proxy_ip4 || remote_port != pcfg->proxy_port)
        return 0;

    // Store local_port -> cookie so proxy can do reverse lookup
    u64 cookie = bpf_get_socket_cookie(skops);
    u32 local_port = skops->local_port;  // Host byte order
    bpf_map_update_elem(&port_to_cookie, &local_port, &cookie, BPF_ANY);

    return 0;
}

// =============================================================================
// TAMPER PROTECTION: Prevent external processes from attacking contained agents
// =============================================================================

// Contained (sandboxed) PIDs — daemon populates this when auto-containment activates.
// Key: PID of contained AI agent (or child)
// Value: 1 = contained
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, u8);
} contained_pids SEC(".maps");

// Daemon PID — exempt from tamper protection checks (it manages containment)
// Key: 0
// Value: daemon PID
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} daemon_pid_map SEC(".maps");

static __always_inline int is_daemon_pid(u32 pid) {
    u32 key = 0;
    u32 *dpid = bpf_map_lookup_elem(&daemon_pid_map, &key);
    return dpid && *dpid == pid;
}

static __always_inline int is_contained(u32 pid) {
    u8 *val = bpf_map_lookup_elem(&contained_pids, &pid);
    return val && *val;
}

// LSM: ptrace_access_check — block external processes from ptrace-ing contained agents.
// This prevents debugger-based sandbox escape (GDB attach, strace, process_vm_readv, etc.)
SEC("lsm/ptrace_access_check")
int BPF_PROG(ringzero_ptrace_access_check, struct task_struct *child, unsigned int mode) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled || !cfg->enforce_blocks)
        return 0;

    // Get target PID (the process being ptrace'd)
    u32 target_pid = BPF_CORE_READ(child, tgid);

    // Only protect contained processes
    if (!is_contained(target_pid))
        return 0;

    // Allow daemon to ptrace its own contained processes (for management)
    u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
    if (is_daemon_pid(caller_pid))
        return 0;

    // Allow self-ptrace (process ptrace-ing itself is fine)
    if (caller_pid == target_pid)
        return 0;

    // Block: external process trying to ptrace a contained agent
    // Emit event for audit
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_PROCESS_EXEC;  // Reuse exec type for tamper attempts
        e->blocked = 0; // observe-only
        fill_process_info(e);
        __builtin_memset(e->path, 0, MAX_PATH_LEN);
        // Encode the tamper attempt info in the path field
        const char tamper_msg[] = "TAMPER:ptrace_blocked";
        __builtin_memcpy(e->path, tamper_msg, sizeof(tamper_msg));
        bpf_ringbuf_submit(e, 0);
    }

    return 0; // observe-only: was -EACCES
}

// LSM: task_kill — block external processes from sending dangerous signals to contained agents.
// Prevents SIGKILL/SIGSTOP/SIGCONT from killing or suspending the sandbox.
SEC("lsm/task_kill")
int BPF_PROG(ringzero_task_kill, struct task_struct *target, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled || !cfg->enforce_blocks)
        return 0;

    u32 target_pid = BPF_CORE_READ(target, tgid);
    u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    // Self-tamper protection (T1562 Impair Defenses): the security daemon itself
    // must not be killable by an unauthorized process — an attacker killing the
    // daemon would disable the whole defense. Allow init/systemd (pid 1 — the
    // `systemctl stop` operator path, so we never trap ourselves) and
    // self-signals; block dangerous signals (KILL/TERM/STOP/CONT) from anyone
    // else. Gated by enforce_blocks above, so observe mode leaves it killable.
    if (is_daemon_pid(target_pid) && caller_pid != target_pid && caller_pid != 1
        && (sig == 9 || sig == 15 || sig == 18 || sig == 19)) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_PROCESS_EXEC;
            e->blocked = 0; // observe-only
            fill_process_info(e);
            __builtin_memset(e->path, 0, MAX_PATH_LEN);
            const char m[] = "TAMPER:daemon_kill_blocked";
            __builtin_memcpy(e->path, m, sizeof(m));
            e->remote_port = (u16)sig;
            bpf_ringbuf_submit(e, 0);
        }
        return 0; // observe-only: was -EACCES
    }

    // Only protect contained agent processes
    if (!is_contained(target_pid))
        return 0;

    // Allow daemon to manage its containers
    if (is_daemon_pid(caller_pid))
        return 0;

    // Allow self-signal (process sending to itself is fine — normal operation)
    if (caller_pid == target_pid)
        return 0;

    // Allow SIGCHLD and other harmless signals from parent processes
    // Only block dangerous signals: SIGKILL(9), SIGSTOP(19), SIGTERM(15), SIGCONT(18)
    if (sig != 9 && sig != 15 && sig != 18 && sig != 19)
        return 0;

    // Block: external process trying to kill/stop a contained agent
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_PROCESS_EXEC;
        e->blocked = 0; // observe-only
        fill_process_info(e);
        __builtin_memset(e->path, 0, MAX_PATH_LEN);
        const char tamper_msg[] = "TAMPER:signal_blocked";
        __builtin_memcpy(e->path, tamper_msg, sizeof(tamper_msg));
        e->remote_port = (u16)sig;  // Encode signal number in port field
        bpf_ringbuf_submit(e, 0);
    }

    return 0; // observe-only: was -EACCES
}

// LSM: sb_mount — block mount operations inside contained namespaces.
// Prevents contained processes from remounting /proc, overlaying filesystem, or escaping.
SEC("lsm/sb_mount")
int BPF_PROG(ringzero_sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled || !cfg->enforce_blocks)
        return 0;

    u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    // Only restrict contained processes from mounting
    if (!is_contained(caller_pid))
        return 0;

    // Allow daemon
    if (is_daemon_pid(caller_pid))
        return 0;

    // Block: contained process attempting mount (potential escape)
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_FILE_CREATE;  // Reuse for mount attempts
        e->blocked = 0; // observe-only
        fill_process_info(e);
        __builtin_memset(e->path, 0, MAX_PATH_LEN);
        const char tamper_msg[] = "TAMPER:mount_blocked";
        __builtin_memcpy(e->path, tamper_msg, sizeof(tamper_msg));
        bpf_ringbuf_submit(e, 0);
    }

    return 0; // observe-only: was -EACCES
}

// LSM: sb_umount — block umount inside contained namespaces.
// Prevents unmounting security filesystems (procfs, sysfs) to hide activity.
SEC("lsm/sb_umount")
int BPF_PROG(ringzero_sb_umount, struct vfsmount *mnt, int flags) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled || !cfg->enforce_blocks)
        return 0;

    u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_contained(caller_pid))
        return 0;

    if (is_daemon_pid(caller_pid))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_FILE_DELETE;  // Reuse for umount attempts
        e->blocked = 0; // observe-only
        fill_process_info(e);
        __builtin_memset(e->path, 0, MAX_PATH_LEN);
        const char tamper_msg[] = "TAMPER:umount_blocked";
        __builtin_memcpy(e->path, tamper_msg, sizeof(tamper_msg));
        bpf_ringbuf_submit(e, 0);
    }

    return 0; // observe-only: was -EACCES
}

// =============================================================================
// MPROTECT W→X DETECTION: Detect runtime code generation (LLM-synthesized shellcode)
// =============================================================================

// Flags from linux/mman.h
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

// Known JIT runtimes that legitimately use W→X transitions.
// We still emit events for these but mark them as "jit" in the path field
// so the daemon can filter/score them differently.
static __always_inline int is_known_jit_runtime(const char *comm) {
    // Node.js / V8 JIT — by far the noisiest
    if (comm[0] == 'n' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'e')
        return 1;
    // Python — NumPy/CFFI can use mprotect
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't' && comm[3] == 'h')
        return 1;
    // Java / JVM
    if (comm[0] == 'j' && comm[1] == 'a' && comm[2] == 'v' && comm[3] == 'a')
        return 1;
    // .NET CLR
    if (comm[0] == 'd' && comm[1] == 'o' && comm[2] == 't' && comm[3] == 'n' && comm[4] == 'e')
        return 1;
    // Deno (V8-based)
    if (comm[0] == 'd' && comm[1] == 'e' && comm[2] == 'n' && comm[3] == 'o')
        return 1;
    // Bun (JavaScriptCore)
    if (comm[0] == 'b' && comm[1] == 'u' && comm[2] == 'n')
        return 1;
    // Electron (V8)
    if (comm[0] == 'e' && comm[1] == 'l' && comm[2] == 'e' && comm[3] == 'c')
        return 1;
    return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(ringzero_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 0;

    // Only interested in Write→Execute transitions
    // Check if new protection includes EXEC and old had WRITE
    if (!(prot & PROT_EXEC))
        return 0;

    // Get the old protection flags from the VMA
    unsigned long old_flags = BPF_CORE_READ(vma, vm_flags);
    // VM_WRITE = 0x00000002, VM_EXEC = 0x00000004
    // We want: old had WRITE, new adds EXEC (W→X transition)
    if (!(old_flags & 0x2))
        return 0;

    // Only monitor AI agent processes
    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_monitored_current(comm))
        return 0;

    // Check if this is a known JIT runtime — still emit but annotate
    int is_jit = is_known_jit_runtime(comm);

    // For known JIT runtimes, filter by VMA characteristics:
    // Only report if the mapping is anonymous (not file-backed) AND
    // in the heap region or has suspicious size. This filters out V8's
    // routine code compilation while catching heap-allocated shellcode.
    if (is_jit) {
        // Check if file-backed (vm_file != NULL) — JIT code pages from
        // file-backed mappings (shared libraries, .so files) are routine
        struct file *vm_file = BPF_CORE_READ(vma, vm_file);
        if (vm_file)
            return 0;  // File-backed W→X in JIT runtime — skip

        // Anonymous mapping in JIT runtime: report but annotate as "jit"
        // so daemon can score it lower
    }

    // Emit event — observe, don't block
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { inc_drop_counter(0); return 0; }

    e->type = EVENT_MPROTECT_WX;
    e->blocked = 0;
    fill_process_info(e);
    __builtin_memset(e->path, 0, MAX_PATH_LEN);

    // Annotate path with JIT vs suspicious and VMA details
    if (is_jit) {
        const char msg[] = "mprotect:W->X:jit";
        __builtin_memcpy(e->path, msg, sizeof(msg));
    } else {
        const char msg[] = "mprotect:W->X:suspicious";
        __builtin_memcpy(e->path, msg, sizeof(msg));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =============================================================================
// PHASE 4: Enhanced enforcement for contained processes
// =============================================================================

// Allowed executables for contained processes — daemon populates from observer policy.
// Key: binary name (e.g., "git", "cargo", "npm")
// Value: 1 = allowed inside containment
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, char[MAX_COMM_LEN]);
    __type(value, u8);
} contained_allowed_exec SEC(".maps");

// Enhanced bprm_check: if contained process tries to exec an unknown binary, block it.
// This is Phase 4 enforcement — kernel-level allow-list for contained agents.
SEC("lsm/bprm_check_security")
int BPF_PROG(ringzero_bprm_check_contained, struct linux_binprm *bprm) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled || !cfg->enforce_blocks)
        return 0;

    u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    // Only enforce on contained processes
    if (!is_contained(caller_pid))
        return 0;

    // Get executable name
    char exec_name[MAX_COMM_LEN] = {};
    struct file *file = BPF_CORE_READ(bprm, file);
    if (file) {
        struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
        if (dentry) {
            bpf_probe_read_kernel_str(exec_name, sizeof(exec_name),
                                       BPF_CORE_READ(dentry, d_name.name));
        }
    }

    // Check if this executable is in the allowed list
    u8 *allowed = bpf_map_lookup_elem(&contained_allowed_exec, exec_name);
    if (allowed && *allowed)
        return 0;  // Allowed

    // Also allow the AI agent binary itself (it's already contained)
    if (is_ai_agent(exec_name))
        return 0;

    // Also allow common shells (they're the parent — needed for pipelines)
    if (exec_name[0] == 'b' && exec_name[1] == 'a' && exec_name[2] == 's' && exec_name[3] == 'h')
        return 0;
    if (exec_name[0] == 's' && exec_name[1] == 'h' && exec_name[2] == '\0')
        return 0;
    if (exec_name[0] == 'z' && exec_name[1] == 's' && exec_name[2] == 'h')
        return 0;

    // Block: contained process trying to exec unauthorized binary
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_PROCESS_EXEC;
        e->blocked = 0; // observe-only
        fill_process_info(e);
        __builtin_memset(e->path, 0, MAX_PATH_LEN);
        // Write full path from bprm
        const char *filename = BPF_CORE_READ(bprm, filename);
        if (filename) {
            bpf_probe_read_kernel_str(e->path, MAX_PATH_LEN, filename);
        } else {
            __builtin_memcpy(e->path, exec_name, MAX_COMM_LEN);
        }
        bpf_ringbuf_submit(e, 0);
    }

    return 0; // observe-only: was -EACCES
}

// Enhanced file_open: block credential access for contained processes at kernel level.
// Double enforcement — observer catches it in userspace, kernel blocks it definitively.
SEC("lsm/file_open")
int BPF_PROG(ringzero_file_open_contained, struct file *file) {
    struct config *cfg = get_config();
    if (!cfg || !cfg->enabled || !cfg->enforce_blocks)
        return 0;

    u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_contained(caller_pid))
        return 0;

    // Get filename
    char filename[MAX_PATH_LEN] = {};
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;
    bpf_probe_read_kernel_str(filename, MAX_PATH_LEN, BPF_CORE_READ(dentry, d_name.name));

    // Block access to credential files for contained processes — by sensitive
    // basename OR by registered identity (dev+ino). The identity check closes the
    // rename/hardlink bypass: an innocuous-named hardlink to a secret has a
    // non-sensitive basename but the same inode.
    if (!is_sensitive_file(filename)) {
        struct inode *f_inode = BPF_CORE_READ(file, f_inode);
        if (!f_inode)
            return 0;
        struct ino_key ik = {};
        ik.ino = BPF_CORE_READ(f_inode, i_ino);
        ik.dev = BPF_CORE_READ(f_inode, i_sb, s_dev);
        u8 *blk = bpf_map_lookup_elem(&blocked_inodes, &ik);
        if (!blk || !*blk)
            return 0;
    }

    // Emit blocked event
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_FILE_OPEN;
        e->blocked = 0; // observe-only
        fill_process_info(e);
        __builtin_memcpy(e->path, filename, MAX_PATH_LEN);
        bpf_ringbuf_submit(e, 0);
    }

    return 0; // observe-only: was -EACCES
}

char LICENSE[] SEC("license") = "GPL";
