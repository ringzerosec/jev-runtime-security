// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Ring Zero Security. Kernel-side component of Ring Zero for Linux.
//
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 as published by the
// Free Software Foundation. See LICENSE in this directory.
// Ring Zero — stdio capture for AI agent processes
//
// Hooks sys_read/sys_write tracepoints, filtered to fd 0/1/2 (stdin/stdout/stderr)
// for tracked agent PIDs. Captures the buffer content so we can see prompts
// and responses flowing through the agent's terminal — no TLS interception needed.
//
// Based on AgentSight's stdiocap.bpf.c (MIT license).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BUF_SIZE    8192
#define RING_BUF_SIZE   (4 * 1024 * 1024)  // 4MB ring buffer
#define TASK_COMM_LEN   16

#define STDIO_DIR_READ  0
#define STDIO_DIR_WRITE 1

// ── Event struct (matches Rust StdioCaptureEvent) ────────────────────────────

struct stdio_event {
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 uid;
    s32 fd;           // 0=stdin, 1=stdout, 2=stderr
    u32 len;          // actual bytes read/written
    u32 buf_size;     // bytes captured (may be less than len)
    u8  is_read;      // 1=read (input), 0=write (output)
    char comm[TASK_COMM_LEN];
    u8  buf[MAX_BUF_SIZE];
};

// ── Maps ─────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUF_SIZE);
} stdio_events SEC(".maps");

// Per-thread args saved at entry, read at exit
struct io_args {
    u64 buf_ptr;
    s32 fd;
    u8  is_read;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);    // pid_tgid
    __type(value, struct io_args);
} pending_io SEC(".maps");

// ── DNS answer capture ───────────────────────────────────────────────────────
//
// WHY THIS EXISTS. Egress is allowed by NAME, and a name has to be turned into
// addresses by somebody. The daemon resolving the name itself does not work:
// the model API is CDN-fronted, so the daemon's answer and the agent's answer
// are different answers to the same question. The only way policy and agent
// agree is to admit the addresses from the answer the AGENT actually received.
//
// WHY NOT RAW CAPTURE. An AF_PACKET sniffer would also see this, and everything
// else on the host belonging to other users and applications. "Reads DNS
// answers for names you allowlisted" is a defensible sentence; "captures all
// network traffic" is not, and it would need CAP_NET_RAW on top.
//
// HOW IT FILTERS. An answer arrives FROM port 53, which recvfrom reports in the
// source address, so no connection tracking is needed for the common case.
//
// WHAT IT MISSES, and this is why userspace warns loudly when nothing is ever
// observed: a connected UDP socket may hand recvfrom a null source address, and
// encrypted DNS (DoH/DoT) has no plaintext answer to read at all. On such a
// host the learned set stays empty and hostname allowlisting does not work.
#define DNS_MAX_ANSWER 1500
#ifndef AF_INET
#define AF_INET 2
#endif
// 53 in network byte order, written out rather than pulled from a header the
// BPF build does not carry.
#define DNS_PORT_BE __builtin_bswap16(53)

struct dns_event {
    u64 timestamp_ns;
    u32 pid;
    u32 len;
    u8  buf[DNS_MAX_ANSWER];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} dns_events SEC(".maps");

struct dns_args {
    u64 buf_ptr;
    u64 src_addr_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);    // pid_tgid
    __type(value, struct dns_args);
} pending_dns SEC(".maps");

// PIDs to track (populated by userspace — agent PIDs + children)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);    // pid
    __type(value, u8);   // 1 = tracked
} tracked_pids SEC(".maps");

// Config: trace all PIDs (1) or only tracked (0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u8);
} stdio_config SEC(".maps");

// ── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline bool should_trace(u32 pid, int fd) {
    // Only capture stdin/stdout/stderr
    if (fd < 0 || fd > 2)
        return 0;

    // Check trace-all mode
    u32 key = 0;
    u8 *trace_all = bpf_map_lookup_elem(&stdio_config, &key);
    if (trace_all && *trace_all)
        return 1;

    // Check tracked PIDs
    u8 *val = bpf_map_lookup_elem(&tracked_pids, &pid);
    return val && *val;
}

// ── Entry probes (save buffer pointer) ───────────────────────────────────────

static __always_inline int enter_io(int fd, const void *buf, bool is_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!should_trace(pid, fd))
        return 0;

    struct io_args args = {};
    args.buf_ptr = (u64)buf;
    args.fd = fd;
    args.is_read = is_read;
    bpf_map_update_elem(&pending_io, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// ── Exit probes (capture buffer content) ─────────────────────────────────────

static __always_inline int exit_io(long ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct io_args *args = bpf_map_lookup_elem(&pending_io, &pid_tgid);
    if (!args)
        return 0;

    if (ret <= 0) {
        bpf_map_delete_elem(&pending_io, &pid_tgid);
        return 0;
    }

    struct stdio_event *event = bpf_ringbuf_reserve(&stdio_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&pending_io, &pid_tgid);
        return 0;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->fd = args->fd;
    event->len = (u32)ret;
    event->is_read = args->is_read;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    u32 copy_size = (u32)ret;
    if (copy_size > MAX_BUF_SIZE)
        copy_size = MAX_BUF_SIZE;
    event->buf_size = copy_size;

    if (bpf_probe_read_user(event->buf, copy_size & 0x1FFF, (void *)args->buf_ptr) < 0)
        event->buf_size = 0;

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&pending_io, &pid_tgid);
    return 0;
}

// ── Tracepoints ──────────────────────────────────────────────────────────────

SEC("tp/syscalls/sys_enter_read")
int trace_enter_read(struct trace_event_raw_sys_enter *ctx) {
    return enter_io((int)ctx->args[0], (const void *)ctx->args[1], true);
}

SEC("tp/syscalls/sys_exit_read")
int trace_exit_read(struct trace_event_raw_sys_exit *ctx) {
    return exit_io(ctx->ret);
}

SEC("tp/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx) {
    return enter_io((int)ctx->args[0], (const void *)ctx->args[1], false);
}

SEC("tp/syscalls/sys_exit_write")
int trace_exit_write(struct trace_event_raw_sys_exit *ctx) {
    return exit_io(ctx->ret);
}

// ── DNS capture probes ───────────────────────────────────────────────────────

static __always_inline int dns_tracked(u32 pid) {
    u32 key = 0;
    u8 *trace_all = bpf_map_lookup_elem(&stdio_config, &key);
    if (trace_all && *trace_all)
        return 1;
    u8 *val = bpf_map_lookup_elem(&tracked_pids, &pid);
    return val && *val;
}

SEC("tp/syscalls/sys_enter_recvfrom")
int trace_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!dns_tracked(pid_tgid >> 32))
        return 0;
    struct dns_args a = {};
    a.buf_ptr = (u64)ctx->args[1];      // void *buf
    a.src_addr_ptr = (u64)ctx->args[4]; // struct sockaddr *src_addr
    bpf_map_update_elem(&pending_dns, &pid_tgid, &a, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_recvfrom")
int trace_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct dns_args *a = bpf_map_lookup_elem(&pending_dns, &pid_tgid);
    if (!a)
        return 0;

    long ret = ctx->ret;
    if (ret <= 0 || a->src_addr_ptr == 0) {
        // ret <= 0: nothing arrived. src_addr null: a connected socket did not
        // tell us where this came from, so we cannot say it is a DNS answer
        // without tracking the connection. Dropped rather than guessed at.
        bpf_map_delete_elem(&pending_dns, &pid_tgid);
        return 0;
    }

    // Only answers, i.e. only datagrams whose SOURCE port is 53.
    struct sockaddr_in sa = {};
    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)a->src_addr_ptr) < 0) {
        bpf_map_delete_elem(&pending_dns, &pid_tgid);
        return 0;
    }
    // sin_port is network byte order; 53 == 0x0035, so the wire bytes are
    // 0x00 0x35 and the value read on a little-endian host is 0x3500.
    if (sa.sin_family != AF_INET || sa.sin_port != DNS_PORT_BE) {
        bpf_map_delete_elem(&pending_dns, &pid_tgid);
        return 0;
    }

    struct dns_event *e = bpf_ringbuf_reserve(&dns_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&pending_dns, &pid_tgid);
        return 0;
    }
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid_tgid >> 32;
    u32 n = (u32)ret;
    if (n > DNS_MAX_ANSWER)
        n = DNS_MAX_ANSWER;
    e->len = n;
    if (bpf_probe_read_user(e->buf, n & 0x7FF, (void *)a->buf_ptr) < 0)
        e->len = 0;
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pending_dns, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
