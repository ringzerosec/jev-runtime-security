// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Ring Zero Security. Kernel-side component of Ring Zero for Linux.
//
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 as published by the
// Free Software Foundation. See LICENSE in this directory.
// Ring Zero Linux Driver - Shared Header

#ifndef RINGZERO_H
#define RINGZERO_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16
#define MAX_SEND_DATA 4096

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
    EVENT_DNS_QUERY = 40,
    EVENT_SSL_DATA = 50,        // SSL/TLS plaintext from uprobe interception
    EVENT_TAMPER_PTRACE = 60,   // Tamper protection: ptrace blocked
    EVENT_TAMPER_SIGNAL = 61,   // Tamper protection: signal blocked
    EVENT_TAMPER_MOUNT = 62,    // Tamper protection: mount blocked
    EVENT_TAMPER_UMOUNT = 63,   // Tamper protection: umount blocked
    EVENT_CONTAINED_EXEC_BLOCKED = 70,  // Contained process exec blocked
    EVENT_CONTAINED_FILE_BLOCKED = 71,  // Contained process credential access blocked
};

// SSL direction
#define SSL_DIR_READ  0
#define SSL_DIR_WRITE 1

#define MAX_SSL_DATA 16384      // 16 KB per SSL event

// Event data structure (shared with kernel) — file/process/connect events
struct event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 timestamp;
    char comm[MAX_COMM_LEN];
    char path[MAX_PATH_LEN];
    char parent_comm[MAX_COMM_LEN];
    __u32 remote_ip;
    __u16 remote_port;
    __u16 local_port;
    __u8 protocol;
    __u8 blocked;
    __u8 _pad[2];
};

// Send event — outbound data inspection (DLP content inspection)
struct send_event {
    __u32 type;             // EVENT_NETWORK_SEND
    __u32 pid;
    __u32 uid;
    __u32 remote_ip;
    __u16 remote_port;
    __u16 data_len;         // Actual bytes captured (up to MAX_SEND_DATA)
    __u32 total_len;        // Total send size
    __u8 blocked;           // 1 if blocked by cache
    __u8 _pad[3];
    char comm[MAX_COMM_LEN];
    char data[MAX_SEND_DATA]; // First 4KB of outbound payload
};

// Block cache key: (pid, dest_ip) pair
struct block_key {
    __u32 pid;
    __u32 ip;
};

// Tainted process info
struct taint_info {
    __u8 tainted;           // 1 if process read sensitive data
    __u8 has_keys;          // 1 if process accessed credential files
    __u16 _pad;
    __u32 taint_time;       // When tainted (seconds since boot)
};

// Configuration (daemon sets this)
struct config {
    __u8 enabled;           // Master switch
    __u8 monitor_all;       // If 1, monitor all processes. If 0, only monitored_processes
    __u8 enforce_blocks;    // If 1, actually block. If 0, just observe/log
    __u8 dlp_enabled;       // If 1, enable DLP taint tracking
    __u32 _reserved;
};

// TLS proxy configuration (daemon sets this via proxy_config_map)
struct proxy_config {
    __u32 proxy_ip4;        // Proxy IPv4 address (network byte order), e.g., 127.0.0.1
    __u16 proxy_port;       // Proxy port (host byte order), e.g., 8443
    __u8 enabled;           // 1 = redirect AI agent HTTPS to proxy
    __u8 _pad;
};

// SSL/TLS plaintext capture event (from uprobe interception)
struct ssl_event {
    __u32 event_type;       // EVENT_SSL_DATA
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u64 timestamp;
    __u32 data_len;         // Actual bytes captured
    __u32 total_len;        // Total buffer length from SSL call
    __u8  direction;        // SSL_DIR_READ or SSL_DIR_WRITE
    __u8  _pad[3];
    char comm[MAX_COMM_LEN];
    char data[MAX_SSL_DATA];
};

// Original destination saved before cgroup/connect4 rewrites it
struct orig_dest_value {
    __u16 family;           // AF_INET or AF_INET6
    __u16 orig_port;        // Original port (host byte order)
    __u32 orig_ip4;         // Original IPv4 (network byte order)
    __u8 orig_ip6[16];      // Original IPv6 (network byte order)
};

#ifdef __cplusplus
}
#endif

#endif // RINGZERO_H
