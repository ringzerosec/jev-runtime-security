// SPDX-License-Identifier: GPL-2.0
// Lab 09 — YOUR mini-enforcer. An lsm/file_open hook that DENIES an open.
//
// SAFE BY DESIGN: it only ever denies a process whose name (comm) is exactly
// "victim", opening a file whose basename is exactly "topsecret.txt". Nothing
// else is ever affected, so a mistake here cannot lock up your VM.
//
// This is GPL/bpf/ringzero.bpf.c's file_open hook in miniature:
//   Q1: is this "the agent"?   (is_agent  <-> is_ai_agent)
//   Q2: is this protected?     (name_eq   <-> is_dentry_protected)
//   verdict: return -EACCES    (deny) or 0 (allow)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EACCES 13
#define AGENT  "victim"          // <-- change to "chatgpt" for exercise 2
#define TARGET "topsecret.txt"

// Compare a null-terminated string to a fixed literal, bounded for the verifier.
static __always_inline int eq(const char *s, const char *lit, int n) {
    #pragma unroll
    for (int i = 0; i < n; i++) {
        if (s[i] != lit[i]) return 0;   // differs -> not equal
        if (lit[i] == '\0') return 1;   // both hit end together -> equal
    }
    return 1;
}

SEC("lsm/file_open")
int BPF_PROG(deny_open, struct file *file) {
    // Q1 — is this "the agent"?
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (!eq(comm, AGENT, sizeof(AGENT)))
        return 0;                        // not the agent -> allow

    // Q2 — is this the protected file? (read the basename from the dentry)
    char name[32] = {};
    struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
    bpf_probe_read_kernel_str(name, sizeof(name), BPF_CORE_READ(d, d_name.name));
    if (!eq(name, TARGET, sizeof(TARGET)))
        return 0;                        // some other file -> allow

    return -EACCES;                      // the agent + the protected file -> DENY
}
