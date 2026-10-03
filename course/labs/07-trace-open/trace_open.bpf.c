// SPDX-License-Identifier: GPL-2.0
// Lab 07 — fire on every openat() syscall and print who opened what.
// This OBSERVES; it cannot block (that's Lab 09). Build+run with run.sh.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    const char *filename = (const char *)ctx->args[1]; // openat(dirfd, PATH, ...)
    bpf_printk("open by %s: %s", comm, filename);
    return 0;
}
