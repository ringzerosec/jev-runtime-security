// SPDX-License-Identifier: GPL-2.0
// Lab 00 — the smallest real eBPF program: it attaches to the file_open LSM
// hook and ALLOWS everything (returns 0). We're not enforcing yet — we only
// prove that your toolchain can compile a BPF object, the verifier accepts it,
// and it attaches to a security hook. That is the whole eBPF pipeline in one
// file. Chapter 9 turns the `return 0` into a real decision.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";   // BPF LSM helpers are GPL-only

SEC("lsm/file_open")
int BPF_PROG(smoke_file_open, struct file *file) {
    return 0;   // 0 = allow. (A negative errno like -EACCES would deny.)
}
