#!/usr/bin/env bash
# Lab 00 — prove Rust AND eBPF both work on this machine.
# Run inside the rgs VM:  bash check.sh
set -e
cd "$(dirname "$0")"

echo "== 1. Rust =="
rustc hello.rs -o hello
./hello
echo

echo "== 2. eBPF: generate vmlinux.h from this kernel's BTF =="
# vmlinux.h describes every kernel type, generated from /sys/kernel/btf/vmlinux.
# CO-RE ("compile once, run everywhere") uses it so the object relocates onto
# other kernels. You generate it once per machine; never commit it.
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
echo "vmlinux.h: $(wc -l < vmlinux.h) lines of kernel type definitions"
echo

echo "== 3. eBPF: compile the smoke program to a BPF object =="
clang -g -O2 -target bpf -D__TARGET_ARCH_$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/') \
      -c smoke.bpf.c -o smoke.bpf.o
echo "compiled: $(file smoke.bpf.o | cut -d: -f2-)"
echo

echo "== 4. eBPF: does the verifier + LSM accept it? (needs sudo) =="
# Load it and pin it, then immediately remove it. If this prints 'loaded+attached'
# your kernel's BPF LSM will run programs you write. This is the real gate.
sudo bpftool prog loadall smoke.bpf.o /sys/fs/bpf/lab00 autoattach 2>/dev/null \
  && echo "loaded+attached OK" \
  && sudo rm -rf /sys/fs/bpf/lab00 \
  || echo "NOTE: load/attach needs root and BPF LSM; on rgs it should pass."

echo
echo "All green? You can do every lab in this course."
