#!/usr/bin/env bash
# Lab 07 — compile, load+attach, and watch the trace. Run in the rgs VM.
#   bash run.sh
# Ctrl-C to stop; it cleans up the pin.
set -e
cd "$(dirname "$0")"
ARCH=$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

echo "[1/3] vmlinux.h (kernel types)"
[ -f vmlinux.h ] || bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

echo "[2/3] compile trace_open.bpf.c -> .o"
clang -g -O2 -target bpf -D__TARGET_ARCH_$ARCH -c trace_open.bpf.c -o trace_open.bpf.o

echo "[3/3] load + attach (needs sudo), then tail the trace"
sudo rm -rf /sys/fs/bpf/lab07 2>/dev/null || true
sudo bpftool prog loadall trace_open.bpf.o /sys/fs/bpf/lab07 autoattach
echo
echo ">>> Now open files in ANOTHER shell (cat /etc/hostname, ls, python3 ...)."
echo ">>> Watching every openat below. Ctrl-C to stop."
echo
trap 'sudo rm -rf /sys/fs/bpf/lab07; echo; echo "cleaned up."' EXIT
sudo cat /sys/kernel/debug/tracing/trace_pipe
