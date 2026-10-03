#!/usr/bin/env bash
# Lab 09 — build your enforcer, attach it, and prove it denies a syscall.
# Run in the rgs VM:  bash run.sh
set -e
cd "$(dirname "$0")"
ARCH=$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

echo "[1/4] vmlinux.h"
[ -f vmlinux.h ] || bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

echo "[2/4] compile your enforcer"
clang -g -O2 -target bpf -D__TARGET_ARCH_$ARCH -c deny_open.bpf.c -o deny_open.bpf.o

echo "[3/4] set up the test file and a fake 'agent' named victim"
echo "the-crown-jewels" > topsecret.txt
PY=$(readlink -f "$(command -v python3)")
cp "$PY" ./victim          # a process named 'victim' == our pretend agent
READ='import sys; print(open("topsecret.txt").read().strip())'

echo "[4/4] attach the enforcer (needs sudo), then run the proof"
sudo rm -rf /sys/fs/bpf/lab09 2>/dev/null || true
sudo bpftool prog loadall deny_open.bpf.o /sys/fs/bpf/lab09 autoattach
trap 'sudo rm -rf /sys/fs/bpf/lab09; rm -f victim deny_open.bpf.o; echo; echo "detached + cleaned up."' EXIT

echo
echo -n "  as victim (the agent):   "; ./victim -c "$READ" 2>&1 || true
echo -n "  as a normal reader:      "; python3 -c "$READ" 2>&1 || true
echo
echo "Same file. The kernel denied the one named 'victim'. That's enforcement."
