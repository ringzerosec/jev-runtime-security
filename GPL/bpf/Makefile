# SPDX-License-Identifier: GPL-2.0-only
# Ring Zero Linux eBPF programs — Makefile
#
# Builds the kernel-side BPF object the agent loads at runtime:
#   build/ringzero.bpf.o   LSM hooks (file/exec/network) + tracepoints + cgroup programs
#
# Requires: clang/llvm (>= 14), bpftool, libbpf-dev, and a running kernel with
# BTF (/sys/kernel/btf/vmlinux, CONFIG_DEBUG_INFO_BTF=y) to generate vmlinux.h.

CLANG ?= clang
BPFTOOL ?= bpftool

# Paths
VMLINUX_PATH ?= /sys/kernel/btf/vmlinux
OUTPUT_DIR ?= build

# Auto-detect target architecture for eBPF
UNAME_ARCH := $(shell uname -m)
ifeq ($(UNAME_ARCH),x86_64)
  BPF_ARCH := x86
else ifeq ($(UNAME_ARCH),aarch64)
  BPF_ARCH := arm64
else ifeq ($(findstring arm,$(UNAME_ARCH)),arm)
  BPF_ARCH := arm
else ifeq ($(UNAME_ARCH),s390x)
  BPF_ARCH := s390
else
  BPF_ARCH := $(UNAME_ARCH)
endif

# Flags
# -std=gnu11: a bpftool-generated vmlinux.h from a recent kernel uses bool/true/
# false, which clang >= ~19 (defaulting to a newer C std) treats as keywords and
# rejects. Pin C11 so they stay ordinary identifiers.
BPF_CFLAGS := -g -O2 -target bpf -std=gnu11 -D__TARGET_ARCH_$(BPF_ARCH)

# Source files
BPF_SRC := ringzero.bpf.c
BPF_OBJ := $(OUTPUT_DIR)/ringzero.bpf.o

# Stdio capture: read/write tracepoints for agent pids the daemon tracks.
STDIO_SRC := stdiocap.bpf.c
STDIO_OBJ := $(OUTPUT_DIR)/stdiocap.bpf.o

.PHONY: all clean install test-attach show-maps

all: $(OUTPUT_DIR) vmlinux.h $(BPF_OBJ) $(STDIO_OBJ)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

# Generate vmlinux.h from the running kernel's BTF. CO-RE relocations let the
# resulting objects load on other kernels with BTF, but they must be COMPILED
# against a real vmlinux.h — fail loudly rather than emit a stub that would
# only produce a confusing wall of errors from clang.
vmlinux.h:
	@if [ -f $(VMLINUX_PATH) ]; then \
		$(BPFTOOL) btf dump file $(VMLINUX_PATH) format c > vmlinux.h; \
	else \
		echo "error: $(VMLINUX_PATH) not found — this kernel has no BTF (CONFIG_DEBUG_INFO_BTF=y required)"; \
		exit 1; \
	fi

# Compile eBPF programs
$(BPF_OBJ): $(BPF_SRC) vmlinux.h ringzero.h
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

$(STDIO_OBJ): $(STDIO_SRC) vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $(STDIO_SRC) -o $(STDIO_OBJ)

# Install the objects where the daemon looks for them (/usr/lib/ringzero)
install: all
	install -d /usr/lib/ringzero
	install -m 644 $(BPF_OBJ) /usr/lib/ringzero/

clean:
	rm -rf $(OUTPUT_DIR) vmlinux.h

# Development helpers
test-attach:
	@echo "Loaded Ring Zero BPF programs:"
	sudo bpftool prog list | grep ringzero || echo "No programs loaded"

show-maps:
	sudo bpftool map list | grep -A2 ringzero || echo "No maps found"
