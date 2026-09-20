# SPDX-License-Identifier: Apache-2.0
# Ring Zero Security — Linux build orchestration
# ringzerosecurity.com

.PHONY: all daemon cli app ebpf deb check dev clean run-daemon run-cli

CARGO         ?= cargo
CARGO_FLAGS   ?= --release
BUILD_DIR     := target/release
EBPF_DIR      := GPL/bpf

## Build daemon + CLI
all: daemon cli

daemon:
	$(CARGO) build $(CARGO_FLAGS) -p agent

cli:
	$(CARGO) build $(CARGO_FLAGS) -p cli

## Build the desktop app (frontend + Tauri). Always goes through the tauri CLI
## so the frontend is embedded — `cargo build -p ringzero-app` on its own
## produces a binary that tries to load the dev server (white screen).
app:
	cd app/ui && npm ci && npm run build
	cd app/src-tauri && $(CARGO) tauri build --no-bundle

## Build the eBPF kernel programs (needs clang, bpftool, libbpf-dev, BTF)
ebpf:
	$(MAKE) -C $(EBPF_DIR) all

## Build the .deb package (daemon + CLI + app + eBPF objects)
deb:
	bash build-deb.sh

## Compile check (fast, no linking)
check:
	$(CARGO) check -p agent -p cli -p ringzero-app

## Dev build (debug, faster compile)
dev:
	CARGO_FLAGS="" $(MAKE) all

## Clean
clean:
	$(CARGO) clean
	$(MAKE) -C $(EBPF_DIR) clean
	rm -rf app/ui/dist

## Run daemon locally (dev, non-root — no kernel hooks)
run-daemon:
	RUST_LOG=info $(CARGO) run -p agent

## Run CLI (dev)
run-cli:
	$(CARGO) run -p cli -- $(ARGS)
