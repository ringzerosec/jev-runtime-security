#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Ring Zero Security — build and install from source (Linux)
# Usage: sudo ./install-from-source.sh [--dev] [--no-ebpf] [--no-app] [--no-service]
# ringzerosecurity.com

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

info()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
error() { echo -e "${RED}[✗]${RESET} $*" >&2; }
die()   { error "$*"; exit 1; }
step()  { echo -e "\n${BOLD}$*${RESET}"; }

# ── Defaults ──────────────────────────────────────────────────────────────────

DEV_MODE=0
SKIP_EBPF=0
SKIP_APP=0
SKIP_SERVICE=0

for arg in "$@"; do
  case "$arg" in
    --dev)         DEV_MODE=1 ;;
    --no-ebpf)     SKIP_EBPF=1 ;;
    --no-app)      SKIP_APP=1 ;;
    --no-service)  SKIP_SERVICE=1 ;;
    --help|-h)
      echo "Usage: sudo $0 [--dev] [--no-ebpf] [--no-app] [--no-service]"
      echo ""
      echo "  --dev          Build in debug mode (faster, larger binaries)"
      echo "  --no-ebpf      Skip eBPF program build and installation"
      echo "  --no-app       Skip the desktop app (daemon + CLI only, e.g. headless servers)"
      echo "  --no-service   Skip systemd service installation"
      exit 0 ;;
    *) die "Unknown argument: $arg" ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_PROFILE=$([ "$DEV_MODE" -eq 1 ] && echo "debug" || echo "release")
CARGO_FLAGS=$([ "$DEV_MODE" -eq 1 ] && echo "" || echo "--release")

# ── Check root ────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  die "This script must be run as root (sudo $0)"
fi

# Building as root puts cargo/npm caches in /root. If the repo is owned by a
# regular user, cargo still works; the built artifacts under target/ will be
# root-owned.

echo -e "${BOLD}"
echo "  ██████╗ ██╗███╗   ██╗ ██████╗     ███████╗███████╗██████╗  ██████╗ "
echo "  ██╔══██╗██║████╗  ██║██╔════╝     ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗"
echo "  ██████╔╝██║██╔██╗ ██║██║  ███╗      ███╔╝ █████╗  ██████╔╝██║   ██║"
echo "  ██╔══██╗██║██║╚██╗██║██║   ██║     ███╔╝  ██╔══╝  ██╔══██╗██║   ██║"
echo "  ██║  ██║██║██║ ╚████║╚██████╔╝    ███████╗███████╗██║  ██║╚██████╔╝"
echo "  ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝    ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ "
echo -e "${RESET}"
echo "  Kernel-level runtime security for AI coding agents"
echo "  ringzerosecurity.com"
echo ""

# ── Check prerequisites ───────────────────────────────────────────────────────

step "Checking prerequisites…"

check_cmd() {
  if command -v "$1" &>/dev/null; then
    info "$1 found ($(command -v "$1"))"
  else
    if [ "${2:-required}" = "optional" ]; then
      warn "$1 not found (optional — $3)"
    else
      die "$1 not found. Install it with: $3"
    fi
  fi
}

check_cmd cargo required  "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
check_cmd git   optional  "apt install git"

# Kernel version check
KERNEL=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL" | cut -d. -f2)
info "Kernel: $KERNEL"
if [[ $KERNEL_MAJOR -lt 5 ]] || [[ $KERNEL_MAJOR -eq 5 && $KERNEL_MINOR -lt 8 ]]; then
  warn "Kernel $KERNEL may be too old for eBPF LSM (requires 5.8+). Proceeding anyway."
fi

# eBPF LSM check
if [[ $SKIP_EBPF -eq 0 ]]; then
  if [[ -f /boot/config-"$KERNEL" ]]; then
    if grep -q "CONFIG_BPF_LSM=y" /boot/config-"$KERNEL" 2>/dev/null; then
      info "CONFIG_BPF_LSM=y confirmed"
    else
      warn "CONFIG_BPF_LSM not confirmed. eBPF enforcement may not work."
      warn "Check: grep CONFIG_BPF_LSM /boot/config-\$(uname -r)"
    fi
  fi
  if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    info "BPF LSM active: $(cat /sys/kernel/security/lsm)"
  else
    warn "BPF LSM not in active LSM list. Add 'lsm=...,bpf' to the kernel cmdline and reboot."
  fi
  if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    warn "No BTF at /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF=y needed) — eBPF build will be skipped."
    SKIP_EBPF=1
  fi

  check_cmd clang    required "apt install clang llvm"
  check_cmd bpftool  required "apt install linux-tools-\$(uname -r)"
fi

if [[ $SKIP_APP -eq 0 ]]; then
  check_cmd npm required "apt install nodejs npm (Node 20+)"
  if ! cargo tauri --version &>/dev/null 2>&1; then
    die "cargo-tauri not found. Install it with: cargo install tauri-cli --version '^2' --locked (or pass --no-app)"
  fi
  info "cargo-tauri found ($(cargo tauri --version 2>/dev/null | head -1))"
fi

# ── Build eBPF kernel programs ────────────────────────────────────────────────

cd "$SCRIPT_DIR"

if [[ $SKIP_EBPF -eq 0 ]]; then
  step "Building eBPF kernel programs…"
  make -C "$SCRIPT_DIR/GPL/bpf" clean all
  info "eBPF programs built"
fi

# ── Build desktop app (frontend + Tauri) ──────────────────────────────────────

if [[ $SKIP_APP -eq 0 ]]; then
  step "Building frontend UI…"
  (cd "$SCRIPT_DIR/app/ui" && npm ci && npm run build)

  step "Building Tauri desktop app (embeds the frontend)…"
  # Always use the tauri CLI here. A plain `cargo build -p ringzero-app`
  # produces a binary with NO embedded frontend that tries to load the dev
  # server and shows a white screen.
  (cd "$SCRIPT_DIR/app/src-tauri" && cargo tauri build --no-bundle $([ "$DEV_MODE" -eq 1 ] && echo "--debug" || true))
fi

# ── Build daemon + CLI ────────────────────────────────────────────────────────

step "Building daemon and CLI (${BUILD_PROFILE})…"
cargo build $CARGO_FLAGS -p agent -p cli

CARGO_TARGET="target/${BUILD_PROFILE}"
for bin in ringzero-daemon rz; do
  [[ -f "$SCRIPT_DIR/$CARGO_TARGET/$bin" ]] || die "Missing $CARGO_TARGET/$bin — build failed"
done

# ── Create directories ────────────────────────────────────────────────────────

step "Creating directories…"

install -d -m 0755 /usr/lib/ringzero
install -d -m 0750 /etc/ringzero
install -d -m 0755 /var/run/ringzero
install -d -m 0750 /var/log/ringzero
install -d -m 0750 /var/lib/ringzero
install -d -m 0755 /usr/share/ringzero

info "Directories created"

# ── Install binaries ──────────────────────────────────────────────────────────

step "Installing binaries…"

install -m 0755 "$SCRIPT_DIR/$CARGO_TARGET/ringzero-daemon" /usr/bin/ringzero-daemon
info "Installed /usr/bin/ringzero-daemon"

install -m 0755 "$SCRIPT_DIR/$CARGO_TARGET/rz" /usr/bin/rz
info "Installed /usr/bin/rz"

install -m 0755 "$SCRIPT_DIR/hooks/rz-hook" /usr/bin/rz-hook
info "Installed /usr/bin/rz-hook"

if [[ $SKIP_APP -eq 0 ]] && [[ -f "$SCRIPT_DIR/$CARGO_TARGET/ringzero-app" ]]; then
  install -m 0755 "$SCRIPT_DIR/$CARGO_TARGET/ringzero-app" /usr/bin/ringzero-app
  info "Installed /usr/bin/ringzero-app"

  install -d -m 0755 /usr/share/ringzero/icons
  for icon in 32x32.png 128x128.png 128x128@2x.png; do
    [[ -f "$SCRIPT_DIR/app/src-tauri/icons/$icon" ]] && \
      install -m 0644 "$SCRIPT_DIR/app/src-tauri/icons/$icon" /usr/share/ringzero/icons/
  done

  install -d -m 0755 /usr/share/applications
  cat > /usr/share/applications/ringzero-security.desktop << 'DESKTOP'
[Desktop Entry]
Name=Ring Zero Security
Comment=See what your AI coding agents access, block what they shouldn't
Exec=/usr/bin/ringzero-app
Icon=ringzero-security
Terminal=false
Type=Application
Categories=System;Security;Monitor;
StartupNotify=true
StartupWMClass=ringzero-security
Keywords=security;ai;agent;ebpf;monitor;
DESKTOP
  if [[ -f /usr/share/ringzero/icons/128x128.png ]]; then
    install -d -m 0755 /usr/share/icons/hicolor/128x128/apps
    cp /usr/share/ringzero/icons/128x128.png /usr/share/icons/hicolor/128x128/apps/ringzero-security.png
    gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true
  fi
  info "Desktop application entry installed"
fi

# ── Install eBPF objects ──────────────────────────────────────────────────────

if [[ $SKIP_EBPF -eq 0 ]]; then
  for obj in ringzero.bpf.o; do
    if [[ -f "$SCRIPT_DIR/GPL/bpf/build/$obj" ]]; then
      install -m 0644 "$SCRIPT_DIR/GPL/bpf/build/$obj" "/usr/lib/ringzero/$obj"
      info "Installed /usr/lib/ringzero/$obj"
    else
      warn "Missing GPL/bpf/build/$obj — not installed"
    fi
  done
fi

# ── Install detection rules + agent skill ─────────────────────────────────────

if [[ -d "$SCRIPT_DIR/yara" ]]; then
  install -d -m 0755 /usr/share/ringzero/yara
  cp -r "$SCRIPT_DIR/yara/." /usr/share/ringzero/yara/
  info "Installed detection rules to /usr/share/ringzero/yara/"
fi

if [[ -d "$SCRIPT_DIR/packaging/skills" ]]; then
  install -d -m 0755 /usr/share/ringzero/skills
  cp -r "$SCRIPT_DIR/packaging/skills/." /usr/share/ringzero/skills/
  info "Installed agent skills to /usr/share/ringzero/skills/"
fi

# ── Install default config ────────────────────────────────────────────────────

step "Installing configuration…"

if [[ ! -f /etc/ringzero/daemon.toml ]]; then
  install -m 0640 "$SCRIPT_DIR/packaging/daemon.toml" /etc/ringzero/daemon.toml
  info "Installed /etc/ringzero/daemon.toml (default config)"
else
  warn "/etc/ringzero/daemon.toml already exists — not overwriting"
fi

# The daemon runs as root; config and state are root-only.
# Deliberately NOT `chmod -R 0750 /etc/ringzero`.
#
# A recursive chmod widens key files to group-readable, and the daemon then
# refuses to start, because load_key() rejects any key file with a group or
# world bit set. On a re-run over an existing install it would take a 0600
# typesafe.key down to 0750 and break the machine in a way whose error message
# points nowhere near the installer. Set directories and ordinary files
# separately, and leave every key at 0600. The .deb postinst does the same.
find /etc/ringzero -mindepth 1 -type d -exec chmod 0750 {} +
find /etc/ringzero -mindepth 1 -type f ! -name '*.key' -exec chmod 0640 {} +
find /etc/ringzero -mindepth 1 -type f -name '*.key' -exec chmod 0600 {} +
chmod 0750 /etc/ringzero
chmod 0750 /var/lib/ringzero
chmod 0750 /var/log/ringzero

# ── Install systemd service ───────────────────────────────────────────────────

if [[ $SKIP_SERVICE -eq 0 ]] && command -v systemctl &>/dev/null; then
  step "Installing systemd service…"

  install -m 0644 "$SCRIPT_DIR/packaging/ringzero-daemon.service" /etc/systemd/system/ringzero-daemon.service
  info "Installed ringzero-daemon.service"

  # Embed the installing user's UID so the daemon's IPC socket peer-credential
  # check accepts the local UI / CLI (see packaging/deb/DEBIAN/postinst).
  OP_UID="${SUDO_UID:-}"
  if [[ -n "$OP_UID" && "$OP_UID" != "0" ]]; then
    install -d -m 0755 /etc/systemd/system/ringzero-daemon.service.d
    cat > /etc/systemd/system/ringzero-daemon.service.d/operator-uid.conf <<EOF
[Service]
Environment=RZ_OPERATOR_UID=${OP_UID}
EOF
    info "Embedded RZ_OPERATOR_UID=${OP_UID} for IPC peer-credential check"
  fi

  systemctl daemon-reload

  info "Enabling and starting ringzero-daemon…"
  systemctl enable ringzero-daemon
  systemctl restart ringzero-daemon

  # Give the operator the READ-ONLY token, so the desktop app and rz-hook can
  # read from the local HTTP API.
  #
  # THIS MUST NEVER BE THE FULL-SCOPE TOKEN. An AI coding agent runs as the same
  # Unix user as the operator, so anything in that user's home is in the agent's
  # reach. A full token there would hand the agent the credential needed to turn
  # enforcement off, which defeats the entire point of the product. The full
  # token stays root-only at /var/lib/ringzero/api-token, and changing policy
  # goes through `sudo rz ...`.
  #
  # This script copied the full token until 2026-09-23. The .deb postinst always
  # did the right thing, so only source installs were affected — which is to say
  # most people building from the public repo. Keep the two installers in step.
  sleep 1
  if [[ -n "$OP_UID" && "$OP_UID" != "0" && -f /var/lib/ringzero/api-token-readonly ]]; then
    op_home=$(getent passwd "$OP_UID" | cut -d: -f6)
    if [[ -n "$op_home" ]]; then
      dest="$op_home/.config/ringzero"
      # Never follow an operator-placed symlink while writing as root.
      if [[ -L "$op_home/.config" || -L "$dest" || -L "$dest/api-token" ]]; then
        warn "Skipping API token copy: $dest contains a symlink"
      else
        install -d -m 0700 -o "$OP_UID" -g "$OP_UID" "$dest"
        install -m 0600 -o "$OP_UID" -g "$OP_UID" \
          /var/lib/ringzero/api-token-readonly "$dest/api-token"
        info "Read-only API token copied to $dest/api-token"
      fi
    fi
  fi
fi

# ── Shell completion ──────────────────────────────────────────────────────────

if [[ -d /etc/bash_completion.d ]]; then
  cat > /etc/bash_completion.d/rz << 'EOF'
_rz_completion() {
  local cur prev words cword
  _init_completion || return
  local commands="status events policy threats diffs sessions escalations audit network enforcement file-access nhi shadow-ai scan session-events setup"
  local policy_cmds="show block-domain set-mode"
  local session_cmds="list create get terminate approve"
  local escalation_cmds="list approve deny"
  local audit_cmds="recent verify export"
  local network_cmds="show set-mode set-enforce"
  local enforcement_cmds="show set-default set-category"
  local file_access_cmds="show add remove"
  local scan_cmds="skills"
  case $prev in
    rz)          COMPREPLY=($(compgen -W "$commands" -- "$cur")) ;;
    policy)      COMPREPLY=($(compgen -W "$policy_cmds" -- "$cur")) ;;
    sessions)    COMPREPLY=($(compgen -W "$session_cmds" -- "$cur")) ;;
    escalations) COMPREPLY=($(compgen -W "$escalation_cmds" -- "$cur")) ;;
    audit)       COMPREPLY=($(compgen -W "$audit_cmds" -- "$cur")) ;;
    network)     COMPREPLY=($(compgen -W "$network_cmds" -- "$cur")) ;;
    enforcement) COMPREPLY=($(compgen -W "$enforcement_cmds" -- "$cur")) ;;
    file-access) COMPREPLY=($(compgen -W "$file_access_cmds" -- "$cur")) ;;
    scan)        COMPREPLY=($(compgen -W "$scan_cmds" -- "$cur")) ;;
    set-mode)    COMPREPLY=($(compgen -W "low medium high" -- "$cur")) ;;
    set-enforce) COMPREPLY=($(compgen -W "enforce observe" -- "$cur")) ;;
    set-default) COMPREPLY=($(compgen -W "observe alert block" -- "$cur")) ;;
  esac
}
complete -F _rz_completion rz
EOF
  info "Installed bash completion for rz"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}Ring Zero Security installed successfully.${RESET}"
echo ""
echo "  Daemon status:   systemctl status ringzero-daemon"
echo "  CLI:             rz status"
echo "  Events:          rz events"
echo "  HTTP API:        curl http://127.0.0.1:7700/api/v1/health"
echo "  Config:          /etc/ringzero/daemon.toml"
echo "  Logs:            journalctl -u ringzero-daemon -f"
if [[ $SKIP_APP -eq 0 ]] && [[ -f /usr/bin/ringzero-app ]]; then
  echo "  Desktop app:     open 'Ring Zero Security' from your application menu"
fi
echo ""
if [[ $SKIP_EBPF -eq 1 ]]; then
  warn "eBPF programs not installed. Kernel enforcement is inactive."
  warn "Install clang + bpftool on a kernel with BTF and re-run to enable."
elif ! grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
  warn "BPF LSM is not active in the running kernel. Add 'bpf' to the lsm= boot"
  warn "parameter (see packaging/deb/DEBIAN/postinst for the GRUB steps) and reboot."
fi
echo ""
