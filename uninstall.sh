#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Ring Zero Security — Linux uninstall script (for source installs)
# Usage: sudo ./uninstall.sh [--purge]
#
# If you installed the .deb, use `sudo apt remove ringzero-security` instead.

set -euo pipefail

GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"
info()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
die()   { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

PURGE=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --help|-h)
      echo "Usage: sudo $0 [--purge]"
      echo "  --purge  Also remove /etc/ringzero config, /var/lib/ringzero state and /var/log/ringzero logs"
      exit 0 ;;
  esac
done

[[ $EUID -ne 0 ]] && die "Must run as root"

echo "Uninstalling Ring Zero Security…"
echo ""

# Stop and disable the service
svc=ringzero-daemon
if systemctl is-active --quiet "$svc" 2>/dev/null; then
  systemctl stop "$svc"
  info "Stopped $svc"
fi
if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
  systemctl disable "$svc"
  info "Disabled $svc"
fi
if [[ -f "/etc/systemd/system/$svc.service" ]]; then
  rm "/etc/systemd/system/$svc.service"
  info "Removed $svc.service"
fi
[[ -d /etc/systemd/system/ringzero-daemon.service.d ]] && rm -rf /etc/systemd/system/ringzero-daemon.service.d

systemctl daemon-reload

# Make sure no kernel programs are left behind, and say so truthfully.
#
# WHAT WAS MEASURED, on Linux 6.8 with the daemon running 14 LSM programs and 2
# cgroup_sock_addr programs:
#
#   - Stopping the service takes all 16 to zero. Every time. The kernel holds
#     these against the owning process's descriptor, so they go when it goes.
#   - An LSM link CANNOT be detached from outside. `bpftool link detach id N`
#     on one returns "Operation not supported". That is by design, not a
#     syntax problem, so no better command exists.
#   - There were no legacy cgroup attachments to find at all.
#
# So the honest job here is not detaching, it is VERIFYING. An earlier version
# of this ran two commands that were invalid, discarded their errors, and then
# printed "Detached eBPF programs" regardless — the exact failure this product
# exists to catch in other software.
#
# The legacy sweep below is kept because on kernels before 5.7 cgroup programs
# are attached without links and do survive process exit. That path could not
# be exercised here, and is written to be harmless when there is nothing to do.
rz_detach_ebpf() {
  # Programs are named ringzero_* (the kernel truncates to 15 chars).
  local ids
  ids=$(bpftool prog list 2>/dev/null | awk '/ name ringzero_/ {sub(":", "", $1); print $1}' || true)
  [ -z "$ids" ] && return 0
  # bpf_link attachments: every LSM hook, and cgroup hooks on kernels >= 5.7.
  # "ID: TYPE  prog PROG_ID ..." -> "LINK_ID PROG_ID"
  bpftool link list 2>/dev/null \
    | awk '/^[0-9]+:/ {for (i = 2; i < NF; i++) if ($i == "prog") {sub(":", "", $1); print $1, $(i + 1)}}' \
    | while read -r link_id prog; do
        for id in $ids; do
          if [ "$prog" = "$id" ]; then bpftool link detach id "$link_id" 2>/dev/null || true; fi
        done
      done || true
  # Legacy cgroup attachments (pre-5.7 fallback) are not links and survive
  # process exit. "ID  ATTACH_TYPE  [FLAGS]  NAME" -> detach by type and id.
  for cg in /sys/fs/cgroup /sys/fs/cgroup/unified; do
    [ -d "$cg" ] || continue
    bpftool cgroup show "$cg" 2>/dev/null \
      | awk '$1 ~ /^[0-9]+$/ && $NF ~ /^ringzero_/ {print $1, $2}' \
      | while read -r id type; do
          bpftool cgroup detach "$cg" "$type" id "$id" 2>/dev/null || true
        done || true
  done
}

rz_ebpf_remaining() {
  bpftool prog list 2>/dev/null | grep -c ' name ringzero_' || true
}

if command -v bpftool &>/dev/null; then
  rz_detach_ebpf
  left=$(rz_ebpf_remaining)
  if [[ "$left" -eq 0 ]]; then
    info "No eBPF programs remain loaded"
  else
    warn "$left ringzero eBPF program(s) are STILL LOADED. Stopping the service"
    warn "normally clears them, so this means something is still holding them."
    warn "Check 'bpftool prog list'; a reboot will clear them for certain."
  fi
else
  warn "bpftool not found — could not verify that eBPF programs were unloaded."
  warn "Stopping the service normally clears them. If enforcement appears to"
  warn "still be active, reboot to be certain."
fi

# Remove pinned BPF objects
[[ -d /sys/fs/bpf/ringzero ]] && rm -rf /sys/fs/bpf/ringzero 2>/dev/null || true

# Remove binaries
for bin in /usr/bin/ringzero-daemon /usr/bin/rz /usr/bin/rz-hook /usr/bin/ringzero-app; do
  [[ -f "$bin" ]] && rm "$bin" && info "Removed $bin"
done

# Remove desktop entry + icon
[[ -f /usr/share/applications/ringzero-security.desktop ]] && rm /usr/share/applications/ringzero-security.desktop && info "Removed desktop entry"
[[ -f /usr/share/icons/hicolor/128x128/apps/ringzero-security.png ]] && rm /usr/share/icons/hicolor/128x128/apps/ringzero-security.png
gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true

# Remove eBPF objects
[[ -d /usr/lib/ringzero ]] && rm -rf /usr/lib/ringzero && info "Removed /usr/lib/ringzero"

# Remove YARA rules, icons, skills
[[ -d /usr/share/ringzero ]] && rm -rf /usr/share/ringzero && info "Removed /usr/share/ringzero"

# Remove shell completion
[[ -f /etc/bash_completion.d/rz ]] && rm /etc/bash_completion.d/rz && info "Removed bash completion"

# Remove runtime directory
[[ -d /var/run/ringzero ]] && rm -rf /var/run/ringzero && info "Removed /var/run/ringzero"

if [[ $PURGE -eq 1 ]]; then
  [[ -d /etc/ringzero ]]     && rm -rf /etc/ringzero     && info "Removed /etc/ringzero (purge)"
  [[ -d /var/lib/ringzero ]] && rm -rf /var/lib/ringzero && info "Removed /var/lib/ringzero (purge)"
  [[ -d /var/log/ringzero ]] && rm -rf /var/log/ringzero && info "Removed /var/log/ringzero (purge)"
else
  warn "Config (/etc/ringzero), state (/var/lib/ringzero) and logs (/var/log/ringzero) preserved."
  warn "Run with --purge to remove them."
fi

echo ""
info "Ring Zero Security uninstalled."
