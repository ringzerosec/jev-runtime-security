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
