#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Ring Zero Security — Linux installer
#
# Downloads the latest .deb from GitHub Releases and installs it.
# Usage: curl -fsSL https://ringzerosecurity.com/install.sh | sudo bash
#
# For building from source instead, see: ./install-from-source.sh
# Requires: Linux x86_64 or aarch64, Debian/Ubuntu (dpkg/apt)

set -euo pipefail

REPO="ringzerosec/jev-agentic-security"
INSTALL_DIR=$(mktemp -d)
trap 'rm -rf "$INSTALL_DIR"' EXIT

# ── Helpers ──────────────────────────────────────────────────────────────────

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

info()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*" >&2; }
die()   { echo -e "${RED}[x]${RESET} $*" >&2; exit 1; }

# ── Pre-flight checks ───────────────────────────────────────────────────────

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

PLATFORM="$(uname -s)"
[[ "$(id -u)" == "0" ]] || die "Run with sudo: curl -fsSL ... | sudo bash"
[[ "$PLATFORM" == "Linux" ]] || die "Unsupported OS: $PLATFORM (this installer is Linux only)"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  DEB_ARCH="amd64" ;;
  aarch64) DEB_ARCH="arm64" ;;
  *)       die "Unsupported architecture: $ARCH (need x86_64 or aarch64)" ;;
esac

# Check kernel version (need 5.8+ for BPF CO-RE + LSM)
KVER=$(uname -r | cut -d. -f1-2)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
if [[ "$KMAJOR" -lt 5 ]] || { [[ "$KMAJOR" -eq 5 ]] && [[ "$KMINOR" -lt 8 ]]; }; then
  warn "Kernel $(uname -r) detected. Ring Zero needs 5.8+ for eBPF CO-RE and BPF LSM."
  warn "The daemon will start but kernel-level monitoring will be limited."
fi

# Check for BTF (required for eBPF CO-RE)
if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
  warn "No BTF found at /sys/kernel/btf/vmlinux."
  warn "Your kernel may need CONFIG_DEBUG_INFO_BTF=y for eBPF support."
fi

# Check for dpkg/apt
command -v dpkg &>/dev/null || die "dpkg not found. This installer supports Debian/Ubuntu. For other distros, build from source: https://github.com/$REPO"

# ── Detect latest release ────────────────────────────────────────────────────

info "Finding latest Ring Zero release..."

if command -v curl &>/dev/null; then
  FETCH="curl -fsSL"
elif command -v wget &>/dev/null; then
  FETCH="wget -qO-"
else
  die "Need curl or wget to download"
fi

# Get latest release tag from GitHub API
LATEST=$($FETCH "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/') || true

if [[ -z "$LATEST" ]]; then
  # Fallback: list all releases
  LATEST=$($FETCH "https://api.github.com/repos/$REPO/releases" 2>/dev/null \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/') || true
fi

[[ -n "$LATEST" ]] || die "Could not find a release. Check https://github.com/$REPO/releases"

VERSION="${LATEST#v}"  # strip leading 'v'
info "Latest version: $VERSION ($LATEST)"

# ── Download .deb ────────────────────────────────────────────────────────────

DEB_NAME="ringzero-security_${VERSION}_${DEB_ARCH}.deb"
DEB_URL="https://github.com/$REPO/releases/download/$LATEST/$DEB_NAME"
FALLBACK_URL="https://ringzerosecurity.com/downloads/$DEB_NAME"

info "Downloading $DEB_NAME..."
DOWNLOADED=0
if command -v curl &>/dev/null; then
  curl -fSL --progress-bar -o "$INSTALL_DIR/$DEB_NAME" "$DEB_URL" 2>/dev/null && DOWNLOADED=1
  if [[ "$DOWNLOADED" -eq 0 ]]; then
    warn "GitHub download failed, trying ringzerosecurity.com..."
    curl -fSL --progress-bar -o "$INSTALL_DIR/$DEB_NAME" "$FALLBACK_URL" && DOWNLOADED=1
  fi
else
  wget -q --show-progress -O "$INSTALL_DIR/$DEB_NAME" "$DEB_URL" 2>/dev/null && DOWNLOADED=1
  if [[ "$DOWNLOADED" -eq 0 ]]; then
    warn "GitHub download failed, trying ringzerosecurity.com..."
    wget -q --show-progress -O "$INSTALL_DIR/$DEB_NAME" "$FALLBACK_URL" && DOWNLOADED=1
  fi
fi
[[ "$DOWNLOADED" -eq 1 ]] || die "Download failed from both GitHub and ringzerosecurity.com"

info "Downloaded $(du -h "$INSTALL_DIR/$DEB_NAME" | cut -f1)"

# ── Install ──────────────────────────────────────────────────────────────────

info "Installing Ring Zero Security..."
if command -v apt-get &>/dev/null; then
  # apt handles dependencies automatically
  apt-get install -y "$INSTALL_DIR/$DEB_NAME" 2>/dev/null || {
    dpkg -i "$INSTALL_DIR/$DEB_NAME" || {
      apt-get install -f -y 2>/dev/null || true
      dpkg -i "$INSTALL_DIR/$DEB_NAME"
    }
  }
else
  dpkg -i "$INSTALL_DIR/$DEB_NAME" || {
    warn "Some dependencies may be missing. Install them manually."
  }
fi

# ── Done (postinst handles the rest: GRUB, keys, reboot prompt) ─────────────
