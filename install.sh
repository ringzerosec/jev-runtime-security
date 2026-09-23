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

# ── Verify the download before handing it to dpkg as root ───────────────────
#
# This script is run as `curl ... | sudo bash`, and dpkg runs maintainer
# scripts as root. Installing a package nobody checked means trusting the
# transport and whatever served it. The release workflow already publishes
# SHA256SUMS next to the .deb, so there is a checksum to check and no reason
# not to.
#
# A missing SHA256SUMS is a REFUSAL, not a warning. "Could not verify, carrying
# on anyway" is the same as not verifying, and it is worse because it looks
# like a check happened. RZ_SKIP_CHECKSUM=1 exists for someone deliberately
# installing an unpublished build, and it says loudly what it is doing.
# The release workflow publishes one sums file per architecture.
SUMS_NAME="SHA256SUMS-${DEB_ARCH}.txt"
SUMS_URL="https://github.com/$REPO/releases/download/$LATEST/$SUMS_NAME"
if [[ "${RZ_SKIP_CHECKSUM:-0}" == "1" ]]; then
  warn "RZ_SKIP_CHECKSUM=1 — installing a package that has NOT been verified."
else
  info "Verifying checksum..."
  SUMS_FILE="$INSTALL_DIR/SHA256SUMS"
  if ! $FETCH "$SUMS_URL" > "$SUMS_FILE" 2>/dev/null || [[ ! -s "$SUMS_FILE" ]]; then
    die "Could not fetch $SUMS_NAME from $SUMS_URL — refusing to install an unverified package. Re-run with RZ_SKIP_CHECKSUM=1 only if you know why it is missing."
  fi
  EXPECTED="$(grep -F " $DEB_NAME" "$SUMS_FILE" | awk '{print $1}' | head -1)"
  [[ -n "$EXPECTED" ]] || die "$SUMS_NAME has no entry for $DEB_NAME — refusing to install."
  command -v sha256sum &>/dev/null || die "sha256sum not found — cannot verify the download."
  ACTUAL="$(sha256sum "$INSTALL_DIR/$DEB_NAME" | awk '{print $1}')"
  if [[ "$ACTUAL" != "$EXPECTED" ]]; then
    rm -f "$INSTALL_DIR/$DEB_NAME"
    die "CHECKSUM MISMATCH for $DEB_NAME. Expected $EXPECTED, got $ACTUAL. The download has been deleted and nothing was installed."
  fi
  info "Checksum verified"
fi

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
