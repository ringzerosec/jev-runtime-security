#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Ring Zero Security — build the Debian packages
#
# Two packages, on purpose:
#
#   ringzero-security   daemon, rz, rz-hook, eBPF object, config, skills, demos.
#                       Depends on libc6 and libgcc-s1 and nothing else, so a
#                       headless server never pulls in a GUI stack.
#   ringzero-desktop    the Tauri viewer, its .desktop entry and icons. Depends
#                       on the GTK/WebKit stack, which is exactly why it is not
#                       part of the daemon package.
#
# Usage:
#   ./build-deb.sh                     both packages, host architecture
#   ./build-deb.sh --daemon-only       skip the app (CI, headless builds)
#   ./build-deb.sh arm64               both packages for an explicit arch
#   ./build-deb.sh --daemon-only arm64

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_VERSION=$(tr -d '[:space:]' < "$SCRIPT_DIR/VERSION" 2>/dev/null || grep '^version' "$SCRIPT_DIR/Cargo.toml" | head -1 | awk -F'"' '{print $2}' || echo "0.1.0")

# A BUILD IDENTIFIER, so an upgrade is never a silent no-op.
#
# Both control files carried a static 0.1.0, so apt compared the new package
# against the installed one, found the same version, and reported "already the
# newest version" while the tester kept running old code. That is how a stale
# interface reached a tester. The suffix is the commit and a UTC timestamp, and
# dpkg orders it after a bare 0.1.0, so every build is an upgrade.
BUILD_ID="$(git -C "$SCRIPT_DIR" rev-parse --short=8 HEAD 2>/dev/null || echo nogit)"
BUILD_STAMP="$(date -u +%Y%m%d%H%M%S)"
if [ -n "$(git -C "$SCRIPT_DIR" status --porcelain 2>/dev/null)" ]; then
  BUILD_ID="${BUILD_ID}dirty"
fi
VERSION="${BASE_VERSION}+${BUILD_STAMP}.g${BUILD_ID}"
echo "[+] Build version: ${VERSION}"

DAEMON_ONLY=0
ARCH=""
for arg in "$@"; do
  case "$arg" in
    --daemon-only) DAEMON_ONLY=1 ;;
    -h|--help) sed -n '3,20p' "$0"; exit 0 ;;
    *) ARCH="$arg" ;;
  esac
done
ARCH=${ARCH:-$(dpkg --print-architecture 2>/dev/null || echo "amd64")}

PKG="ringzero-security_${VERSION}_${ARCH}"
STAGING="$SCRIPT_DIR/target/deb/$PKG"
DESKTOP_PKG="ringzero-desktop_${VERSION}_${ARCH}"
DESKTOP_STAGING="$SCRIPT_DIR/target/deb/$DESKTOP_PKG"

echo "[+] Building Ring Zero Security v${VERSION} (${ARCH})"

# ── Build eBPF programs ───────────────────────────────────────────────────────
EBPF_DIR="$SCRIPT_DIR/GPL/bpf"
if command -v clang &>/dev/null && [[ -f /sys/kernel/btf/vmlinux ]]; then
  echo "[+] Compiling eBPF programs..."
  make -C "$EBPF_DIR" clean all 2>&1 | tail -3
  echo "[+] eBPF programs compiled"
else
  echo "[!] Skipping eBPF build (need clang + /sys/kernel/btf/vmlinux)"
  echo "    Install: sudo apt install clang llvm bpftool linux-headers-\$(uname -r) libbpf-dev"
fi

# ── Build daemon + CLI ────────────────────────────────────────────────────────
echo "[+] Building daemon and CLI..."
cargo build --release -p agent -p cli 2>&1 | tail -3

# Ensure release binaries exist
for bin in ringzero-daemon rz; do
  [[ -f "$SCRIPT_DIR/target/release/$bin" ]] || {
    echo "[!] Missing target/release/$bin"
    exit 1
  }
done

# Stage package
rm -rf "$STAGING"
mkdir -p "$STAGING"
cp -r "$SCRIPT_DIR/packaging/deb/DEBIAN" "$STAGING/DEBIAN"
mkdir -p "$STAGING/usr/bin" \
         "$STAGING/usr/lib/ringzero" \
         "$STAGING/etc/ringzero" \
         "$STAGING/etc/systemd/system" \
         "$STAGING/var/log/ringzero"

# Binaries
install -m 0755 "$SCRIPT_DIR/target/release/ringzero-daemon" "$STAGING/usr/bin/"
install -m 0755 "$SCRIPT_DIR/target/release/rz"              "$STAGING/usr/bin/"
# Hook script for agent event capture (Codex, Claude Code)
install -m 0755 "$SCRIPT_DIR/hooks/rz-hook" "$STAGING/usr/bin/"

# eBPF objects
[[ -f "$SCRIPT_DIR/GPL/bpf/build/ringzero.bpf.o" ]] && \
  install -m 0644 "$SCRIPT_DIR/GPL/bpf/build/ringzero.bpf.o" "$STAGING/usr/lib/ringzero/"
[[ -f "$SCRIPT_DIR/GPL/bpf/build/stdiocap.bpf.o" ]] && \
  install -m 0644 "$SCRIPT_DIR/GPL/bpf/build/stdiocap.bpf.o" "$STAGING/usr/lib/ringzero/"

# The build stamp, read at runtime by rz and the app so a tester can confirm
# which build they are on without guessing from file dates.
printf '%s\n' "$VERSION" > "$STAGING/usr/lib/ringzero/BUILD"
chmod 0644 "$STAGING/usr/lib/ringzero/BUILD"

# Systemd service
install -m 0644 "$SCRIPT_DIR/packaging/ringzero-daemon.service"    "$STAGING/etc/systemd/system/"

# Default config (preserves existing on upgrade via conffiles)
install -m 0640 "$SCRIPT_DIR/packaging/daemon.toml" "$STAGING/etc/ringzero/"

# Agent skills (e.g. the 'ringzero' management skill for headless servers — the
# postinst installs it into the operator's agent skills dir)
if [[ -d "$SCRIPT_DIR/packaging/skills" ]]; then
  mkdir -p "$STAGING/usr/share/ringzero/skills"
  cp -r "$SCRIPT_DIR/packaging/skills/." "$STAGING/usr/share/ringzero/skills/"
  echo "[+] Agent skills included"
fi

# Web UI. The daemon serves these static assets on loopback from
# /usr/share/ringzero/ui, so a headless box gets the same read-only views in a
# browser with no GTK or WebKit anywhere near it.
# Build it here rather than trusting whatever dist happens to be on disk: a
# stale bundle ships an old interface against a current daemon, which is worse
# than shipping none, because nothing about it looks wrong.
if [[ -d "$SCRIPT_DIR/app/ui" && "${RZ_SKIP_UI_BUILD:-0}" != "1" ]]; then
  echo "[+] Building the web UI"
  ( cd "$SCRIPT_DIR/app/ui" \
    && { [[ -d node_modules ]] || npm ci --no-audit --no-fund >/dev/null; } \
    && npm run build >/dev/null ) \
    || { echo "[x] Web UI build failed — refusing to package a stale bundle"; exit 1; }
fi

if [[ -d "$SCRIPT_DIR/app/ui/dist" ]]; then
  mkdir -p "$STAGING/usr/share/ringzero/ui"
  cp -r "$SCRIPT_DIR/app/ui/dist/." "$STAGING/usr/share/ringzero/ui/"
  echo "[+] Web UI included"
else
  echo "[!] app/ui/dist missing — building without the web UI (run: cd app/ui && npm ci && npm run build)"
fi

# Runnable demos. A security claim someone can test on their own machine is
# worth more than a paragraph, so the package ships them.
if [[ -d "$SCRIPT_DIR/examples" ]]; then
  mkdir -p "$STAGING/usr/share/ringzero/examples"
  install -m 0755 "$SCRIPT_DIR/examples"/*.sh "$STAGING/usr/share/ringzero/examples/"
  install -m 0644 "$SCRIPT_DIR/examples/README.md" "$STAGING/usr/share/ringzero/examples/"
  echo "[+] Demos included"
fi

# Fix DEBIAN script permissions
chmod 0755 "$STAGING/DEBIAN/preinst" \
           "$STAGING/DEBIAN/postinst" \
           "$STAGING/DEBIAN/prerm" \
           "$STAGING/DEBIAN/postrm"

# Update architecture in control
sed -i "s/^Architecture:.*/Architecture: ${ARCH}/" "$STAGING/DEBIAN/control"
sed -i "s/^Version:.*/Version: ${VERSION}/"        "$STAGING/DEBIAN/control"

# Compute installed-size
SIZE=$(du -sk "$STAGING" | cut -f1)
sed -i "/^Installed-Size/d" "$STAGING/DEBIAN/control"
echo "Installed-Size: $SIZE" >> "$STAGING/DEBIAN/control"

# Build
# --root-owner-group forces files inside the package to be owned by root:root
# instead of the (non-root) build user, which dpkg-deb otherwise warns about
# and which would ship world-writable-by-uid-1000 system files.
mkdir -p "$SCRIPT_DIR/target/deb"
dpkg-deb --root-owner-group --build "$STAGING" "$SCRIPT_DIR/target/deb/${PKG}.deb"

echo ""
echo "[+] Package built: target/deb/${PKG}.deb"
echo "    Install with: sudo apt install ./target/deb/${PKG}.deb"

# ── ringzero-desktop ─────────────────────────────────────────────────────────
if [[ "$DAEMON_ONLY" -eq 1 ]]; then
  echo ""
  echo "[i] --daemon-only: skipping ringzero-desktop"
  exit 0
fi

echo ""
echo "[+] Building the desktop viewer..."

if ! command -v npm &>/dev/null; then
  echo "[!] npm not found — cannot build the viewer's frontend."
  echo "    Install Node 22+, or run with --daemon-only."
  exit 1
fi

echo "[+] Building frontend..."
(cd "$SCRIPT_DIR/app/ui" && npm ci --silent && npm run build 2>&1 | tail -3)

# The tauri CLI is what embeds the built frontend into the binary. Without it,
# `cargo build -p ringzero-app` produces a binary that tries to load the Vite
# dev server and shows the user a connection-refused white screen. Fail loudly
# rather than ship that.
if command -v cargo-tauri &>/dev/null || cargo tauri --version &>/dev/null 2>&1; then
  echo "[+] Building the Tauri binary (frontend embedded)..."
  (cd "$SCRIPT_DIR/app/src-tauri" && cargo tauri build --no-bundle 2>&1 | tail -5)
else
  echo "[!] cargo-tauri not found — cannot build a viewer with an embedded frontend."
  echo "    Install it:  cargo install tauri-cli --version '^2' --locked"
  echo "    Or build the daemon package alone:  ./build-deb.sh --daemon-only"
  exit 1
fi

[[ -f "$SCRIPT_DIR/target/release/ringzero-app" ]] || {
  echo "[!] Missing target/release/ringzero-app"
  exit 1
}

rm -rf "$DESKTOP_STAGING"
mkdir -p "$DESKTOP_STAGING/DEBIAN" \
         "$DESKTOP_STAGING/usr/bin" \
         "$DESKTOP_STAGING/usr/share/ringzero/icons"

cp "$SCRIPT_DIR/packaging/deb-desktop/DEBIAN/control"  "$DESKTOP_STAGING/DEBIAN/"
cp "$SCRIPT_DIR/packaging/deb-desktop/DEBIAN/postinst" "$DESKTOP_STAGING/DEBIAN/"
cp "$SCRIPT_DIR/packaging/deb-desktop/DEBIAN/prerm"    "$DESKTOP_STAGING/DEBIAN/"
chmod 0755 "$DESKTOP_STAGING/DEBIAN/postinst" "$DESKTOP_STAGING/DEBIAN/prerm"

install -m 0755 "$SCRIPT_DIR/target/release/ringzero-app" "$DESKTOP_STAGING/usr/bin/"

# Verify the frontend really is embedded. Vite emits hashed asset names that
# only appear in the binary when the UI was bundled in. grep -c (not -q) so
# `strings` is never SIGPIPE'd under pipefail.
_embed_hits=$(strings "$DESKTOP_STAGING/usr/bin/ringzero-app" 2>/dev/null \
  | grep -cE 'assets/index-[A-Za-z0-9_-]+\.(js|css)' || true)
if [[ "${_embed_hits:-0}" -eq 0 ]]; then
  echo "[!] ringzero-app has no embedded frontend — refusing to package it."
  echo "    Such a binary shows 'connection refused' on launch."
  exit 1
fi
echo "[+] Frontend embed verified"

for icon in 32x32.png 64x64.png 128x128.png 128x128@2x.png icon.png; do
  [[ -f "$SCRIPT_DIR/app/src-tauri/icons/$icon" ]] && \
    install -m 0644 "$SCRIPT_DIR/app/src-tauri/icons/$icon" "$DESKTOP_STAGING/usr/share/ringzero/icons/"
done

# The launcher and its icons ship as REAL FILES in the package, not as a
# heredoc in postinst. A package that is unpacked but not configured — which is
# what a wedged conffile prompt leaves behind — then still has a working
# launcher entry instead of none at all. postinst only refreshes the caches.
#
# One name throughout: the binary is ringzero-app, the launcher is
# ringzero-app.desktop, it declares StartupWMClass=ringzero-app, and the icons
# are installed as ringzero-app.png. The shell matches a window to its launcher
# by WM class and then shows that launcher's Icon=, so the four agreeing is
# what puts an icon on the window under Wayland, where an icon compiled into
# the binary is ignored.
mkdir -p "$DESKTOP_STAGING/usr/share/applications"
install -m 0644 "$SCRIPT_DIR/packaging/deb-desktop/ringzero-app.desktop" \
  "$DESKTOP_STAGING/usr/share/applications/ringzero-app.desktop"

# Every size a shell actually asks for. hicolor lookup takes an exact-size
# directory first and only scales when there is no match, so shipping 32 and 64
# is the difference between a crisp icon and a downscaled 128.
# There is no SVG in the source tree, so no scalable/ directory is installed.
_install_icon() { # <source file> <hicolor dir>
  [[ -f "$SCRIPT_DIR/app/src-tauri/icons/$1" ]] || return 0
  mkdir -p "$DESKTOP_STAGING/usr/share/icons/hicolor/$2/apps"
  install -m 0644 "$SCRIPT_DIR/app/src-tauri/icons/$1" \
    "$DESKTOP_STAGING/usr/share/icons/hicolor/$2/apps/ringzero-app.png"
}
_install_icon 32x32.png       32x32
_install_icon 64x64.png       64x64
_install_icon 128x128.png     128x128
_install_icon 128x128@2x.png  256x256   # the file is genuinely 256x256
_install_icon icon.png        512x512   # the file is genuinely 512x512

# A package that claims a launcher and ships no icon for it is the bug we just
# fixed; fail the build rather than ship it again.
for _want in 32x32 64x64 128x128 256x256 512x512; do
  [[ -f "$DESKTOP_STAGING/usr/share/icons/hicolor/$_want/apps/ringzero-app.png" ]] || {
    echo "[!] Missing hicolor/$_want icon — refusing to package a launcher with no icon."
    exit 1
  }
done
echo "[+] Launcher and 5 icon sizes staged"

# Polkit action for the app's privileged writes. Without this file pkexec falls
# back to a generic action and the person authenticating is asked to approve
# "running a program as root" rather than a change to enforcement.
mkdir -p "$DESKTOP_STAGING/usr/share/polkit-1/actions"
install -m 0644 "$SCRIPT_DIR/packaging/polkit/com.ringzerosecurity.app.policy" \
  "$DESKTOP_STAGING/usr/share/polkit-1/actions/com.ringzerosecurity.app.policy"

sed -i "s/^Architecture:.*/Architecture: ${ARCH}/" "$DESKTOP_STAGING/DEBIAN/control"
sed -i "s/^Version:.*/Version: ${VERSION}/"        "$DESKTOP_STAGING/DEBIAN/control"
# Keep the dependency on the daemon package pinned to this exact version.
sed -i "s/ringzero-security (= [^)]*)/ringzero-security (= ${VERSION})/" "$DESKTOP_STAGING/DEBIAN/control"

DSIZE=$(du -sk "$DESKTOP_STAGING" | cut -f1)
sed -i "/^Installed-Size/d" "$DESKTOP_STAGING/DEBIAN/control"
echo "Installed-Size: $DSIZE" >> "$DESKTOP_STAGING/DEBIAN/control"

dpkg-deb --root-owner-group --build "$DESKTOP_STAGING" "$SCRIPT_DIR/target/deb/${DESKTOP_PKG}.deb"

echo ""
echo "[+] Package built: target/deb/${DESKTOP_PKG}.deb"
echo "    Install with: sudo apt install ./target/deb/${PKG}.deb ./target/deb/${DESKTOP_PKG}.deb"
