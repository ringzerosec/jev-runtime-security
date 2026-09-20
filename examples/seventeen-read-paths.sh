#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Ring Zero demo — an "agent" tries 17 different ways to read one secret.
#
# What this shows: the kernel-side eBPF LSM hook (drivers/linux/ebpf/ringzero.bpf.c,
# `ringzero_file_open`) decides on every open(2) made by a monitored agent process
# or one of its descendants. It does not matter which tool does the reading, whether
# the path is reached through a symlink or a hardlink, or whether the file is
# renamed first — the open is refused with EACCES before any byte is read.
#
# Requirements:
#   - ringzero-daemon running as root with the eBPF programs loaded
#     (`rz status` must show kernel monitoring active; BPF LSM must be enabled —
#     see README "Install").
#   - `rz` on PATH (installed by the .deb). Run this script as your normal user.
#
# The script never touches your real ~/.ssh. It creates a throwaway secret under
# ~/rz-demo (override with RZ_DEMO_DIR; not /tmp — the daemon runs with
# PrivateTmp and could not pin the file's inode there), registers it as
# protected, and runs the read attempts inside a process named `claude` (a copy
# of bash) so the kernel treats it as an agent.

set -u

DEMO="${RZ_DEMO_DIR:-$HOME/rz-demo}"
SECRET="$DEMO/vault/id_rsa"
AGENT="$DEMO/claude"

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

command -v rz >/dev/null || { red "rz not found — install Ring Zero first"; exit 1; }
if ! rz status 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -q 'Kernel driver: *active'; then
  red "Kernel monitoring does not look active (rz status). Continue anyway? [y/N]"
  read -r ans; [[ "$ans" == y* ]] || exit 1
fi

# ── Setup ─────────────────────────────────────────────────────────────────────
rm -rf "$DEMO"
mkdir -p "$DEMO/vault"
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nthis-is-a-fake-demo-key\n-----END OPENSSH PRIVATE KEY-----\n' > "$SECRET"
chmod 600 "$SECRET"
cp "$(command -v bash)" "$AGENT"   # comm == "claude" → monitored as an AI agent

# Register the secret as protected. The daemon pushes both the basename and the
# file's (device, inode) identity into the kernel maps, so hardlinks and renames
# are covered, not just the name.
rz file-access add "$SECRET" block -d "demo: seventeen read paths" >/dev/null
sleep 1

bold "Secret: $SECRET"
bold "Agent:  $AGENT (bash renamed to 'claude')"
echo

# Each attempt runs inside the agent process. The agent prints OK if it managed to
# read the secret's contents and BLOCKED otherwise.
attempt() {
  local label="$1"; shift
  local out
  out=$("$AGENT" -c "$*" 2>&1)
  if grep -q 'fake-demo-key' <<<"$out"; then
    red "  [READ]    $label"
    return 1
  else
    green "  [BLOCKED] $label"
    return 0
  fi
}

blocked=0; total=0
try() { total=$((total+1)); attempt "$@" && blocked=$((blocked+1)); }

bold "17 read paths:"
try "cat"                          "cat $SECRET"
try "head"                         "head -c 200 $SECRET"
try "tail"                         "tail -n 5 $SECRET"
try "shell redirection (<)"        "cat < $SECRET"
try "bash \$(<file) builtin"       "echo \"\$(<$SECRET)\""
try "exec 3<file + read"           "exec 3<$SECRET; while read -r -u 3 l; do echo \"\$l\"; done"
try "dd"                           "dd if=$SECRET bs=4k count=1 2>/dev/null"
try "cp then cat the copy"         "cp $SECRET $DEMO/copy && cat $DEMO/copy"
try "grep"                         "grep -a . $SECRET"
try "sed"                          "sed -n p $SECRET"
try "awk"                          "awk '{print}' $SECRET"
try "base64 (decoded)"             "base64 $SECRET | base64 -d"
try "tar to stdout"                "tar -cf - -C $DEMO/vault id_rsa | tar -xOf -"
try "python3 open()"               "python3 -c 'print(open(\"$SECRET\").read())'"
try "python3 mmap"                 "python3 -c 'import mmap,os; fd=os.open(\"$SECRET\",os.O_RDONLY); print(mmap.mmap(fd,0,prot=mmap.PROT_READ)[:200].decode())'"
try "symlink then cat"             "ln -sf $SECRET $DEMO/link && cat $DEMO/link"
try "hardlink then cat"            "ln -f $SECRET $DEMO/hard && cat $DEMO/hard"

echo
if [[ $blocked -eq $total ]]; then
  green "Blocked $blocked/$total read paths."
else
  red "Blocked $blocked/$total read paths — see 'rz events' for what got through."
fi

echo
bold "Bonus: rename/delete of the protected file from the agent:"
"$AGENT" -c "mv $SECRET $DEMO/vault/renamed 2>&1" | sed 's/^/  mv: /'
"$AGENT" -c "rm -f $SECRET 2>&1"                  | sed 's/^/  rm: /'
[[ -f "$SECRET" ]] && green "  secret still in place" || red "  secret was moved or removed"

echo
echo "Recent kernel events (rz events --limit 25):"
rz events --limit 25 2>/dev/null | tail -25 || true

# ── Cleanup ───────────────────────────────────────────────────────────────────
id=$(rz file-access show 2>/dev/null | grep -F "$SECRET" | awk '{print $1}' | head -1)
[[ -n "$id" ]] && rz file-access remove "$id" >/dev/null 2>&1 || true
rm -rf "$DEMO"
