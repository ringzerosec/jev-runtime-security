# Chapter 10 — All the other hooks

> Goal: now that you can read one LSM hook, read the rest. Each guards a different
> syscall from Chapter 1's table. The pattern never changes — *who, what,
> verdict* — so this chapter is mostly a guided tour of `GPL/bpf/ringzero.bpf.c`.

## 10.1 The map of hooks

Run `grep -n 'SEC("lsm/' GPL/bpf/ringzero.bpf.c`. Each line is a boundary:

| Hook (`SEC("lsm/…")`) | Syscall it guards | What an agent is trying to do |
| --- | --- | --- |
| `file_open` (940) | `openat` | read a protected file |
| `inode_create` (1197) | create a file | plant a file in a protected dir |
| `inode_unlink` (1234) | `unlink` | **delete** a protected file |
| `inode_rename` (1272) | `rename` | move a protected file away |
| `inode_link` (1320) | `link` | **hardlink** a protected file (the dodge) |
| `bprm_check_security` (1349) | `execve` | run a program |
| `socket_connect` (1589) | `connect` | open an outbound connection |
| `socket_sendmsg` (1764) | send | send data out |
| `ptrace_access_check` (2013) | `ptrace` | read another process's memory |
| `task_kill` (2054) | `kill` | signal another process |
| `sb_mount` / `sb_umount` (2120/2154) | `mount` | mount/unmount a filesystem |
| `file_mprotect` (2218) | `mprotect` | make memory executable |

Two important truths about this table, both from the product's honesty:

- **File hooks refuse; most others only record.** `file_open`, `inode_*` return
  `-EACCES` to *deny*. In this release `execve` and network hooks mostly
  **record** (emit an event, return allow) — you'll see them fill an event and
  `return 0`. That's the "recorded, not refused" line in the README. The
  machinery to deny is identical; the policy choice is not to, yet.
- **Delete, rename, hardlink exist because a file is `(dev, ino)`, not a name**
  (Chapter 2). If you only guarded `file_open`, an agent could `rename` the file
  out of a blocked directory, or `link` a second name to it and open *that*. So
  each of those verbs gets its own hook, all keyed on the same identity.

## 10.2 Read three of them

Open the file and read these, in order — you'll see the same three-part shape you
wrote in Lab 09.

**`inode_unlink` (1234)** — deny deleting a protected file. Same `is_ai_agent` /
`is_dentry_protected` questions; verdict `-EACCES` on a protected target. This is
"it deleted the database *and* the backups" being made impossible.

**`inode_link` (1320)** — the one you added. `link(old, new)` makes `new` a second
name for `old`. The hook checks whether **`old`** is protected: if the agent tries
to hardlink a protected file, deny — otherwise the new name would be an unguarded
door to the same `(dev, ino)`. Reading this next to Chapter 2 should now click
completely.

**`bprm_check_security` (1349)** — fires on `execve`, i.e. whenever a program is
about to run. This is where the daemon learns "an agent just launched a child" and
where `is_ai_agent(exec_name)` tags new agent processes. It's central to Chapter
12 (how the descendant set gets populated), even though it mostly records rather
than blocks.

## 10.3 The socket hooks and taint (preview)

`socket_connect` (1589) is where **egress** would be enforced: a connection from a
*tainted* agent process to an off-allowlist address returns `-EACCES`. "Tainted"
means "this process tree ingested untrusted external content" — set by the
userspace watcher in Chapter 13. So the network hook reads a map
(`tainted_pids`) that userspace writes: another kernel/user handshake through a
map. Off by default; the mechanism is here.

## Where this lives in the repo

- **Everything** — `GPL/bpf/ringzero.bpf.c`. This chapter is a reading list into
  that one file. Use the line numbers above.
- **The "recorded vs refused" policy** — compare an `inode_unlink` path (returns
  `-EACCES`) with a `socket_connect` path in the default config (records, allows).
- **The README table** "What's enforced, and what isn't" is exactly §10.1's first
  truth, stated for users.

## Exercise

1. `grep -c 'SEC("lsm/' GPL/bpf/ringzero.bpf.c` — how many boundaries? Match each
   to a syscall from Chapter 1.
2. Read `inode_link`. In one sentence, what would break if this hook didn't exist
   (use the word "hardlink")?
3. Find a hook that fills an `event` and `return 0`s without ever returning
   `-EACCES`. That's a "record, don't refuse" hook. Which syscall, and why might
   the team have chosen to observe rather than block it in v1? (Hint: false
   positives on normal dev work — see Chapter 17.)

---

Next: **[Chapter 11 — Loading and attaching from Rust](11-loading-from-rust.md)** —
how the daemon puts all this in the kernel.
