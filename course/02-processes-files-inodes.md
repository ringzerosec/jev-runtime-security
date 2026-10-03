# Chapter 2 — Processes, files, inodes, dentries

> Goal: make "who asked?" and "which file?" precise. You'll learn what identifies
> a *process* and what identifies a *file* — and why a file's **name** is the
> least reliable of its identities. This is why a rename, a hardlink, or a symlink
> can't dodge a Ring Zero rule.

## 2.1 A process, precisely

When the kernel runs a program it creates a **process**. The things that identify
it, which you'll see all through the code:

- **PID** (process id) — a number, unique while the process lives. Reused later.
- **PPID** — the PID of its parent (the process that started it). Every process
  has a parent, forming a tree back to `init`/systemd.
- **`comm`** — a short name the kernel keeps for the process, **max 16 bytes**
  (15 chars + a null). It's usually the program's filename. This tiny field is
  the root of how Ring Zero recognizes an agent — and, as you saw with the
  ChatGPT desktop app, its biggest weakness (Chapter 12).
- **uid** — which user the process runs as. Your agent runs as *you*.

A process is created by **`fork`** (make a copy of the current process) usually
followed by **`execve`** (replace the copy's program with a new one). So
`bash` running `python3 evil.py` is: bash forks, the child execs `python3`. The
child's parent is bash; bash's parent is your terminal; and so on. That chain is
the **process tree**, and "is this process descended from an agent?" is a walk up
that tree (Chapter 12).

### Try it

```sh
echo $$                        # the PID of your shell
ps -o pid,ppid,comm -p $$      # its PID, parent, and comm
cat /proc/$$/status | head     # the kernel's own view: Name, Pid, PPid, Uid...
```

`/proc/<pid>/` is the kernel exposing process facts as fake files. Ring Zero's
userspace reads `/proc` to resolve who a caller is (Chapter 12); the kernel side
reads the same facts directly from in-kernel structures.

## 2.2 A file has three different identities

Say a rule is "block `/home/u/projects/secret.txt`". What does "that file" even
mean? There are three answers, and only one is trustworthy.

**1. The path / name** — `"/home/u/projects/secret.txt"`. Human-friendly and
completely unreliable as an identity, because:
- `rename()` changes it in one syscall.
- a **symlink** is a second path pointing at it.
- a **hardlink** is a second *real name* for the exact same file — no "original."
- `~/projects` isn't even a real path; the shell expands `~`, the kernel never
  sees a tilde (a bug you fixed once — the rule `~/projects/*` had to be expanded
  to `/home/u/projects` before the kernel could use it).

**2. The inode** — every file on a disk has an **inode**, a number that is the
file's true identity on that filesystem: its data, permissions, size, link count.
Names *point to* an inode. A hardlink is literally a second name pointing at the
same inode. So if you identify a file by its inode, a rename or a new hardlink
lands on the **same** inode — the same decision.

But an inode number is only unique *within one filesystem*. Two different disks
can both have inode 12345. So the real identity is:

**3. `(device, inode)`** — the disk (device) plus the inode number. Globally
unambiguous. **This is how Ring Zero identifies a protected file.** In the kernel
that's a small struct used as a map key:

```c
struct ino_key { u32 dev; u64 ino; };   // (device, inode) — the true identity
```

Because the rule is keyed on `(dev, ino)`, none of the name tricks work: rename
it, hardlink it, symlink it — the bytes still live at one `(dev, ino)`, and that's
what the hook checks.

Ring Zero actually keeps **both**: a set of blocked *basenames* (for a rule like
"any file named `id_rsa`") *and* a set of blocked `(dev, ino)` (for "this exact
file"). You'll see both maps in Chapter 8.

## 2.3 Dentries — how the kernel walks a path

Inside the kernel a path like `/home/u/projects/secret.txt` is a chain of
**dentries** ("directory entries"). Each dentry links a name to an inode and
points to its parent dentry. `secret.txt`'s dentry → `projects`' dentry → `u`'s →
`home`'s → `/`.

This matters for **directory rules**. "Block everything under `~/projects`" can't
be a single inode — files get created there later. So the hook, given the file
being opened, **walks up the parent dentries** asking at each step "is *this*
directory the blocked one?" That walk is bounded (you don't loop forever) — in
this repo, up to 32 levels (`MAX_DIR_WALK`), and if it hits the limit it fails
*open* (allows), because denying a file just for being deeply nested would break
normal tools. (You fixed exactly this: the walk used to be 12 levels and denied
on truncation, which blocked a node agent's file 13 directories deep.)

## Where this lives in the repo

- **`(device, inode)` identity** — `GPL/bpf/ringzero.bpf.c`: `struct ino_key`,
  and the `blocked_inodes` map (line ~91). The function `is_dentry_protected`
  checks basename **and** `(dev, ino)`.
- **The directory walk** — search `dentry_under_blocked_dir` and `MAX_DIR_WALK`
  in the same file. Read how it climbs `d_parent` and what it returns at the
  limit.
- **Tilde/path resolution in userspace** — `agent/src/ebpf_loader.rs`,
  `expand_tilde` (~line 553): the daemon turns `~/projects/*` into a real
  `/home/<user>/projects` before pushing it to the kernel, because the kernel
  only understands real `(dev, ino)`.
- **Reading process identity from `/proc`** — `agent/src/common/agent_detect.rs`.

## Exercise

1. `ls -li secret.txt` prints the inode number (first column). `ln secret.txt
   copy.txt` (hardlink), then `ls -li` both — same inode. `cp` instead — different
   inode. This is *why* the rule keys on the inode, not the name.
2. In `ringzero.bpf.c`, find `struct ino_key`. Why is `dev` needed and not just
   `ino`? (Hint: two USB drives.)
3. You block `~/projects`. An agent runs `ln ~/projects/secret.txt /tmp/s` then
   reads `/tmp/s`. Walk through: does the `(dev, ino)` of `/tmp/s` match the
   protected file? (This is the hardlink case; the answer is in Chapter 9/10.)

---

Next: **[Chapter 3 — Ownership, borrowing, structs, enums](03-ownership-borrowing-structs-enums.md)** —
Rust starts here.
