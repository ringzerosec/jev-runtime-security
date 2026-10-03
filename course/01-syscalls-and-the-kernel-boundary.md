# Chapter 1 — Syscalls and the kernel boundary

> Goal: understand what a *system call* is, why there are two worlds (user space
> and kernel space), and why the syscall boundary is the one place an AI agent
> can't talk its way past. Everything Ring Zero does hangs on this one idea.

## 1.1 A program can't actually do anything

Here's a fact that surprises people: a normal program cannot touch a file, the
network, the screen, or another process **on its own**. It can add numbers and
move bytes around in its own memory — that's it. The moment it wants to *affect
the world* — read a file, open a socket, start another program — it has to **ask
the kernel to do it on its behalf**.

That request is a **system call** (syscall). It is the only door out of a
program's private sandbox.

Why is it built this way? Because your machine runs dozens of programs that don't
trust each other, sharing one disk, one network card, one CPU. If every program
could poke hardware directly, any one of them could read another's memory, wipe
the disk, or hog the CPU forever. So the CPU itself runs in two privilege levels:

- **User space** (also "userland"): where your programs run. Restricted. Can't
  touch hardware or other programs' memory.
- **Kernel space**: where the operating system kernel runs. Privileged. It owns
  the hardware and arbitrates between everyone.

A syscall is the controlled gateway between them. The program puts a request
number and arguments in CPU registers, executes a special instruction
(`syscall` on x86-64), and the CPU **switches into kernel space**, jumps to a
fixed kernel entry point, does the work if allowed, and switches back with a
result. The program was frozen the whole time the kernel ran.

```
   user space                          kernel space
   ----------                          ------------
   your program
     open("/etc/passwd", O_RDONLY)
             |   syscall instruction
             v   ── CPU privilege switch ──►  sys_openat()
                                                • check permissions
                                                • find the file
                                                • hand back a number (fd)
             ◄── switch back ──────────────
     fd = 3
```

The key insight for this whole course: **the kernel is not optional and cannot be
skipped.** No matter what language the program is in, no matter how it's written,
if it wants to open a file it *must* make that syscall. That is the choke point.

## 1.2 The syscalls that matter to us

There are a few hundred syscalls. You only need a handful to understand Ring
Zero. These are the "verbs" an AI agent uses to affect your machine:

| Syscall (roughly) | What the program is trying to do | Ring Zero cares because |
| --- | --- | --- |
| `openat` / `open` | open a file to read or write | reading a secret, a credential |
| `execve` | replace itself with another program | running a downloaded binary, a shell |
| `connect` | open a network connection | sending your data somewhere |
| `unlink` | delete a file | deleting the database |
| `rename` | move/rename a file | moving a protected file out of the way |
| `link` | make a hardlink (a 2nd name for a file) | sneaking a second name to dodge a rule |
| `ptrace` | inspect/control another process | reading another process's memory |

Notice these are *ordinary, legitimate* operations. Nothing here is malware. An
agent "reading a file" and an attacker "reading a file" make the identical
syscall. That's exactly why you can't tell them apart by looking for "bad"
programs — the interesting question isn't *what* is running, it's *who asked* and
*for what*. Hold that thought; it's the whole product.

### Try it — watch the syscalls a program makes

On the lab VM (`limactl shell rgs`), `strace` prints every syscall a program
makes:

```sh
strace -f -e trace=openat,execve,connect cat /etc/hostname
```

You'll see the `execve` that started `cat`, the `openat` that opened
`/etc/hostname`, and the read. That `openat` line is *precisely* the moment Ring
Zero gets to say yes or no. Everything before it — how `cat` was written, what
language, what it "intended" — is invisible and irrelevant at the boundary. Only
the syscall crosses.

## 1.3 Why the boundary is the honest place

An AI coding agent is a program that decides what to do based on text it reads: a
prompt, a web page, a README, a tool result. You can write rules *into* that text
— "never touch production" — but those rules are just more text the model weighs,
and other text can outweigh them. A guardrail written where the agent can read it
is a suggestion.

Now look at where the syscall boundary sits:

```
  the agent's reasoning        ← text, promises, "guardrails" (persuadable)
  the code it writes/runs      ← bash, python, a compiled binary (arbitrary)
  ────────── syscall ──────────  ← the one line everything must cross
  the kernel                    ← decides: allow or deny  (not persuadable)
```

Below the syscall, there is no prompt to inject, no README to plant, no
instruction to follow. There is a request number and some arguments, and a rule
that a **human with root** wrote. The agent's cleverness ends at that line. A
decision made *here* is made below everything the agent can influence.

That is the thesis of Ring Zero in one sentence: **move the decision below the
agent, to the syscall, where nothing it reads can change the answer.** The rest
of this book is how that's actually built.

## 1.4 How you hook the boundary (the preview)

Historically, enforcing rules at syscalls meant writing kernel modules (dangerous
— a bug crashes the machine) or using frameworks like SELinux/AppArmor (powerful
but coarse and not agent-aware). Ring Zero uses a newer mechanism: **eBPF**,
small programs the kernel will run *at* specific points — including a family of
security hooks called **LSM** (Linux Security Modules). You attach a tiny program
to "the moment a file is opened," and the kernel asks *your* program "allow this?"
before completing the syscall. Your program answers `0` (allow) or a negative
error like `-EACCES` (deny), and the kernel obeys.

You'll build one of those yourself in Part III. For now, just know the shape:

```c
// pseudo-preview of what you'll write in Chapter 9
SEC("lsm/file_open")               // "run me when any file is opened"
int on_file_open(struct file *f) {
    if (is_the_agent() && is_protected(f))
        return -EACCES;            // deny — the open() fails
    return 0;                       // allow
}
```

The real one is in this repo, and it's not much bigger.

## Where this lives in the repo

- **The hooks themselves** — `GPL/bpf/ringzero.bpf.c`. Open it and search for
  `SEC("lsm/`. You'll find one hook per boundary we care about:
  - `SEC("lsm/file_open")` (line 940) — the open() verdict, our main event.
  - `SEC("lsm/inode_unlink")` (1234), `inode_rename` (1272), `inode_link` (1320)
    — delete / rename / hardlink.
  - `SEC("lsm/bprm_check_security")` (1349) — `execve`, running a program.
  - `SEC("lsm/socket_connect")` (1589) — outbound network.
  - `SEC("lsm/ptrace_access_check")` (2013), `sb_mount` (2120), `task_kill`
    (2054) — the rest of the verbs from the table above.
- **The premise in the product's own words** — `README.md`, the sentence
  "enforced in the kernel, at the system call — below the agent."

Every one of those `SEC("lsm/…")` lines is a syscall boundary we decided to stand
on. By the end of Part IV you'll read all of them comfortably.

## Exercise

1. On the VM, run `strace -f -e trace=openat ls` and find the `openat` calls.
   Which files did `ls` open just to list a directory? (You'll see it opens
   shared libraries too — a hint that "one command" is many syscalls.)
2. In `GPL/bpf/ringzero.bpf.c`, count how many distinct `SEC("lsm/…")` hooks
   exist (`grep -c 'SEC("lsm/' GPL/bpf/ringzero.bpf.c`). Each is a boundary. Which
   syscall from the table in §1.2 does each one correspond to? Write the list —
   you're now reading the product's threat model.
3. Reasoning question: an agent runs `python3 evil.py`, and `evil.py` opens a
   protected file. How many syscalls crossed the boundary — and which single one
   is where the file actually gets denied? (Answer in Chapter 9, but guess now.)

---

Next: **[Chapter 2 — Processes, files, inodes, dentries](02-processes-files-inodes.md)**,
where "who asked?" and "which file?" get precise — and you'll see why a file's
name is the *least* reliable way to identify it.
