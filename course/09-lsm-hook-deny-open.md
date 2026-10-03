# Chapter 9 — The LSM hook that denies an open

> Goal: write an `lsm/file_open` program that **refuses** to open a file — a real,
> working mini-Ring-Zero. Then read the actual `ringzero_file_open` hook and
> understand its hot path, including the exact spot the ChatGPT-detection bug lived.
>
> Lab: `labs/09-deny-open/` — your own kernel enforcer. **Safe by design:** it only
> ever denies a process *you* name `victim`, so a mistake can't lock up the VM.

## 9.1 Allow or deny is just a return value

Recall from Chapter 6: an `lsm/file_open` program returns `0` to allow or a
negative errno to deny, and **the kernel obeys**. Denying an open is literally:

```c
return -EACCES;    // EACCES = 13, "permission denied" -> the open() syscall fails
```

That's the whole trick. The hard parts are the two questions *before* it: **is
this a process I should enforce against?** and **is this a file I protect?** Get
those right and enforcement is one `return`.

## 9.2 Your enforcer (the lab)

`labs/09-deny-open/deny_open.bpf.c` — read it end to end; it's the shape of the
real thing at 1/50th the size:

```c
SEC("lsm/file_open")
int BPF_PROG(deny_open, struct file *file) {
    // Q1: is this "the agent"? (here: any process named "victim")
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_agent(comm))          // a 6-char version of Ring Zero's is_ai_agent
        return 0;                 // not the agent -> allow, cheaply

    // Q2: is this the protected file? (here: basename == "topsecret.txt")
    char name[32] = {};
    struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
    bpf_probe_read_kernel_str(name, sizeof(name), BPF_CORE_READ(d, d_name.name));
    if (!name_eq(name, "topsecret.txt"))
        return 0;                 // some other file -> allow

    return -EACCES;               // the agent, opening the protected file -> DENY
}
```

New pieces:

- **`BPF_PROG(deny_open, struct file *file)`** — the macro that gives an LSM
  program its typed arguments. `file` is the file being opened.
- **`BPF_CORE_READ(file, f_path.dentry)`** — CO-RE-safe reading of kernel struct
  fields (Chapter 6). You can't just write `file->f_path.dentry` — the verifier
  needs the relocatable read so it works across kernels.
- **`bpf_probe_read_kernel_str`** — copy a kernel string (the filename) into your
  own buffer so you can inspect it safely.

## 9.3 Run it — watch a syscall get refused

```sh
cd /Users/jarvis/rgs/course/labs/09-deny-open
bash run.sh
```

`run.sh` builds and attaches your program, then runs the proof:

```
as victim (the "agent"):  reading topsecret.txt ...  Permission denied   ← your kernel said no
as a normal reader:       reading topsecret.txt ...  <the contents>       ← same file, allowed
```

Same file, same bytes on disk with normal `rw-r--r--` permissions — but a process
*named* `victim` cannot open it, and everything else can. You just enforced policy
below the program, at the syscall. Nothing the `victim` process does — bash,
python, a compiled binary — changes the answer, because the decision is in the
kernel, keyed on facts the process can't alter mid-syscall.

## 9.4 Now read the real hook

Open `GPL/bpf/ringzero.bpf.c` at **`SEC("lsm/file_open")` (line 940)**. It's your
lab program plus production concerns. The shape is identical: **Q1 who, Q2 which
file, then a verdict.** The differences that matter:

**Q1 is scoped for speed.** `file_open` fires for *every* open on the machine, so
the hot path rejects non-agents as fast as possible:

```c
u32 cur_pid = bpf_get_current_pid_tgid() >> 32;
int agent = is_ai_agent(comm) || bpf_map_lookup_elem(&agent_descendants, &cur_pid);
if (!agent) { /* cheap fallback checks, else */ return 0; }
```

A process is enforced if its `comm` is a known agent **or** its PID is in the
`agent_descendants` map (tagged at fork — Chapter 12). Everything else returns
almost immediately: that's why system-wide overhead is near-zero (the latency
answer from earlier).

**This is exactly where the ChatGPT bug lived.** `is_ai_agent(comm)` is the kernel
function you patched. The ChatGPT desktop app runs every process as `comm =
"ChatGPT"`; that string wasn't in `is_ai_agent`, so `agent` was false, so the hook
`return 0`'d — allowed — before ever checking the file. The fix was one more
comparison in `is_ai_agent`. Your lab's `is_agent()` is the same function in
miniature; change its target from `"victim"` to your own `comm` and watch
enforcement follow the name. That *is* the whole "detection is the root of trust"
lesson, and Chapter 12 is about its limits.

**Q2 is richer.** Instead of one basename, the real hook calls
`is_dentry_protected` (basename match **and** `(dev, ino)` match) and
`dentry_under_blocked_dir` (the bounded parent walk from Chapter 2) — all reading
the maps from Chapter 8. But it still ends the same way: a protected open returns
`-EACCES` and records an event.

## Where this lives in the repo

- **The hook** — `GPL/bpf/ringzero.bpf.c`, `SEC("lsm/file_open")` line 940.
- **Q1 detection** — `is_ai_agent` (line 479) — your `is_agent()`, full size.
- **Q2 protection** — `is_dentry_protected` and `dentry_under_blocked_dir` in the
  same file.
- **The deny** — search `-EACCES` in that file; every one is a refused syscall.

## Exercise (in `labs/09-deny-open/`)

1. Run `bash run.sh`. Confirm `victim` is denied and a normal reader is allowed.
2. **Reproduce the ChatGPT bug and fix.** Change `#define AGENT "victim"` to
   `"chatgpt"`, rebuild, and try `victim` again — now it's *allowed* (the name no
   longer matches), exactly the gap you hit in production. Add `chatgpt` back and
   watch it deny again. You just lived the bug.
3. Add a second protected filename (make `name_eq` accept either `"topsecret.txt"`
   or `"id_rsa"`). This is the `blocked_files` map from Chapter 8, hardcoded.
4. Read the real `is_dentry_protected`. Why does checking `(dev, ino)` in addition
   to the basename defeat the hardlink trick from Chapter 2?

---

Next: **[Chapter 10 — All the other hooks](10-all-the-other-hooks.md)** — exec,
connect, delete, rename, and the rest.
