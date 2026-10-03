# Chapter 7 — Your first program: observe an event

> Goal: write and run a real eBPF program that fires on **every file open on the
> machine** and prints the filename. Observing before enforcing is the right order
> — you'll see the exact event Ring Zero later decides on.
>
> Lab: `labs/07-trace-open/` — build it, load it, watch it.

## 7.1 The smallest useful pattern: `bpf_printk`

The easiest way to see an eBPF program work is to have it print. `bpf_printk(...)`
writes to the kernel's trace pipe, which you read from user space with
`cat /sys/kernel/debug/tracing/trace_pipe`. It's the eBPF `println!` — great for
learning, not for production (Ring Zero uses ring buffers instead, §7.3).

Here's the whole program (`labs/07-trace-open/trace_open.bpf.c`):

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
char LICENSE[] SEC("license") = "GPL";

// Fire whenever any process enters the openat() syscall.
SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));   // who is opening (the `comm`)
    const char *filename = (const char *)ctx->args[1]; // 2nd arg of openat = path
    bpf_printk("open by %s: %s", comm, filename);
    return 0;
}
```

Three ideas you'll reuse forever:

- **`SEC("tracepoint/syscalls/sys_enter_openat")`** — attach at the entry of the
  `openat` syscall. A *tracepoint* is an observation point; unlike an `lsm/` hook,
  its return value doesn't allow/deny anything. We're only watching.
- **`bpf_get_current_comm`** — a BPF helper that copies the current process's
  `comm` (that 16-byte name from Chapter 2). This is the *same* helper the real
  enforcement hook uses to recognize an agent.
- **Reading arguments** — the tracepoint context gives the syscall's arguments;
  `args[1]` is `openat`'s path.

## 7.2 Run it (the full eBPF loop, by hand)

```sh
cd /Users/jarvis/rgs/course/labs/07-trace-open
bash run.sh        # compiles, loads+attaches, then tails the trace
```

`run.sh` does what a loader does: generate `vmlinux.h`, `clang -target bpf` to an
`.o`, `sudo bpftool prog loadall ... autoattach` to verify+attach, then
`sudo cat .../trace_pipe`. In another terminal, `cat /etc/hostname` or run
anything — watch your program report every open, with the opener's `comm`. Ctrl-C,
then `run.sh` cleans up the pin.

You just ran the complete eBPF pipeline: **C → bytecode → verifier → attached →
firing on real syscalls.** Chapters 8–9 change *what the program does* at that
firing; the pipeline stays the same.

## 7.3 How Ring Zero really ships events: the ring buffer

`bpf_printk` is for humans. To send **structured** events to its daemon at high
rate, Ring Zero uses a **ring buffer** map — a chunk of memory the kernel writes
event structs into and user space drains. From `GPL/bpf/ringzero.bpf.c`:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);   // 256 KB buffer
} events SEC(".maps");
```

The kernel side reserves a slot, fills an `event` struct (pid, comm, path, whether
it was blocked), and submits it:

```c
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (e) {
    e->type = EVENT_FILE_OPEN;
    fill_process_info(e);          // pid, comm, ...
    bpf_ringbuf_submit(e, 0);      // hand it to user space
}
```

The Rust daemon opens the other end and reads those structs in a loop (Chapter
11). This is the "observe" half of the product — the same events that, joined with
the verdict, become the trace in Chapter 15.

## Where this lives in the repo

- **The `events` ring buffer** — `GPL/bpf/ringzero.bpf.c` (~line 58), the very
  first map defined.
- **`fill_process_info` / `bpf_ringbuf_reserve` / `submit`** — search those in the
  same file; they appear in nearly every hook to record what happened.
- **`bpf_get_current_comm`** — search it: the exact helper from your lab, used in
  `is_monitored_current` and the hooks.

## Exercise (in `labs/07-trace-open/`)

1. Run `bash run.sh`. In another VM shell, run `ls`, `cat /etc/hostname`, `python3
   -c "open('/etc/hosts')"`. Find each in the trace, with its `comm`.
2. Change the `bpf_printk` to also print the pid: add
   `bpf_get_current_pid_tgid() >> 32` and a `%d`. Rebuild, rerun. (You just added a
   field to a kernel program.)
3. Conceptual: why can't a tracepoint like this *block* the open, while an
   `lsm/file_open` program can? (Answer: Chapter 9 — it's about *where* the hook
   sits and whether the kernel consults its return value.)

---

Next: **[Chapter 8 — Maps: shared memory between kernel and user space](08-maps.md)**.
