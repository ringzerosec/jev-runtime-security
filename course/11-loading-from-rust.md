# Chapter 11 — Loading and attaching from Rust

> Goal: connect the two halves. You've written kernel programs and loaded them
> with `bpftool` (Labs 7, 9). In production, the **Rust daemon** does that loading
> — and then drains events and pushes rules. This chapter reads
> `agent/src/ebpf_loader.rs`, the seam between everything in Part II and Part IV.

## 11.1 What "loading" actually means

`bpftool prog loadall foo.o ... autoattach` did four things. A Rust loader does the
same, programmatically:

1. **Open** the compiled `.o` (`/usr/lib/ringzero/ringzero.bpf.o`) and parse its
   programs and maps.
2. **Load** — hand the bytecode to the kernel, which runs the **verifier**. This
   is where a bad program is rejected (returns an error you handle with `?`).
3. **Attach** each program to its hook (`file_open`, `inode_unlink`, …). Now they
   fire on real syscalls.
4. **Keep handles** to the maps so the daemon can read events and write rules.

In Rust this is done with a BPF library (the `libbpf`-family bindings). The
important thing for you is the *shape*, which mirrors your labs exactly.

## 11.2 The attach list

The daemon knows which program attaches to which hook from an explicit list — this
is the real code, `agent/src/ebpf_loader.rs:1240`:

```rust
let lsm_programs = [
    ("ringzero_file_open",            "file_open"),
    ("ringzero_inode_create",         "inode_create"),
    ("ringzero_inode_unlink",         "inode_unlink"),
    ("ringzero_inode_rename",         "inode_rename"),
    ("ringzero_inode_link",           "inode_link"),      // the one you added
    ("ringzero_bprm_check",           "bprm_check_security"),
    ("ringzero_socket_connect",       "socket_connect"),
    ("ringzero_socket_sendmsg",       "socket_sendmsg"),
    // ... ptrace, task_kill, sb_mount, sb_umount, file_mprotect ...
];
for (prog_name, hook_name) in &lsm_programs {
    // find the program named prog_name in the loaded object, attach it to hook_name
}
```

Left column = the C function name (the `BPF_PROG(ringzero_file_open, …)` you read
in Chapter 9). Right column = the LSM hook. When you added the ChatGPT fix you
touched the C program; had you added a *new hook*, you'd add a line here too — which
is exactly what the `inode_link` work did (kernel hook + this line).

## 11.3 The root check and the load

Before any of this, the daemon insists on root (Chapter 5's `unsafe` FFI), because
only root can load BPF. From `ebpf_loader.rs:1221`:

```rust
if unsafe { libc::geteuid() } != 0 {
    // refuse: loading BPF needs root
}
let bpf_path = std::env::var("RINGZERO_BPF_OBJECT")
    .unwrap_or_else(|_| PathBuf::from("/usr/lib/ringzero/ringzero.bpf.o"));
info!("Loading BPF object: {}", bpf_path.display());
// open + load (verifier runs here) + attach the list above
```

That `/usr/lib/ringzero/ringzero.bpf.o` is the exact file you rebuilt and `scp`'d
to the VM when you fixed the ChatGPT bug — now you know what reads it and when.

## 11.4 After loading: the two ongoing jobs

Once attached, the daemon does two things forever (the Tokio tasks from Chapter 5):

- **Drain events** from the `events` ring buffer — the "what happened" stream
  (Chapter 7) — and log/serve them.
- **Push rules** into the maps — when `rz file-access add` arrives, resolve the
  path and write `blocked_inodes` / `blocked_files` (Chapter 8).

So the loader is the hub: it owns the map handles that both the event drain and the
rule-push use. Reading `ebpf_loader.rs` top to bottom, you'll see load → attach →
hand map handles to the rest of the daemon.

## 11.5 A minimal Rust loader (optional lab)

You don't need to build this to understand it, but if you want the hands-on
version: the `libbpf-rs` crate loads an `.o` in a few lines —

```rust
use libbpf_rs::ObjectBuilder;
let mut obj = ObjectBuilder::default().open_file("deny_open.bpf.o")?.load()?;
for prog in obj.progs_iter_mut() {
    let _link = prog.attach()?;   // attach by its SEC() type
}
// ... keep _link alive; the program detaches when it drops ...
```

That's Lab 09's `.o`, loaded from Rust instead of `bpftool`. `cargo add libbpf-rs`
in a fresh project, point it at your `deny_open.bpf.o`, and you've replaced
`bpftool` with your own daemon-in-miniature. (The real loader does far more —
error handling, map wiring, pinning — but this is the seed.)

## Where this lives in the repo

- **The whole loader** — `agent/src/ebpf_loader.rs` (2040 lines). Key spots:
  the root check (~1221), the BPF object path (~1227), the `lsm_programs` list
  (1240), the attach loop (1266).
- **`expand_tilde`** (~553) — the rule-resolution you debugged, called before
  writing paths into maps.
- **The event drain + rule push** — follow the map handles out of `ebpf_loader`
  into `agent/src/main.rs`.

## Exercise

1. In `ebpf_loader.rs`, read the `lsm_programs` list and cross-check every entry
   against the `SEC("lsm/…")` lines in `ringzero.bpf.c`. They must correspond —
   find the pair for the hook you're most curious about.
2. Why does the daemon refuse to run if `geteuid() != 0`? What would fail later if
   it didn't? (Chapter 5 + this chapter.)
3. (Optional, hands-on) Make the §11.5 loader in a new cargo project and load your
   Lab 09 `deny_open.bpf.o` from Rust. Confirm `victim` is still denied — now with
   *your* loader, not bpftool.

---

That's Part IV. You can read the kernel enforcement and how Rust drives it.
**Part V — [Chapter 12: Knowing who the agent is](12-knowing-who-the-agent-is.md)**
— what makes this *agent* security, not just file permissions.
