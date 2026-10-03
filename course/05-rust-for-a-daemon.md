# Chapter 5 — Rust for a daemon

> Goal: the three things that make the *daemon* code look different from a script
> — **async/await** (doing many things at once), **`unsafe` + FFI** (calling C
> and the kernel), and **shared state** (`Arc`/`Mutex`). You won't master these;
> you'll be able to read them.

A **daemon** is a long-running background program. `ringzero-daemon` never
"finishes" — it loads the eBPF, then sits in a loop reacting to events forever.
That shape drives everything below.

## 5.1 Async/await — waiting on many things without threads

The daemon must do several things "at the same time": drain kernel events from a
ring buffer, serve the local API, tail agent transcripts, run the write-scanner.
Most of the time each of these is *waiting* — for the next event, the next
request. Spawning an OS thread per task is heavy; instead Rust has **async**.

An `async fn` returns a **future** — a computation that can be paused at each
`.await` point (where it would block) so the runtime can run something else on the
same thread. The runtime here is **Tokio**.

```rust
#[tokio::main]                     // sets up the async runtime
async fn main() -> anyhow::Result<()> {
    let bpf = load_bpf()?;         // sync setup

    // spawn concurrent tasks; each runs until its next .await, then yields
    tokio::spawn(async move { drain_events(bpf).await });
    tokio::spawn(async move { serve_api().await });

    tokio::signal::ctrl_c().await?; // park here until Ctrl-C, using no CPU
    Ok(())
}
```

Mental model: `.await` = "I might wait here; let other tasks run meanwhile." It is
**not** parallelism-for-speed; it's *concurrency* so one thread can babysit many
mostly-idle jobs. That fits a daemon perfectly.

## 5.2 `unsafe` and FFI — the escape hatch to C and the kernel

Rust's guarantees hold only over *safe* Rust. But a security daemon must call
kernel/C things the compiler can't verify: get the current uid, load BPF objects,
read raw syscall results. For those you write **`unsafe`**, which unlocks a few
extra abilities (calling C functions, dereferencing raw pointers) and means "I,
the human, promise this is correct; compiler, stand down here."

```rust
// FFI: declare the C function, then call it inside `unsafe`.
let uid = unsafe { libc::geteuid() };   // "who am I running as?"
if uid != 0 {
    anyhow::bail!("the daemon must run as root to load BPF");
}
```

`libc` is a crate exposing the C standard library. The daemon uses `unsafe`
sparingly and deliberately — you'll see `unsafe { libc::geteuid() }` guarding
root-only paths, and the BPF-loading crate wrapping the kernel calls. The goal is
a *small* unsafe surface with safe Rust around it. Grep the codebase for `unsafe`
— there's not much, and each spot is a real boundary with the C/kernel world.

**FFI is also how the two halves of Ring Zero meet.** The kernel side is C
(eBPF). The daemon is Rust. They share data through BPF **maps**, and both sides
must lay out the key/value structs *identically byte-for-byte*. That agreement is
the "maps ABI" — Chapter 8.

## 5.3 Shared state — `Arc` and `Mutex`

Several async tasks need the same data (the current config, the event counters).
But remember the borrow rule: one mutator XOR many readers. Across tasks, Rust
enforces that with types:

- **`Arc<T>`** — "atomically reference-counted" shared ownership. Cloning an `Arc`
  makes another handle to the *same* value; it's freed when the last handle drops.
  This is how several tasks can share one thing.
- **`Mutex<T>`** — a lock. To touch the data you `.lock()` it; only one task holds
  the lock at a time. Combined: `Arc<Mutex<T>>` = "shared, and safely mutable."

```rust
use std::sync::{Arc, Mutex};
let config = Arc::new(Mutex::new(load_config("...")?));   // shared, lockable

let c2 = Arc::clone(&config);            // a handle for another task
tokio::spawn(async move {
    let cfg = c2.lock().unwrap();        // take the lock
    println!("default action: {}", cfg.enforcement.default_action);
});                                       // lock released when `cfg` drops
```

The compiler will *reject* sharing plain mutable data between tasks — you're
forced to wrap it. That's Rust turning "data race" from a 3am production incident
into a compile error.

## Where this lives in the repo

- **`#[tokio::main]` and the task spawns** — `agent/src/main.rs` (top of `main`).
  Read how it loads BPF, then spawns the event drain, the API server, the
  watchers, then awaits a shutdown signal.
- **`unsafe { libc::geteuid() }`** — `agent/src/ebpf_loader.rs:1221` and
  `cli/src/main.rs` (root checks). Small, deliberate.
- **BPF load as the big FFI boundary** — `agent/src/ebpf_loader.rs`: the crate
  that opens `/usr/lib/ringzero/ringzero.bpf.o` and attaches it is your Rust code
  driving the kernel.
- **`Arc`/`Mutex` shared state** — search `Arc<` and `Mutex<` in `agent/src/`.

## Exercise

1. In your `labs/03-rust-basics` project, add `tokio` (`cargo add tokio --features
   full`), make `main` `async` with `#[tokio::main]`, `tokio::spawn` two tasks
   that each print and `tokio::time::sleep(...).await`, and watch them interleave.
2. Add `let uid = unsafe { libc::geteuid() };` (`cargo add libc`) and print it.
   Run normally (your uid) and with `sudo` (0). This is the exact check the daemon
   uses to refuse to run unprivileged.
3. Read `main` in `agent/src/main.rs`. List every `tokio::spawn` — each is one of
   the "several things at once" from §5.1. You now know what they are.

---

That's Part II. You can read the Rust side. **Part III — [Chapter 6: What eBPF
is](06-what-ebpf-is.md)** — the kernel side begins.
