# Chapter 8 — Maps: shared memory between kernel and user space

> Goal: understand **maps** — the only way an eBPF program keeps state and the
> only way it talks to user space. Rules get *into* the kernel through maps;
> events come *out* through maps. Once you get maps, the whole architecture snaps
> into place.

## 8.1 The problem maps solve

Your eBPF program is tiny, stateless, and re-runs from scratch on every event. It
can't open files, allocate memory, or keep a variable between firings. So how does
it know *which* files are blocked? And how does the daemon *tell* it?

**Maps.** A map is a kernel-managed key/value store that both sides share:

- The **kernel program** reads maps to make decisions (`is this inode blocked?`)
  and writes maps to report (`push this event`).
- The **user-space daemon** writes maps to configure (`block this inode`) and
  reads maps to observe (`drain events`).

The map lives in the kernel; both sides hold a handle to the same one.

```
   daemon (Rust)                     kernel program (eBPF)
   -------------                     ---------------------
   "block (dev=8,ino=42)"  --write-->  [ blocked_inodes ]  <--read--  "is this open's
                                                                        inode in here?"
   drain events            <--read---  [ events ringbuf ]  <--write--  "record this open"
```

## 8.2 Map types you'll meet

Each map declares a **type**, a max size, and its key/value types. Straight from
`GPL/bpf/ringzero.bpf.c`:

**A hash map — exact-match lookups.** "Is this file's identity blocked?"

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ino_key);   // (dev, ino) from Chapter 2
    __type(value, u8);             // present = blocked
} blocked_inodes SEC(".maps");
```

Lookup is O(1): the hook computes the open file's `(dev, ino)` and does one
`bpf_map_lookup_elem(&blocked_inodes, &key)`. Found → deny.

**Another hash — blocked basenames.** "Any file named `id_rsa`."

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, char[MAX_PATH_LEN]);
    __type(value, u8);
} blocked_files SEC(".maps");
```

**An LRU hash — the agent-descendant set.** "Which PIDs are inside an agent tree?"

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);   // evicts oldest when full
    __uint(max_entries, 16384);
    __type(key, u32);   // pid
    __type(value, u8);
} agent_descendants SEC(".maps");
```

`LRU` ("least recently used") means when it fills, the kernel evicts the
stalest entry instead of failing — right for an ever-changing set of live PIDs
(Chapter 12).

**A ring buffer — the event stream** (you met it in Chapter 7): kernel writes
event structs, daemon drains them.

Other types exist (arrays for config, per-CPU maps for counters), but hash, LRU,
and ringbuf carry the product.

## 8.3 The ABI — both sides must agree byte-for-byte

Here's the subtle, critical part. The kernel side is C; the daemon is Rust. When
the daemon writes a key into `blocked_inodes`, it must lay out `struct ino_key`
**exactly** as the C side reads it — same field order, same sizes, same padding.
The map is just bytes; nobody translates. If C has `{ u32 dev; u64 ino; }` and
Rust writes `{ u64 ino; u32 dev; }`, the kernel reads garbage and the rule silently
never matches.

This "both sides agree on the byte layout" is the **maps ABI**. In practice the
Rust side declares a matching `#[repr(C)]` struct (C layout) so the bytes line up.
It's the seam between the two halves of the product, and a class of bug all its
own: a rule that "doesn't work" is often an ABI mismatch, not a logic error.

## 8.4 How a rule travels, end to end

Now you can trace the whole path of `rz file-access add ~/projects/secret.txt
block`:

1. **`rz`** (CLI) sends the request to the daemon over its local socket.
2. **daemon** resolves `~` to a real path, `stat()`s it to get `(dev, ino)`,
   and writes that key into the `blocked_inodes` **map**.
3. Later, an agent opens that file. The **kernel** `file_open` hook computes the
   open file's `(dev, ino)`, does `bpf_map_lookup_elem(&blocked_inodes, ...)`,
   finds it, returns `-EACCES`.
4. The hook also reserves an `events` ringbuf slot recording the blocked open.
5. The **daemon** drains that event and logs/shows it.

Every arrow crossing the kernel/user boundary is a map. That's the architecture.

## Where this lives in the repo

- **All the maps** — top of `GPL/bpf/ringzero.bpf.c` (lines ~58–210):
  `events`, `blocked_files`, `blocked_inodes`, `blocked_dir_inodes`,
  `allowed_dir_inodes`, `agent_descendants`, `tainted_pids`, `config`.
- **Writing rules into maps (Rust side)** — `agent/src/ebpf_loader.rs`: search
  `update` / `blocked_inodes` / `block_inode_path` — the daemon populating maps
  from the rule store.
- **The ABI structs** — the Rust `#[repr(C)]` structs mirroring the C keys/values.

## Exercise

1. On the VM with the daemon running: `sudo bpftool map list | grep -i ringzero`.
   You're seeing the exact maps from §8.2, live. Pick one: `sudo bpftool map dump
   name blocked_inodes` — those bytes are your rules.
2. In `ringzero.bpf.c`, find `blocked_dir_inodes`. Why does a *directory* rule
   need its own map plus the parent-walk from Chapter 2, instead of just
   `blocked_inodes`?
3. Explain the ABI risk in your own words: what breaks if the Rust `ino_key` and
   the C `ino_key` disagree on field order?

---

That's Part III — you understand eBPF's machinery. **Part IV — [Chapter 9: The
LSM hook that denies an open](09-lsm-hook-deny-open.md)** — you write an enforcer.
