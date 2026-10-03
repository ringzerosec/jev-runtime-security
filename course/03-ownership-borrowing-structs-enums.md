# Chapter 3 — Ownership, borrowing, structs, enums

> Goal: the four Rust ideas you need before any of the daemon code makes sense —
> **ownership**, **borrowing**, **structs**, **enums**. If you've written Python,
> JS, or Java, the new and strange part is ownership. We'll go slow there.
>
> Lab: `labs/03-rust-basics/` (a cargo project you'll grow through Ch 3–4).

## 3.1 Why Rust exists

C lets you touch memory directly, which is fast but lets you make catastrophic
mistakes: use a pointer after the memory is freed, free it twice, read past the
end of a buffer. Those bugs are most security holes. Garbage-collected languages
(Python, Go) avoid them by having a runtime clean up for you — but you pay with a
GC pausing your program, which you can't have inside a kernel-adjacent daemon on a
hot path.

Rust's bet: **prevent those bugs at compile time, with no garbage collector.**
The compiler tracks who is responsible for each piece of memory and refuses to
build code that could misuse it. The rules feel strict at first; they're the
price of "fast like C, safe like Python." A security product is exactly where
that trade is worth it.

## 3.2 Ownership (the one genuinely new idea)

**Every value has exactly one owner — one variable responsible for freeing it.
When the owner goes out of scope, the value is freed. Automatically. No GC.**

```rust
fn main() {
    let s = String::from("hello");   // s owns this string
    println!("{s}");
}                                    // s goes out of scope -> string freed here
```

The twist: assigning or passing a value **moves** ownership. The old variable is
no longer usable.

```rust
let a = String::from("hi");
let b = a;              // ownership MOVES from a to b
// println!("{a}");     // COMPILE ERROR: a no longer owns anything
println!("{b}");        // fine
```

This looks annoying until you see what it prevents: two variables can't both
think they own (and both try to free) the same memory. The "double free" bug is
impossible by construction.

Simple copyable values (numbers, `bool`, `char`) are **copied**, not moved —
they're cheap and have no heap memory to own:

```rust
let x = 5;
let y = x;              // x is COPIED
println!("{x} {y}");    // both fine
```

## 3.3 Borrowing (using a value without taking it)

Moving everything everywhere would be painful. So you can **borrow** a value with
`&` — a reference. Borrowing lets you look at (or modify) a value you don't own.

```rust
fn length(s: &String) -> usize {   // borrows s, doesn't take it
    s.len()
}
let name = String::from("ringzero");
let n = length(&name);             // lend name out
println!("{name} is {n} chars");   // name is still ours
```

Two rules the compiler enforces (the "borrow checker"):

1. You can have **many** shared, read-only borrows (`&T`) at once, **or**
2. exactly **one** mutable borrow (`&mut T`) — and no shared ones while it exists.

This is "many readers XOR one writer," and it's what makes data races impossible:
you can't have someone reading a value while someone else mutates it.

```rust
let mut v = vec![1, 2, 3];
let r = &v;            // read-only borrow
// v.push(4);          // ERROR: can't mutate while r borrows it
println!("{r:?}");     // r's borrow ends after last use
v.push(4);             // now fine
```

You'll hit borrow-checker errors constantly at first. They are not the compiler
being mean — each one is a real aliasing bug in a slower language.

## 3.4 Structs — grouping data

A `struct` is a named bundle of fields. Ring Zero's config is built from these.
Here's a real one from `agent/src/config.rs`:

```rust
pub struct EnforcementSection {
    pub default_action: String,           // "observe" | "alert" | "block"
    pub categories: EnforcementCategories, // a struct nested in a struct
}
```

`pub` means "visible outside this module" (Chapter 4). Fields have types. You
build one with field names and read them with a dot:

```rust
let e = EnforcementSection {
    default_action: String::from("block"),
    categories: EnforcementCategories::default(),
};
println!("{}", e.default_action);
```

The `#[derive(Debug, Clone, Serialize, Deserialize)]` line above a struct
auto-generates code: `Debug` lets you `println!("{e:?}")`, `Clone` lets you copy
it explicitly, and `Serialize/Deserialize` (from the `serde` crate) let it be
read from/written to the TOML config file. You'll meet `derive` again in Ch 4.

## 3.5 Enums — a value that is one of several shapes

An `enum` is a type whose value is exactly one of a fixed set of variants. This is
far more powerful than an enum in C — variants can carry data. Ring Zero grades a
finding's seriousness with one:

```rust
pub enum Severity {   // (from agent/src/write_scan)
    Low,
    Medium,
    High,
    Critical,
}
```

The killer feature is `match`: the compiler forces you to handle **every**
variant, so you can't forget a case.

```rust
fn should_block(s: Severity) -> bool {
    match s {
        Severity::Critical | Severity::High => true,
        Severity::Medium | Severity::Low => false,
    }   // remove one arm and it WON'T COMPILE — no silent fall-through
}
```

The most important enums in all of Rust are `Option` and `Result` — a value that
might be absent, and an operation that might fail. They're Chapter 4, because
they're how Rust handles "null" and errors without null-pointer crashes.

## Where this lives in the repo

- **Structs everywhere** — `agent/src/config.rs` is almost nothing but structs
  and enums (`DaemonConfig`, `EnforcementSection`, `EnforcementCategories`,
  `PiiAction`). Open it now that you can read the shape.
- **`Severity` enum + `match`** — `agent/src/write_scan/mod.rs` (search
  `enum Severity` and the `match` on it).
- **Ownership/borrowing in anger** — any function in `agent/src/` that takes
  `&self` or `&str`: it's borrowing, not taking ownership.

## Exercise (in `labs/03-rust-basics/`)

```sh
limactl shell rgs && cd /Users/jarvis/rgs/course/labs/03-rust-basics
cargo run
```

1. In `src/main.rs`, add a `Severity` enum and a `should_block` function like
   §3.5. Call it on each variant and print the result.
2. Trigger the borrow checker on purpose: make a `let mut v = vec![...]`, take
   `let r = &v;`, then `v.push(...)` before printing `r`. Read the error — it's
   telling you about a real aliasing hazard.
3. Add a `struct Rule { pattern: String, block: bool }`, build one, print it with
   `#[derive(Debug)]` and `{:?}`.

---

Next: **[Chapter 4 — `Result`, `Option`, errors, traits, modules](04-result-option-errors-traits.md)**.
