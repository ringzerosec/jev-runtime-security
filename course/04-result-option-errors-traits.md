# Chapter 4 — `Result`, `Option`, errors, traits, modules

> Goal: how Rust says "might be missing" and "might fail" without null-pointer
> crashes, and how code is organized into traits and modules. After this you can
> read most of `agent/src/` and `cli/src/`.

## 4.1 `Option<T>` — there is no null

Rust has no `null`. A value that might be absent has type `Option<T>`, an enum
with two variants:

```rust
enum Option<T> {   // built into the language
    Some(T),       // present, holds a T
    None,          // absent
}
```

Because "absent" is a *different type* from "present," you can't accidentally use
a missing value as if it were there — the compiler makes you handle `None`. This
is how Rust kills the billion-dollar null-pointer mistake.

```rust
fn find_rule(rules: &[Rule], name: &str) -> Option<&Rule> {
    for r in rules {
        if r.pattern == name {
            return Some(r);
        }
    }
    None
}

match find_rule(&rules, "id_rsa") {
    Some(r) => println!("blocked: {}", r.pattern),
    None    => println!("no rule for that"),
}
```

## 4.2 `Result<T, E>` — operations that can fail

Anything that talks to the world can fail: a file might not exist, config might be
malformed. Rust represents "success or error" as `Result`:

```rust
enum Result<T, E> {   // built in
    Ok(T),            // success, holds the value
    Err(E),           // failure, holds an error
}
```

Reading a file returns `Result<String, io::Error>`. You must acknowledge the
error path — you can't silently ignore it:

```rust
use std::fs;
match fs::read_to_string("/etc/ringzero/config.toml") {
    Ok(text) => println!("read {} bytes", text.len()),
    Err(e)   => eprintln!("couldn't read config: {e}"),
}
```

### The `?` operator — the everyday way to handle errors

Writing `match` on every fallible call is noise. The `?` operator means "if this
is `Err`, return that error from my function; otherwise unwrap the `Ok` value."

```rust
fn load_config(path: &str) -> Result<Config, anyhow::Error> {
    let text = fs::read_to_string(path)?;       // ? -> on error, return it
    let cfg: Config = toml::from_str(&text)?;   // ? -> same
    Ok(cfg)
}
```

That reads like the happy path, but every `?` is a fully-checked error exit. This
pattern is *everywhere* in the daemon. `anyhow::Error` (from the `anyhow` crate)
is a catch-all error type; libraries often define their own instead.

`.unwrap()` and `.expect("msg")` say "I'm certain this is `Ok`/`Some`; if not,
crash." Fine in a lab or a test, risky in the daemon's hot path — you'll see the
codebase prefer `?` and real handling.

## 4.3 Traits — shared behavior

A **trait** is a set of methods a type promises to provide — like an interface.
If a type implements `Display`, it knows how to print itself:

```rust
use std::fmt;
impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        };
        write!(f, "{s}")
    }
}
// now: println!("{}", Severity::High)  ->  HIGH
```

You've already used traits without writing them: `#[derive(Debug, Clone,
Serialize, Deserialize)]` asks the compiler to *implement those traits for you*.
`Serialize`/`Deserialize` (the `serde` crate) are why a `struct` can be read from
TOML — the trait defines "how to turn me into/from data," and `serde` generates
it. This is the backbone of `config.rs`.

Traits also enable generics: a function can accept "any type that implements
`Display`" (`fn show<T: Display>(x: T)`), giving you C++-template-like reuse with
compile-time checks.

## 4.4 Modules and crates — how a big program is organized

- A **crate** is a compilation unit / package. Ring Zero is a **workspace** of
  several crates: `agent` (the daemon), `cli` (`rz`), `checks`, `ringzero-app`
  (the viewer). See the top-level `Cargo.toml`.
- A **module** (`mod`) is a namespace inside a crate. `agent/src/write_scan/` is
  the `write_scan` module; `mod.rs` is its entry file. `pub` marks what's visible
  outside it. `use path::to::Thing;` brings a name into scope.

So `agent/src/config.rs` defines `pub struct DaemonConfig`, and `main.rs` does
`use crate::config::DaemonConfig;` to use it. `crate::` means "from the root of
this crate."

## Where this lives in the repo

- **`Result` + `?` everywhere** — open `agent/src/ebpf_loader.rs` and look at
  `load_bpf`; nearly every line that can fail ends in `?` and returns a
  `Result`/`anyhow::Result`.
- **`Option`** — lookups like "is there a rule for this?" return `Option`.
- **Traits via derive** — every struct in `config.rs` derives `Serialize,
  Deserialize`; that's the trait system reading your TOML.
- **Workspace of crates** — the root `Cargo.toml` lists the members; each has its
  own `src/`.

## Exercise (in `labs/03-rust-basics/`)

1. Add `find_rule` (§4.1) returning `Option<&Rule>`; build a small `Vec<Rule>`
   and look one up; handle `Some`/`None`.
2. Write a function `read_first_line(path: &str) -> Result<String, std::io::Error>`
   using `fs::read_to_string(path)?` and returning the first line. Call it on
   `/etc/hostname` (works) and `/nope` (error) and print both outcomes.
3. Implement `Display` for `Severity` (§4.3) and print `Severity::Critical` with
   `{}` instead of `{:?}`. Notice the difference between `Debug` and `Display`.

---

Next: **[Chapter 5 — Rust for a daemon](05-rust-for-a-daemon.md)** — async, `unsafe`,
and calling C.
