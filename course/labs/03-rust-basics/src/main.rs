// Lab 03 — Rust basics you'll grow through Chapters 3 and 4.
// Run:  cargo run
//
// Read top to bottom, then do the exercises at the end of each chapter by
// editing this file and re-running `cargo run`. Compile errors are lessons —
// read them; Rust's are unusually good.

// ── A struct: a named bundle of fields (Ch 3.4) ──────────────────────────────
#[derive(Debug, Clone)] // auto-generates Debug (for {:?}) and Clone
struct Rule {
    pattern: String,
    block: bool,
}

// ── An enum: one of a fixed set of shapes (Ch 3.5) ───────────────────────────
#[derive(Debug)]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

// `match` must cover every variant, or it won't compile.
fn should_block(s: &Severity) -> bool {
    match s {
        Severity::Critical | Severity::High => true,
        Severity::Medium | Severity::Low => false,
    }
}

fn main() {
    // Ownership & move (Ch 3.2)
    let a = String::from("hello");
    let b = a; // ownership MOVES to b; using `a` now would not compile
    println!("moved string is now owned by b: {b}");

    // Borrowing (Ch 3.3): lend a value without giving it away
    let name = String::from("ringzero");
    println!("'{name}' is {} chars", length(&name));
    println!("we still own name: {name}");

    // Struct
    let r = Rule { pattern: String::from("id_rsa"), block: true };
    println!("rule: {r:?}");

    // Enum + match
    for s in [Severity::Low, Severity::High, Severity::Critical] {
        println!("{s:?} -> block? {}", should_block(&s));
    }

    // ── Ch 4 preview: Option and Result (uncomment once you reach Chapter 4) ──
    // let found: Option<&Rule> = Some(&r);
    // match found { Some(x) => println!("found {x:?}"), None => println!("none") }
}

// Borrows `s` (does not take ownership). `&str` is a borrowed string slice.
fn length(s: &str) -> usize {
    s.len()
}
