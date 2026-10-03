// Lab 00 — a Rust program is just a program until it makes a syscall.
// Build:  rustc hello.rs -o hello
// Run:    ./hello
//
// This does two things: pure computation (adds numbers — no kernel needed),
// then a syscall (opens a file — the kernel MUST be asked). Run it under strace
// to see the difference:  strace -e trace=openat ./hello

use std::fs;

fn main() {
    // 1. Pure user-space work. The kernel never hears about this.
    let sum: u32 = (1..=100).sum();
    println!("1+..+100 = {sum}   (computed entirely in user space)");

    // 2. Touching the world = a syscall. read_to_string calls openat + read.
    match fs::read_to_string("/etc/hostname") {
        Ok(name) => println!("this machine is: {}   (via the openat syscall)", name.trim()),
        Err(e) => println!("couldn't read /etc/hostname: {e}"),
    }
}
