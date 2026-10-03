# Labs — write and run the code yourself

Every hands-on lab lives here, one folder per topic. The `rgs` VM mounts this
directory, so you edit files here (on your Mac or in the VM) and build/run them
**in the VM**, where the kernel and toolchain are.

## Get into the VM

```sh
limactl shell rgs
cd /Users/jarvis/rgs/course/labs      # this same folder, seen from inside the VM
```

That's your workspace. Everything below runs there.

## What's here

| Folder | Chapter | You build/run |
| --- | --- | --- |
| `00-setup/` | 0 | Prove Rust **and** eBPF both work on your VM |
| `03-rust-basics/` | 3–4 | A Rust program you grow as you learn the language |
| `07-trace-open/` | 7 | Your first eBPF program: watch every file open |
| `09-deny-open/` | 9 | **Your own mini-enforcer**: an LSM hook that denies an open |
| `11-loader/` | 11 | Load and attach your eBPF from Rust |

(Folders appear as you reach their chapter.)

## The golden rule of these labs

eBPF needs **root** to load, and a kernel with **BPF LSM** on. The `rgs` VM has
both. If a load fails with "permission denied" you forgot `sudo`; if it fails
with "BPF LSM" you're not on the `rgs` VM.

Start with **`00-setup/`** and run its `./check.sh`.
