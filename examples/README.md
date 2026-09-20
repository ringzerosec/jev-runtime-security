# examples

## `boundary-demo.sh` — the one that proves the claim

An agent writes a C program, compiles it, and runs the binary. The binary calls
`open(2)` on a protected file directly: no shell, no `cat`, no tool a filter
could have matched on. The kernel refuses the open anyway.

```sh
bash examples/boundary-demo.sh
```

Needs `rz` on PATH, the daemon running with the kernel programs loaded, and a C
compiler. The script asserts its own result and exits non-zero if the file was
read.

The compile runs and the binary runs. **Exec and network connections are
recorded in this release, not refused** — only the file open is denied. A demo
that shows a blocked exec would be showing you something this release does not
do.

## `seventeen-read-paths.sh` — the same boundary, seventeen ways

Seventeen different ways to read one protected file — `cat`, `dd`, `python3`,
a symlink, a hardlink, `tar` to stdout, and so on. All seventeen are refused,
because the decision is keyed on the file, not on the command.

```sh
bash examples/seventeen-read-paths.sh
```
