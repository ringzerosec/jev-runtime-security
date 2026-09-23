# Contributing

Thanks for looking at the code. This is an early 0.x project and review is
welcome — particularly review that tries to break the enforcement claim.

## Developer Certificate of Origin

Every commit must be signed off. Add `-s` to your commit:

```sh
git commit -s -m "fix: …"
```

That appends `Signed-off-by: Your Name <you@example.com>`, which certifies you
wrote the patch or have the right to submit it under this project's licenses,
per the [Developer Certificate of Origin](https://developercertificate.org/).
We do not require a CLA for userspace code.

## Building both layers

```sh
# Kernel side (GPL-2.0) — needs clang, bpftool, libbpf-dev, and BTF
make -C GPL/bpf all

# Userspace (Apache-2.0)
cargo build --release
cargo test --workspace
cargo fmt --all -- --check
```

`vmlinux.h` is generated from the running kernel's BTF at build time. It is not
committed.

## Before you open a pull request

- `cargo fmt --all -- --check` and `cargo test --workspace` pass.
- New behaviour has a test next to the code.
- **Claims in docs match what the code does.** If you change what is enforced,
  change `README.md`, `GPL/README.md` and `trace/README.md` in the same pull
  request. Saying we block something we only record is the one review comment
  that will always block a merge.

## Kernel-side code (`GPL/`)

Changes under `GPL/` are accepted as **issues and suggestions, not pull
requests**, until a CLA process exists. Open an issue describing the change; a
diff attached to the issue is fine.

The bar is higher here for a straightforward reason: a mistake in an LSM hook
does not produce a failing test, it produces a machine that will not boot, or
one that silently stops enforcing. Anything touching a hook's return path needs
a reasoned argument for why it cannot deny something it should not, and cannot
allow something it should.

The licence split is load-bearing. Do not move BPF source out of `GPL/`, and do
not embed BPF source into the userspace crates: the kernel will refuse to load
a BPF LSM program that is not GPL-declared, and the Apache side must stay free
of GPL source.

## Unsafe code

`unsafe` needs a comment saying what invariant makes it sound. Most of the
existing uses are raw `libc` calls for process checks; keep them that narrow.

## Security issues

Do not open an issue. Email **security@ringzerosecurity.com** — see
[SECURITY.md](SECURITY.md).

## Code of conduct

Participating here means following the [code of conduct](CODE_OF_CONDUCT.md).
