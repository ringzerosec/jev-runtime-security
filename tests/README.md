# tests

Unit tests live next to the code they cover and run with `cargo test
--workspace`: 184 in the agent, 7 in the checks crate at the time of writing.

This directory holds cross-cutting tests that need a loaded kernel program and
therefore cannot run in a plain `cargo test` — they need root, a BPF-LSM
kernel, and a machine you are willing to have an agent poke at.

**Planned — not in this release.** The end-to-end behaviour is covered today by
`examples/boundary-demo.sh`, which is runnable and asserts its own result.
