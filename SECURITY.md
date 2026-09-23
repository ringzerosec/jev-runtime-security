# Security policy

## Reporting a vulnerability

Email **security@ringzerosecurity.com**. Please do not open a public issue for
a vulnerability, and please do not demonstrate one in an issue, a pull request
or a discussion.

GitHub private vulnerability reporting is enabled on this repository, so you
can also use **Security → Report a vulnerability** if you prefer to keep
everything on GitHub.

We will acknowledge your report, tell you whether we can reproduce it, and keep
you updated while we work on it. We will credit you when the fix ships unless
you would rather we did not.

## What we especially want to hear about

**Bypasses.** This project makes one specific claim: an agent running as your
developer cannot get at a protected file, and cannot turn enforcement off. If
you can break either half of that, we want to know before your audience does.

That includes:

- Reading, writing, deleting or renaming a protected file from an agent-tagged
  process tree, by any route.
- Disabling enforcement, changing policy, or stopping the service from an
  unprivileged process, including anything reachable through the local API, the
  IPC socket, the hook path, or the on-disk config and policy store.
- Escaping the agent process tree so a spawned process is no longer treated as
  part of the session.
- Getting a secret out of a trace record, a webhook delivery or the review
  queue, where redaction should have removed it.

## What is already known, and is not a vulnerability

These are documented limits of this release, not findings:

- **Exec and network connections are recorded, not refused.** Running a program
  or opening a connection is expected to succeed.
- **A privileged human operator can stop the service.** It is a normal Linux
  service. The stop is logged. We do not claim it is unkillable.
- **Raw-disk reads, snapshot-style reads and hostname-level egress** are
  outside v1 kernel scope.
- **The userspace checks can be bypassed.** They label intent; they do not
  enforce. That is why the kernel layer exists.
- **Kernels before 6.4** fail to load the eBPF object, and the agent then runs
  in a degraded mode that refuses nothing. It says so at startup.

## Known bypasses of the kernel layer

Published deliberately. A security tool that names its own limits is worth more
than one that waits for someone else to find them, and an operator who knows the
edges can decide whether they matter.

**Process-name matching is the root of trust, and it is weak.** An agent is
identified by its `comm`, which is 16 bytes and which the process controls.
`prctl(PR_SET_NAME)`, or simply copying the binary to another name, removes a
process and everything it spawns from monitoring entirely. Everything else here
rests on that identification. It is a heuristic, not an identity, and nothing in
this project should be read as claiming otherwise.

**A process can evict itself from tracking.** `agent_descendants` is an LRU
bounded at 16384. A process that forks enough children can push its own entry
out, after which its opens are no longer checked.

**Three ways to reach a file without a `file_open` hook at all**, because the
hook only fires on an open:

- An already-open file descriptor passed over a unix socket by another process.
- `process_vm_readv`, which reads another process's memory directly.
- `O_PATH`, which skips the hook.

**The taint map is a plain hash with no eviction.** `tainted_pids` stops
accepting entries at 10000. Insert failures are counted and surfaced, but a
machine past that point stops taking new taint.

**Directory blocks are bounded at 12 levels.** This one now fails CLOSED: a path
deeper than the walk can prove is treated as blocked rather than allowed. Before
that it failed open, and a file thirteen directories under a blocked root was
not blocked.

**Enforcement posture is recorded, not enforced.** `rz enforcement
set-default/set-category` writes a posture that nothing in the event pipeline
reads today. Setting it to `block` blocks nothing. File-access rules are the
only setting the kernel applies. The CLI and the UI say so at the point of use.

**Exec and network connect are observe-only** unless the separately-gated
`[scanner.write_scan] enforce` or `[egress] enforce` are turned on, and both are
off by default.

## Supported versions

This is a 0.x project. Fixes land on `main` and in the next tagged release.
