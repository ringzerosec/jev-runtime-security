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

## Supported versions

This is a 0.x project. Fixes land on `main` and in the next tagged release.
