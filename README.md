# ringzero

[![build](https://github.com/ringzerosec/jev-agentic-security/actions/workflows/ci.yml/badge.svg)](https://github.com/ringzerosec/jev-agentic-security/actions/workflows/ci.yml)
[![userspace: Apache-2.0](https://img.shields.io/badge/userspace-Apache--2.0-blue)](LICENSE)
[![kernel: GPL-2.0](https://img.shields.io/badge/kernel-GPL--2.0-blue)](GPL/LICENSE)
[![platform: linux](https://img.shields.io/badge/platform-linux-lightgrey)](SUPPORT.md)

Kernel-level runtime security for AI coding agents, in two layers: checks that
score what an agent is *about to do*, and eBPF/LSM programs that decide what it
is *allowed to do*.

> **On the name.** This is Ring Zero's project. *Jev* is TypeSafe's System One
> model, which this project can call as the checks provider. Ring Zero is not
> affiliated with TypeSafe, and no TypeSafe code or model weights are bundled
> here — see [NOTICE](NOTICE).

## Two layers, one trace

**Kernel enforcement** is eBPF LSM programs. They decide, per agent, whether an
operation happens at all, and they are also the primary source of observation:
the file opens, execs and connections an agent actually made. They cannot be
talked around, because they run below the agent and below anything the agent
writes. Nothing about them depends on the agent's cooperation.

**Checks** score what an agent looks like it is doing, in userspace, off the
hot path. They label intent; they can be bypassed, like any guardrail. They
read two things on a default install:

- **syscall events** from the kernel — what happened;
- **captured terminal output** — what the agent said it was doing, read in the
  kernel below the agent, so no configuration inside the agent is involved.

The two layers are joined by one trace format keyed on `session_id`. The check
says what it looked like the agent was about to do; the kernel says what
actually happened. **That join is the point of this project.** See
`trace/README.md`.

**Agent hooks are optional and off by default.** A hook in Claude Code or Codex
adds one thing nothing else can give: the structured arguments of a tool call
*before* it runs, and therefore the chance to decline it. It is also app-layer,
bypassable, and configuration inside the thing being watched — an agent can
edit it. Installing one edits another vendor's config file, which is not
something to do quietly, so it happens only when you ask:
`RZ_INSTALL_AGENT_HOOKS=1`. Nothing in the default install depends on a hook
being there.

## The desktop app reads with one token and writes with none

`ringzero-desktop` shows sessions, the event timeline, threats, the review queue
and daemon status. Everything it **reads** uses a **read-only** API token, which
is what the installer leaves the operator, because an AI coding agent runs as
that same user and a full-scope token sitting in their home would hand the agent
the ability to turn enforcement off.

Writing does not use a token at all. **A change made in the app requires an
interactive administrator authentication.** Pressing Save runs the equivalent
`rz` command through `pkexec`: polkit prompts, the command runs as root, and the
app then re-reads the daemon's state. The polkit action ships with the desktop
package at `/usr/share/polkit-1/actions/com.ringzerosecurity.app.policy`, is
`auth_admin` rather than `yes` or `auth_admin_keep`, so it asks every time and
leaves no remembered answer for an agent to reuse. It is pinned to `/usr/bin/rz` so the person
authenticating is told what is about to change rather than being asked to approve
"running a program as root".

That prompt is the boundary. An agent running as your developer has no password
and no way to answer an authentication dialog, so it cannot make the change
non-interactively; a human at the machine can. The app can only ask for a fixed
list of commands — file-access rule add and remove, enforcement posture, review
labelling — and refuses anything else before `pkexec` is reached.

If `pkexec` is not installed, or the prompt is dismissed, the app says so, leaves
the screen as it was, and names the `sudo rz …` command to run instead. Nothing
is half-applied: a run of related changes stops at the first one that does not
go through, and the app tells you how far it got.

## THE ONE RULE

**Enforcement is deterministic. Models never decide the syscall.**

The kernel allows or denies by policy only: fixed rules, no model in the
decision path, no model call in the file-open, exec or connect hook, ever. The
syscall never waits on inference. The hook fires millions of times a day at
nanosecond-to-microsecond scale; a model is hundreds of microseconds to
milliseconds, thousands of times too slow — and a probability is not an
authorization.

Models are allowed in two places only:

1. **Async, alongside.** Read the event stream after the fact: correlate,
   score, flag, propose. Off the hot path. All the check and triage work lives
   here.
2. **Precomputed, compiled to a bit.** Score an artifact once at write time in
   userspace and store a label; the kernel later reads that label as one bit at
   kernel speed. The model ran offline. The kernel never calls it.

A model may make a proposed policy **stricter, never looser**. If a model is
unsure, the safe default applies. Uncertainty never opens anything.

## Quick start

Requires Linux with `CONFIG_BPF_LSM=y`, `bpf` in `/sys/kernel/security/lsm`,
BTF at `/sys/kernel/btf/vmlinux`, and kernel 6.4 or later. See
[SUPPORT.md](SUPPORT.md) for a three-command self-check.

```sh
# Install (Debian/Ubuntu, amd64 or arm64)
sudo apt install ./ringzero-security_<version>_<arch>.deb

# The installer adds `bpf` to the kernel command line. Reboot if it asks.
rz status                  # daemon + kernel programs
```

The daemon package depends on `libc6` and `libgcc-s1` and nothing else, so a
server stays free of a GUI stack. The desktop viewer is a **separate** package:

```sh
sudo apt install ./ringzero-desktop_<version>_<arch>.deb
```

Then watch a denial happen:

```sh
bash examples/boundary-demo.sh
```

The agent writes a C program, compiles it, runs the binary, and the binary
calls `open(2)` on a protected file with no shell and no tool in the way. The
kernel refuses the open. That is the demo worth running, because it is the one
a tool-layer filter could not have produced.

## The optional tool-call hook can deny, at a cost you choose

**This section is about the opt-in hook.** Without one installed, `[checks]
blocking = true` does nothing at all, because declining a call before it runs is
the one thing only a hook can do. The daemon says so at startup rather than
letting the setting sit there looking active.

With a hook installed, it is fire-and-forget by default: it records what the
agent is about to do and never blocks. With `[checks] blocking = true` it can
also **deny** a tool call, and the deterministic scorer runs first and gates the
model call, so an ordinary call adds no network latency.

There is an operational trade, and it is yours to make. With blocking on and the
default provider, a provider outage or rate limit means one of two things, set
by a required `fail_mode`:

- `fail_mode = "closed"` denies the call — your developers are blocked.
- `fail_mode = "open"` allows it — that path is unprotected until the provider
  recovers.

There is no third option while the scorer is a network call, which is the
strongest reason to run the model locally. The scoring provider is an endpoint:
`base_url` selects it, and a locally shipped fine-tuned model — this project's
intended next step — replaces the hosted call with no code change and removes
this trade. The kernel remains the boundary regardless: this hook is app-level
and bypassable (see `examples/boundary-demo.sh`), so it is a convenience, not the
enforcement point.

## What terminal capture reads, and how to turn it off

Ring Zero reads the text an agent writes to, and reads from, its terminal. It is
captured in the kernel below the agent, so it does not depend on the agent
cooperating and cannot be switched off from inside it. On a default install this
is the checks layer's main input, since hooks are opt-in.

**It can see secrets.** Terminal output is whatever the agent printed: a token
it echoed, a config file it `cat`'d, a key in an error message. So:

- every fragment goes through the `[webhooks.redaction]` redactor **before** it
  is stored or scored, and the raw text is dropped at that point;
- what is kept goes in the local event timeline on this machine, as
  `agent_stdout` / `agent_stdin` events, truncated to `max_event_bytes`;
- it leaves the machine **only** if the checks layer is on with a hosted
  provider *and* the local scorer already flagged that fragment, and then only
  after the same redaction;
- if the redactor cannot be built, capture does not run at all rather than
  capture unredacted.

Turn it off with `[stdio_capture] enabled = false`. Kernel enforcement is
unaffected: you can run the enforcement layer with no terminal capture
whatsoever.

**What it cannot see.** Matching is on the process name, so an agent whose
binary has been renamed is not captured. That is a real limit, and it is the
same one the kernel's own name-based agent detection has.

## Scanning what an agent writes

An agent can write a program, compile it and run it, and until now no layer read
what it wrote. Our own `examples/boundary-demo.sh` does exactly that. Content
cannot be judged when a file is opened, because the bytes do not exist yet, so
the scan happens when the write finishes and the answer is stored as one bit the
kernel reads later.

Detection is fanotify `CLOSE_WRITE` with the writing pid, marked per filesystem.
Only files written from inside a tracked agent tree are read, and only files
worth reading: source and scripts by extension, anything with a shebang,
anything executable, anything in an agent directory. A build's object files are
never opened.

**Enforcement is off by default.** With `[scanner.write_scan] enforce = true`
the kernel refuses to open or exec a file that a **deterministic** pattern
flagged. A model verdict can raise what a human is shown and can never cause a
refusal, because here severity means "refuse to run" rather than "show someone".
`file_open` is checked as well as exec, because `python3 evil.py` execs python3
and only opens the script.

**The window, measured on the test VM rather than asserted.** There is a gap
between the write closing and the verdict being stored, and during it the file
is usable:

| | close to verdict |
|---|---|
| first write after start | 1573 ms |
| steady state, five runs | 798 to 874 ms |

Almost all of that is userspace polling the kernel map, not the scan: the scan
itself takes 12 to 97 ms. If you want the window smaller, that polling is the
part to attack, not the scanner. The default is fail-open: the file runs during
the window.
`[scanner.write_scan] fail_closed = true` closes it, at the cost of a pause on
every agent-written file.

**What it reads.** File contents the user never sent anywhere. Findings stay on
this machine. Nothing reaches a third party unless the scanner's model layer is
explicitly enabled, and then only redacted and truncated.

## Narrowing egress when external content enters

An agent that fetches a web page or calls an MCP server has pulled in content it
did not write, and that content can carry instructions. Ring Zero treats that as
a deterministic fact — the agent invoked a web fetch, a web search, or an MCP
tool — and raises kernel **taint** on the agent's process tree. With egress
enforcement on, a tainted process is then held to an egress allowlist: loopback,
the LLM API endpoints, and whatever the operator approved. Everything else is
refused at `socket_connect` with `EACCES`.

Two halves, both deterministic. A userspace watcher tails each agent's
transcript and raises taint on provenance, never on a judgment that the content
is bad. The kernel enforces the allowlist. Taint is only ever raised; the kernel
drops it when the process exits, which is not a loosening of authority.

**Off by default.** `[egress] enforce = false` records an off-allowlist connect
and allows it. `[egress] enforce = true` refuses it. The LLM endpoints are
always allowed, so the agent keeps reaching its model.

**Deliberately narrow.** The taint trigger ships with web fetch, web search and
MCP only. A read of a file outside the workspace is a plausible fourth signal,
held back until its false-positive rate on a normal session is measured, because
it is the one most likely to taint an ordinary coding session. A session that
only reads, writes and runs local commands is never tainted — verified on the
VM. See `models/README.md` for the selectivity check and the measured detection
gap.

**The agent's own journal is excluded**, from both the taint trigger and the
write-scanner. The transcript is the union of everything the session handled, so
it always looks sensitive; scanning it would flag it harder than a real threat,
and with quarantine on the kernel would then refuse the very file the agent
reads to resume.

## What is enforced, and what is not

Read this before you read anything else.

| Operation | This release |
|---|---|
| Open, create, delete, rename of a protected file | **Refused in the kernel** |
| Process execution (`exec`) | **Recorded**, not refused |
| Outbound network connections | **Recorded**, not refused |
| DNS, outbound sends, ptrace, mount, kill | **Recorded**, not refused |

Protected files are matched by basename **and** by `(device, inode)`, so a
rename, a hardlink or a symlink lands on the same decision as the original.

Exec and connect events are recorded and correlated into chains, and they carry
`"allowed": true` in the trace even when they are the interesting part of an
attack. Nothing in this repository blocks them today. See `GPL/README.md`.

## Repository layout

| Path | What | License |
|---|---|---|
| `GPL/bpf/` | eBPF LSM programs — the enforcement layer | GPL-2.0 |
| `agent/` | loader, policy engine, local API, IPC, review queue | Apache-2.0 |
| `checks/` | deterministic scorers, off the hot path | Apache-2.0 |
| `cli/` | `rz` | Apache-2.0 |
| `app/` | desktop viewer (Tauri + React) — reads with the read-only token, writes via polkit | Apache-2.0 |
| `trace/` | the shared event format, versioned | Apache-2.0 |
| `review/` | the queue that collects labelled denials | Apache-2.0 |
| `models/` | training and eval — **planned, nothing ships** | Apache-2.0 |
| `policies/`, `hooks/`, `examples/`, `tests/`, `docs/` | supporting material | Apache-2.0 |

## Licensing

This Apache-2.0 license covers the entire repository EXCEPT the contents of the
`GPL/` directory, which is licensed GPL-2.0 (see [GPL/LICENSE](GPL/LICENSE)).

The split is required, not chosen: Linux refuses to load a BPF LSM program
unless it declares a GPL-compatible license, because those programs call
GPL-only kernel helpers. The userspace loader links **compiled objects** only;
no BPF source is compiled into the Apache-2.0 side.

Attribution for third-party code is in [NOTICE](NOTICE).

## Honesty and limitations

The checks run in userspace and can be bypassed, like any guardrail — an agent
can write a binary, or a compromised plugin runs inside the agent process.
That's exactly why the kernel layer exists: it enforces below the agent, where
it can't be talked around.

Enforcement is meant to be out of the agent's reach. The on/off authority lives
in a privileged service: the full-scope API token is root-only at
`/var/lib/ringzero/api-token`, what the installer leaves in the operator's home
is the **read-only** token, and the IPC path refuses an enforcement change from
any peer that is not uid 0. The service binary, its config and its policy store
are themselves protected objects in the policy, so "edit the config", "kill the
daemon" and "chmod the policy file" are just more denied operations, keyed on
the object rather than on a command string we tried to blocklist.

### Cached sudo credentials are a real hole, and they are not ours to close

Read this before believing the paragraph above. `sudo` remembers that you
authenticated, per terminal, for about fifteen minutes. In that window:

```
$ cat /var/lib/ringzero/api-token          Permission denied
$ sudo -v                                  a human authenticates once
$ sudo -n cat /var/lib/ringzero/api-token  prints the full-scope token
```

An agent running in a terminal where you recently used `sudo` inherits that
cache, reads the token with no prompt, and can call the API as if it were you.
Being in the `sudo` group is the normal case on a developer laptop, so this is
not an exotic configuration. This is a property of `sudo`, not something Ring
Zero introduces or can repeal.

**What we do about it.** A valid token is no longer enough to change policy. The
daemon resolves the calling process — through `/proc/net/tcp` to a socket inode
and on to a pid, or through `SO_PEERCRED` on the IPC socket — and refuses a
mutating call whose caller, or any of its ancestors, is an AI agent. A caller it
cannot identify is refused too, because the check is to *prove* the caller is
not an agent. Reads are never affected, and every refusal lands in the audit
chain and the review queue.

**What that does not do.** It catches an agent that runs a tool process as its
child, which is how agents normally work. It does not catch an agent that
exec-replaces itself, that launches a helper outside its own process tree, or
that writes a file some other privileged process later reads. Process names are
evidence, not proof. Treat this as closing the common accident, not as a
boundary — the kernel enforcement is the boundary.

**What you can do about it**, and this is the actual fix: do not run agents in a
terminal you have used `sudo` in, or turn the timestamp off. `SUPPORT.md` has
the exact `sudoers` snippet. Neither is installed by default, because changing
how `sudo` behaves on your machine is your decision.

`pkexec` is not affected: it does not consult sudo's timestamp, and the desktop
app's polkit action is `auth_admin` with no "keep", so it prompts every time.
Verified on a box with passwordless `sudo` — strictly more permissive than a
cached timestamp — where a non-interactive `pkexec` still failed.

A privileged human operator can still stop the service deliberately, and that
is logged. We do not claim it is unkillable.

There are two ways an operator can hand that authority away, and neither is a
bug we can fix for you:

- `rz` reads `RZ_API_TOKEN` and `RZ_API_TOKEN_FILE` from the environment. If
  you export the full-scope token into your shell profile, every process
  running as you inherits it — including the agent. Do not do that. Use `sudo`,
  which reads the root-only token — `/var/lib/ringzero/api-token` is in `rz`'s
  search only when it is running as root, and `rz` never writes to it.
- When the daemon runs **unprivileged** (a dev `cargo run`), it writes the raw
  token under `$HOME/.config/ringzero/` and `/tmp/ringzero-api-token`, readable
  by anything running as that user. Dev mode is for development; it is not a
  security boundary.

v1 kernel scope does not yet cover raw-disk reads, snapshots, or hostname-level
egress. Exec and network connections are recorded, not refused.

The checks layer is off by default, so an untouched install sends nothing off
the machine. Turning it on with the default provider means each scored tool
call goes to a third-party API in **this release**: redacted tool-call fields,
the workspace path, the approved-host list and a hash of the task. Raw prompt
text is never sent. The provider is an endpoint chosen by `base_url`, and the
intended next step is a fine-tuned model shipped locally, which serves the same
contract and removes the third-party call with no code change. Set
`provider = "deterministic"` to keep scoring local today; those scorers are
repeatable but not calibrated against labelled data. No model weights ship in
this repository, and no triage or correlation model ships either — those need
labelled denials, which is what the review queue is for.

## Credit

The classifier approach is inspired by TypeSafe's Jev (System One). We are not
affiliated with TypeSafe. We train our own models.

The checks layer's default provider calls TypeSafe's hosted Jev API when you
enable it. No model weights are bundled in this repository, and the local
deterministic scorers are what run when the hosted provider is unavailable or
unselected.

## Contributing, security, support

- [CONTRIBUTING.md](CONTRIBUTING.md) — DCO sign-off, building both layers, and
  the rule for kernel-side review.
- [SECURITY.md](SECURITY.md) — report a bypass privately, not as an issue.
- [SUPPORT.md](SUPPORT.md) — kernel requirements and the self-check.
