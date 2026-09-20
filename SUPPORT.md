# Support

## What your machine needs

| Requirement | Why |
|---|---|
| `CONFIG_BPF_LSM=y` | BPF programs attach to LSM hooks. |
| `bpf` in `/sys/kernel/security/lsm` | The BPF LSM must be active, which usually means adding `lsm=...,bpf` to the kernel command line and rebooting. |
| `/sys/kernel/btf/vmlinux` present | CO-RE relocation, and generating `vmlinux.h` at build time. |
| Kernel 6.4 or later | One field the programs read does not exist earlier. |
| root, or `CAP_BPF` + `CAP_MAC_ADMIN` | Loading and attaching the programs. |

On kernels before 6.4 the eBPF object fails to load and the agent runs in a
degraded, userspace-only mode that refuses nothing. It logs this at startup.

## Three-command self-check

```sh
grep -q CONFIG_BPF_LSM=y "/boot/config-$(uname -r)" && echo "BPF LSM: compiled in" || echo "BPF LSM: MISSING"
grep -q bpf /sys/kernel/security/lsm && echo "BPF LSM: active" || echo "BPF LSM: not in lsm= — add it and reboot"
[ -f /sys/kernel/btf/vmlinux ] && echo "BTF: present" || echo "BTF: MISSING"
```

All three must pass before enforcement can do anything.

## Tested on

| Distribution | Kernel | Architecture |
|---|---|---|
| Ubuntu 24.04 | 6.8 | aarch64 |

That is the configuration this release was actually built and exercised on.
Other distributions and architectures may work — the build is not
architecture-specific and the CI builds on amd64 — but they have not been
verified, and we would rather say so than pad the table.

## Installing the desktop viewer

Optional, and a separate package so servers stay free of the GTK/WebKit stack:

```sh
sudo apt install ./ringzero-security_<version>_<arch>.deb   # required first
sudo apt install ./ringzero-desktop_<version>_<arch>.deb    # the viewer
```

It appears as "Ring Zero Security" in your application menu. It is a **viewer**:
sessions, events, threats, the review queue and status all work, and anything
that would change policy or enforcement is disabled with the `sudo rz …` command
shown next to it. That is because the token in your home is read-only on
purpose — see the section above.

## After installing

```sh
rz status                  # daemon state and whether the kernel programs are loaded
rz events --follow         # live event stream
rz file-access show        # the protected-object rules
journalctl -u ringzero-daemon -n 200 --no-pager
```

## Changing enforcement

Changing policy or enforcement is an operator action and needs root:

```sh
sudo rz enforcement set enforce
```

Without `sudo` you will get `this requires root: sudo rz ...`. That is
deliberate: an AI agent runs as your developer, so the credential in your
developer's home is the read-only one.

## Two ways to leak the full-scope token

Enforcement authority is root-only, and these are the two ways an operator
hands it away by accident.

**Do not export the token into your shell.** `rz` reads `RZ_API_TOKEN` and
`RZ_API_TOKEN_FILE` from the environment. Putting the full-scope token in your
shell profile gives it to every process running as you — including the AI agent
you installed this to contain. Use `sudo rz ...`, which reads a root-only
token: `/root/.config/ringzero/api-token` if it is there, otherwise the one the
installer leaves at `/var/lib/ringzero/api-token`.

**Dev mode is not a security boundary.** When the daemon runs unprivileged (a
`cargo run` during development) it writes the raw token under
`$HOME/.config/ringzero/` and `/tmp/ringzero-api-token`, readable by anything
running as that user. That is fine for development and wrong for a machine you
care about. Run the packaged daemon as root for anything real.

## Terminal capture: what is read, where it goes, how to stop it

On by default. Ring Zero reads the text your agents write to, and read from,
their terminals, captured in the kernel below the agent. With agent hooks
opt-in, this is the main thing the checks layer has to work with.

**What is read.** Whatever the agent printed. That can include secrets it was
legitimately working with — a token it echoed, a config file it printed, a key
inside an error message.

**What happens to it.**

1. The `[webhooks.redaction]` redactor runs over every fragment first. The raw
   text is dropped at that point and is never stored or logged.
2. What survives redaction is stored in the local event timeline on this
   machine, as `agent_stdout` and `agent_stdin` events, truncated to
   `max_event_bytes` (4096 by default).
3. It leaves the machine only if `[checks]` is on with a hosted provider **and**
   the local deterministic scorer already flagged that fragment. Benign output
   never goes anywhere.
4. If the redactor cannot be built from your config, capture does not start at
   all. It will not capture unredacted.

**How to turn it off**, keeping kernel enforcement:

```toml
[stdio_capture]
enabled = false
```

```bash
sudo systemctl reload ringzero-daemon
```

To keep capture in the timeline but never score it, leave `enabled = true` and
set `score = false`.

**What it cannot see.** Matching is on the process name. An agent whose binary
has been renamed is not captured.

## Agent hooks are opt-in

Installing a hook edits Claude Code's or Codex's own settings file, which is not
something to do to someone's machine without being asked. Nothing in the default
install depends on one.

```bash
RZ_INSTALL_AGENT_HOOKS=1 sudo apt install ./ringzero-security_<version>_<arch>.deb
```

What it adds: the structured arguments of a tool call *before* it runs, and the
ability to decline the call. What it costs: it is app-layer and bypassable, and
it is configuration inside the thing being watched, so an agent can edit it.

`[checks] blocking = true` does nothing without a hook, because declining a call
before it runs is the only thing a hook can do that nothing else can. The daemon
logs a clear warning at startup if blocking is on with no hook configured.

## Optional hardening: stop an agent inheriting your sudo credentials

Not installed by default. It changes how `sudo` behaves on your machine, which
is your decision, not ours.

`sudo` remembers that you authenticated, per terminal, for about fifteen
minutes. An agent running in that terminal can use the cache without a prompt:

```bash
sudo -v                                   # you authenticate once
sudo -n cat /var/lib/ringzero/api-token   # the agent reads the full-scope token
```

The daemon now refuses a policy change whose caller is an agent process or a
child of one, whatever token it presents, and records the attempt. That closes
the common case. It does not close an agent that exec-replaces itself or starts
a helper outside its own process tree, so if this matters to you, pick one of
these.

**Simplest: run agents in a terminal you never use `sudo` in.** The cache is per
terminal (`tty_tickets` is on by default on Debian and Ubuntu), so a separate
terminal for agent work has no credential to inherit. Nothing to configure.

**Or turn the timestamp off.** Every `sudo` then asks for a password, and there
is no window to inherit:

```bash
sudo visudo -f /etc/sudoers.d/99-ringzero-timestamp
```

```sudoers
# Ask every time: no cached credential for an AI agent to reuse.
Defaults timestamp_timeout=0
```

**Or scope it to the group that has sudo**, leaving anything else alone:

```sudoers
Defaults:%sudo timestamp_timeout=0
```

Check what you have now with `sudo -l | grep timestamp`, and confirm the file
parses before you rely on it — `visudo -c` refuses to save a broken sudoers.

Changing enforcement from the desktop app is unaffected either way: it uses
`pkexec`, which does not consult sudo's timestamp and prompts every time.

## "A token is registered and this process does not have it"

`rz` needs a bearer token for the daemon's management API. It looks in
`$RZ_API_TOKEN`, then `$RZ_API_TOKEN_FILE` if you set it, then
`$HOME/.config/ringzero/api-token`, and — when you are root —
`/var/lib/ringzero/api-token`. The error lists each place and what it found
there, so read that list first.

As a normal user the root-only path cannot even be stat'd, which is the point:
that token carries enforcement authority. Re-run the same command with `sudo`.

If another client such as the desktop viewer registered the token, pass it
explicitly for the one command rather than exporting it:

```bash
RZ_API_TOKEN=<token> rz threats
```

`rz checks status`, `rz checks set-key` and `rz checks test` do not need this
token. They read `/etc/ringzero/daemon.toml`, write the key file and call the
provider themselves, so they work on a box where something else owns the
daemon's API token. `rz checks status` then reports one line as `unknown` —
whether a provider is live right now is the one thing only the daemon knows.

## Checks and the third-party API

The checks layer is off by default. While it is off, nothing it touches leaves
your machine.

Turning it on matters, because the default provider is hosted:

```toml
[checks]
enabled  = true
provider = "jev"            # hosted by TypeSafe — see below
# provider = "deterministic"  # keeps everything on this machine
```

With `provider = "jev"`, each scored tool call sends to
`https://api.typesafe.ai`: the tool name and arguments, the workspace path, the
approved-host list, and a **hash** of the task. All of it goes through the
`[webhooks.redaction]` redactor first, so matched secrets are masked before the
request is built. **Raw prompt text is never sent.**

The key lives in a file, never in the config:

```sh
sudo install -m 600 -o root -g root /dev/null /etc/ringzero/typesafe.key
sudo sh -c 'printf %s "YOUR_KEY" > /etc/ringzero/typesafe.key'
```

If that file is missing, unreadable, or readable by group or others, the checks
layer refuses to start and logs one error naming the path. It does not fall
back to local scoring on its own, because an operator who asked for the model
needs to know they did not get it. The rest of the daemon keeps running.

If the API is slow or returns 401, 422, 429 or 529, that single call falls back
to the local scorer and the reason is recorded in the trace. Nothing blocks.

### Letting the hook deny (`[checks] blocking`)

Off by default: the tool-call hook records and never blocks. To let it deny:

```toml
[checks]
enabled  = true
blocking = true
fail_mode = "closed"   # or "open" — REQUIRED, no default (see below)
timeout_ms = 1500
```

The daemon refuses to start with `blocking = true` and no `fail_mode`, because
the choice is consequential. With the default (network) provider, a provider
outage forces it:

- `fail_mode = "closed"` denies the pending call — developers are blocked.
- `fail_mode = "open"` allows it — that path is unprotected until recovery.

The deterministic scorer runs first and gates the model call, so an ordinary
tool call makes no network request and adds no latency; only a locally-flagged
call is sent to the model, and the model may only turn an allow into a deny. A
denied call returns the harness's documented deny response with the rule name in
the reason, so the agent learns the path is out of policy instead of retrying.

Every decision is recorded in the trace — the decision, the provider, the
measured latency, whether it was blocked, and the fail-mode outcome if the model
could not answer — so "why did my tool call stall" is answerable from the trace
alone.

This is a network round trip in front of a tool call, which is why blocking is
opt-in. The scoring provider is an endpoint chosen by `base_url`; the intended
next step is a locally shipped fine-tuned model that serves the same contract,
removing the round trip and the fail-mode trade with no code change. The kernel
remains the enforcement boundary regardless: this hook is app-level and
bypassable.

## Getting help

- Questions and bugs: [open an issue](https://github.com/ringzerosec/jev-agentic-security/issues).
- Vulnerabilities: **security@ringzerosecurity.com**, never a public issue. See
  [SECURITY.md](SECURITY.md).
