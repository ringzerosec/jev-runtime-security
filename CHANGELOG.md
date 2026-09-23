# Changelog

Versions follow [semantic versioning](https://semver.org/). This is a 0.x
project, so the minor version moves for breaking changes.

## [0.1.0] — unreleased

First public release. Linux only.

### Two layers

- **Kernel enforcement** (`GPL/bpf`, GPL-2.0) — eBPF LSM programs that refuse
  open, create, delete and rename of protected files for an agent's whole
  process tree. Files are pinned by basename **and** by `(device, inode)`, so
  renames, hardlinks and symlinks reach the same decision.
- **Checks** (`checks/`, Apache-2.0) — deterministic scorers for tool-call
  argument risk and sensitive-data exposure. They run off the syscall path on
  harness hook events, return one option from a fixed set with a probability
  and a confidence, and never allow or deny anything. Off by default.
- **The join** (`trace/`) — one versioned event format both layers write, keyed
  on `session_id`, so an intent label can be lined up against the kernel's real
  decision.

### Recorded, not refused

Process exec, network connect, DNS, outbound sends, ptrace, mount, kill and
mprotect are captured and correlated into chains. None of them is blocked in
this release, and the trace records them with `"allowed": true`.

### Also in this release

- **Review queue** — every kernel denial and every check flag lands in a queue
  with its trace attached and a human label field (`benign`, `real-threat`,
  `false-positive`). No model reads it. It exists to collect the labelled data
  that triage and correlation models will need.
- **Enforcement authority is root-only.** The installer places the *read-only*
  API token in the operator's home; the full-scope token stays root-only at
  `/var/lib/ringzero/api-token`, and the IPC path refuses an enforcement change
  from any peer that is not uid 0. An agent running as the developer gets a 403
  and a message pointing a human at `sudo`. Every change is audit-logged.
- **Detection webhooks** — HMAC-signed, redacted event stream with a bounded
  local queue, a `file://` JSONL sink, and opt-in synchronous verdict hooks
  with a required `fail_mode`.
- **SIEM forwarders** for Splunk HEC, Elasticsearch, Microsoft Sentinel and
  syslog/CEF. All off by default.
- **`rz`** command-line tool and a local HTTP API bound to 127.0.0.1.
- **`examples/boundary-demo.sh`** — an agent writes a C program, compiles it,
  runs the binary, and the kernel refuses the binary's `open(2)`. The compile
  and the exec both run, because exec is recorded, not refused.

### Known issues

- `ringzero_file_open` reserves its ring-buffer slot before checking the block
  maps and allows the open when the reservation fails, so a sustained event
  flood from an agent can let a protected read through. The agent drains the
  ring every 5 ms as a mitigation; the kernel-side reordering is queued.
- Outbound payload capture does not return the real send buffer on 6.x kernels
  (`iov_iter.__iov`), so termination on that data is disabled.
- On kernels before 6.4 the eBPF object fails to load and the agent runs in a
  degraded, userspace-only mode that refuses nothing. It logs this at startup.

### Tool-call hook can deny (opt-in)

`[checks] blocking = true` lets the agent tool-call hook deny a call, not just
record it. Off by default and fire-and-forget when off. The deterministic
scorer runs first and gates the model call, so an ordinary call adds no
latency; a required `fail_mode` ("open" or "closed", no default) decides what
happens when the scorer cannot answer, and the daemon refuses to start without
it. A short-lived cache reuses a decision for an identical call. A denied call
returns Claude Code's documented PreToolUse deny response with the rule name in
the reason. The decision, provider, latency, block outcome and any fail-mode
application are recorded in the trace. A model-backed verdict hook on
`file_open`, `process_exec` or `socket_connect` is refused in config with an
explanation of the arithmetic; the verdict hook remains available for a fast
local policy engine.

The scoring provider is an endpoint chosen by `base_url`; a locally shipped
fine-tuned model that serves the same contract is the intended next step and
removes the third-party call with no code change.

### Packages

Two, so a server never pulls in a GUI stack:

- **`ringzero-security`** — daemon, `rz`, `rz-hook`, the eBPF object, config,
  agent skills and the runnable demos. `Depends: libc6, libgcc-s1`.
- **`ringzero-desktop`** — the desktop viewer, its `.desktop` entry and icons.
  Depends on the GTK/WebKit stack and on `ringzero-security` at the same
  version. The viewer is read-only: it reads its token's scope from
  `GET /api/v1/auth/scope` and disables anything that would change policy,
  naming the `sudo rz …` command instead. No privilege helper, no sudo prompt.

`bash build-deb.sh` builds both; `bash build-deb.sh --daemon-only` skips the
viewer for CI and headless builds.

### Not included

No model weights, no triage or correlation model, no policy-drafting model. The
Windows and macOS components are not part of this repository.
