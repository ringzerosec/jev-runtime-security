

# Ring Zero Security

[![build](https://github.com/ringzerosec/jev-runtime-security/actions/workflows/ci.yml/badge.svg)](https://github.com/ringzerosec/jev-runtime-security/actions/workflows/ci.yml)
[![userspace: Apache-2.0](https://img.shields.io/badge/userspace-Apache--2.0-blue)](LICENSE)
[![kernel: GPL-2.0](https://img.shields.io/badge/kernel-GPL--2.0-blue)](GPL/LICENSE)

**Runtime security for AI coding agents.** Policy is enforced in the kernel, at
the system call — below the agent, and below anything the agent writes. The
agent's reasoning never gets a vote in whether an operation is allowed.

> *Jev* is TypeSafe's System One model, which Ring Zero can call as an optional
> checks provider. Ring Zero is not affiliated with TypeSafe, and no TypeSafe
> code or model weights are bundled here — see [NOTICE](NOTICE).

## Why

OpenAI's *Agent security in the enterprise* states the problem plainly:

- **A credential is not authorization.** Access to a system doesn't establish
  that a given action in it was authorized.
- **Context is untrusted.** A repo, a web page, a tool result can each *instruct*
  the agent — and any of them can redirect it.
- **Instructions are a weak defense.** A rule in a prompt is guidance; an agent
  can be argued out of it. Independent controls provide containment.
- **Place controls close to the effect** — and enforced controls and advisory
  checks are not the same thing.

Ring Zero is the enforced control, placed at the lowest layer the agent runs on.

## Demo
[![Watch the video]([https://youtube.com](https://youtu.be/bR8qixgksOI))]



## How the guidance maps to what Ring Zero does

| OpenAI principle | What Ring Zero enforces |
|---|---|
| Enforce boundaries, below the agent | eBPF/LSM decides file open / create / delete / rename per agent, at the syscall. It runs below the agent and can't be talked around. |
| Place the control close to the effect | The decision is on the operation itself — a protected file is matched by basename **and** `(device, inode)`, so a rename, hardlink or symlink hits the same decision. |
| Enforced control ≠ advisory check | The kernel decides deterministically. The model (checks / Jev) only *raises* severity — it can make a verdict stricter, never permit what policy denies. |
| Assume context is untrusted | A web fetch, search, or MCP call raises kernel **taint** on the agent's process tree; a tainted process can be held to an egress allowlist (opt-in). |
| The agent is an identifiable actor | Enforcement authority is root-only. The agent runs as your developer with a **read-only** token and can't turn enforcement off. |
| Observe actions | One trace keyed on `session_id` joins what it *looked like* the agent would do with what it *actually* did. |

## The one rule

**Enforcement is deterministic. Models never decide the syscall.**

The kernel allows or denies by fixed policy — no model in the file-open, exec, or
connect path, ever. A model runs only *async* (score the event stream after the
fact) or *precomputed* (score an artifact once at write time and store one bit
the kernel later reads). A model may make a verdict **stricter, never looser.** A
probability is not an authorization.

## Quick start

Requires Linux with `CONFIG_BPF_LSM=y`, `bpf` in `/sys/kernel/security/lsm`, BTF
at `/sys/kernel/btf/vmlinux`, kernel 6.4+. [SUPPORT.md](SUPPORT.md) has a
three-command self-check.

```sh
sudo apt install ./ringzero-security_<version>_<arch>.deb   # amd64 or arm64
rz status                          # daemon + kernel programs
bash examples/boundary-demo.sh     # watch a denial: the agent compiles a binary
                                   # that open()s a protected file — kernel refuses
```

The desktop viewer is a separate package (`ringzero-desktop`): it reads with the
read-only token and writes only through an interactive polkit prompt an agent
can't answer.

## What's enforced, and what isn't

| Operation | This release |
|---|---|
| Open, create, delete, rename of a protected file | **Refused in the kernel** |
| Process execution (`exec`) | **Recorded**, not refused |
| Outbound connections, DNS, sends, ptrace, mount, kill | **Recorded**, not refused |

Off by default, opt-in where you configure them: write-scan enforcement (refuse
to run an agent-written file a deterministic rule flagged), the egress allowlist,
and a tool-call hook that can decline a call before it runs.

## Limitations we don't hide

- **Agent detection is by process name.** An agent whose binary is renamed to
  something unknown isn't recognized — and what isn't recognized isn't enforced.
  The known-agent list is maintained (Claude, Cursor, Copilot, Codex, the ChatGPT
  desktop app, Gemini / Antigravity, aider, Cline, opencode, …).
- **Cached `sudo` can expose the root token.** In a terminal where you recently
  ran `sudo`, an agent inherits the timestamp. This is a property of `sudo`, not
  Ring Zero; the mitigation and exact `sudoers` snippet are in [SECURITY.md](SECURITY.md).
- **v1 kernel scope** doesn't yet cover raw-disk reads, snapshots, or
  hostname-level egress. Exec and network are recorded, not refused.
- The checks layer is **off by default** — an untouched install sends nothing off
  the machine.

## Licensing

Apache-2.0 for the whole repository **except** `GPL/`, which is GPL-2.0 (Linux
won't load a BPF LSM program without a GPL-compatible license). The userspace
loader links compiled BPF objects only; no BPF source compiles into the
Apache-2.0 side. Third-party attribution: [NOTICE](NOTICE).

## More

- [SECURITY.md](SECURITY.md) — report a bypass privately; the full token / `sudo` model.
- [SUPPORT.md](SUPPORT.md) — kernel requirements and self-check.
- [CONTRIBUTING.md](CONTRIBUTING.md) — DCO sign-off, building both layers.
- `GPL/README.md`, `trace/README.md`, `models/README.md` — layer detail.
