---
name: ringzero
description: Operate Ring Zero Security on this host from the command line — check status, set enforcement posture, block/allow file access at the kernel, review threats and agent sessions, manage network policy, and scan agent skills for supply-chain risk. Use on headless servers (no GUI) or whenever asked to operate, configure, harden, or inspect Ring Zero / the "rz" CLI.
---

# Operating Ring Zero Security (`rz`)

Ring Zero is a kernel-level (eBPF LSM) security daemon that monitors and controls
AI-agent behavior on this host. On a server there is no desktop app — everything
is done through the `rz` CLI. This skill covers the operator tasks.

**Always run `rz status` first** to confirm the daemon is up and whether the
kernel driver (eBPF) is active. If enforcement isn't active, a first-install
reboot may be pending (the installer enables BPF LSM via GRUB).

## Status & monitoring
- `rz status` — daemon health, kernel-driver state, active sessions, threats blocked.
- `rz events` — live stream of agent file / exec / network kernel events.
- `rz threats` — recent blocked or flagged threats.
- `rz sessions list` — active agent sessions (`rz sessions approve|terminate <id>`).

## Enforcement posture (per threat category)
Each category responds as `observe` (log only), `alert`, or `block`.
- `rz enforcement show` — current default + per-category posture.
- `rz enforcement set-default block` — set the default for every category.
- `rz enforcement set-category credential_access block` — set one category.
  Categories: `credential_access`, `data_exfiltration`, `privilege_escalation`,
  `prompt_injection`, `supply_chain`, `excessive_agency`, `output_handling`,
  `memory_poisoning`, `tool_misuse`, `rogue_agent`, `system_prompt_leakage`,
  `mcp_tool_poisoning`, `harmful_content`.
- Enforcement changes need a reload: `sudo systemctl reload ringzero-daemon`.

## File access control (kernel-enforced, applies live)
Block or allow specific files for AI-agent processes (pushed straight to eBPF).
- `rz file-access show` — list rules (each has an id).
- `rz file-access add '*id_rsa' block` — block a basename/glob for agents.
- `rz file-access add '/home/u/.env' block -d "project secrets"`.
- `rz file-access remove <id>` — remove a rule (id from `show`).

## Network policy
- `rz network show` — current mode + enforce state.
- `rz network set-mode high|medium|low`.
- `rz network set-enforce enforce|observe`.

## Supply-chain / agent-skill scanning
- `rz scan skills` — scan installed agent skills / plugins / MCP servers for
  prompt-injection and supply-chain risk (e.g. a hijacked `*claw*` skill).

## What actually enforces

Only **file-access rules** are enforced by the kernel. `rz enforcement
set-default/set-category` records a posture that nothing in the event pipeline
reads today, so setting it to `block` blocks nothing. Do not tell an operator a
machine is locked down on the strength of it.

## Common requests → commands
| Ask | Command |
|---|---|
| "Is Ring Zero running / healthy?" | `rz status` |
| "Lock it down / harden everything" | `rz file-access add '<path>' block` for each path that matters — file-access rules are the only setting the kernel actually enforces |
| "Stop agents reading my SSH keys" | `rz file-access add '*id_rsa' block` |
| "What got blocked recently?" | `rz threats` |
| "Audit the agent skills on this box" | `rz scan skills` |
| "Watch what agents are doing" | `rz events` |

## Notes
- `file-access` and `network` changes apply **live**; `enforcement` changes need
  a daemon reload (`sudo systemctl reload ringzero-daemon`).
- Enforcement requires BPF LSM active; `rz status` shows the kernel-driver state.
- Treat blocked credential/exfil events as real incidents — investigate the
  session (`rz sessions list`, `rz events`) before relaxing any rule.
