# CIS MCP Server Benchmark v1.0.0 → Ring Zero coverage map

How Ring Zero maps to the CIS MCP Server Benchmark. Three uses in one sheet: a
**compliance mapping**, a **product roadmap** for the MCP work, and the honest
**"what we cover vs what we don't."**

> Requirements below are **paraphrased** (facts) with their CIS section numbers.
> The CIS Benchmark is copyrighted; this is our own derived mapping, not a copy.

**Legend**
- 🟢 **Enforce (kernel)** — Ring Zero enforces this at the syscall. *Most MCP
  tooling cannot; this is the differentiator.*
- 🔵 **Detect / audit** — our models (the RLCD brain) decide and/or the trace
  records it (tighten-only; see `models/THE-BRAIN.md`).
- 🟡 **Roadmap** — planned (mostly the MCP gateway / identity work).
- ⚪ **Server-author's job** — protocol/crypto/impl concern of whoever *builds* the
  MCP server, outside our runtime-enforcement lane. We don't implement MCP; we
  confine and authorize it.

## The parts we uniquely own (🟢 kernel-enforced)

These are the CIS recs that require **OS-level, kernel-enforced** controls — the
ones an app-layer tool can't meet and we can:

| CIS | Requirement (paraphrased) | Ring Zero control |
|---|---|---|
| **9.2** | MCP server process confined to its working set by **OS-level kernel-enforced controls** (Automated) | eBPF/LSM syscall enforcement — *this is the product* |
| **4.2.1** | Filesystem scope restricted to least privilege, **OS-enforced** | `file_open` / dir rules / `(dev,ino)` protection |
| **5.4.1** | Path traversal & arbitrary filesystem access prevented (Automated) | inode-keyed rules + bounded dentry walk; symlink/hardlink land on the same decision |
| **4.2.2** | stdio subprocess environment restricted to the minimum vars | exec/env enforcement below the agent |
| **9.3** | Local stdio servers run under least-privilege identities + sandbox isolation | the sealed sandbox + uid/exec enforcement |
| **4.1.2** | Project-scoped server definitions not executed without explicit consent | v1 MCP authorization — refuse `exec` of an unapproved stdio server |
| **6.2** | Tokens/keys protected in clients and servers | root-only tokens (0600), secrets floor, DLP redaction |

**Positioning line:** *"Ring Zero enforces the CIS MCP Benchmark's OS-level
confinement, filesystem-scope, path-traversal, and least-privilege controls
(§9.2, §4.2.1, §5.4.1, §4.2.2, §9.3) — at the syscall, where app-layer MCP tools
can't."*

## Detect / audit (🔵 — the brain + trace)

| CIS | Requirement | Ring Zero |
|---|---|---|
| **3.2.3** | Tool annotations (`readOnlyHint`…) treated as **untrusted**; authz rests on operator classification, not server self-description | our core principle — untrusted self-description, operator sets policy; `mcp_tool_poisoning` scores tool metadata |
| **4.2.3** | Untrusted Resource URIs not dereferenced without scheme/destination policy | provenance **taint** on fetch + egress allowlist |
| **1.3** | Newly advertised server capabilities re-validated before invocation | scanner watches MCP config; capability-change detection |
| **4.1.1** | Per-tool consent / pre-approved allowlists | approval/escalation + allowlist |
| **3.2.2** | Token passthrough to downstream APIs forbidden | egress detection/allowlist |
| **7.x** | Lifecycle & invocation metadata recorded; behavioral monitoring of `notifications/*`; monotonic timestamps | the `session_id` trace + event stream |
| **8.1** | Third-party servers vetted, **allowlists enforced** | MCP authorization allowlist + scanner discovery |

## Roadmap (🟡)

| CIS | Requirement | Plan |
|---|---|---|
| **8.2** | Third-party servers **pinned to a verified content hash**, re-vetted on update | binary-identity work (hash > name — ties to the agent-identity discussion) |
| **9.1** | Remote servers in containers/VMs + **gateway ingress controls** | the MCP gateway (deferred to v2) + sandbox |
| **3.2.1** | Per-tool (not per-server) authorization granularity | extend v1 authorization |
| **5.5.1 / 8.3** | MCP Tasks authz/expiry; private-mirror-only artifacts | later |

## Server-author's job — out of our lane (⚪)

Protocol / crypto / implementation concerns of whoever *builds* the MCP server —
**not** our runtime-enforcement layer. We state this plainly so we don't overclaim:

- **§2** Transport: TLS required, no plaintext, Origin/DNS-rebinding validation,
  request metadata headers.
- **§3.1.2, §3.3.x** OAuth 2.1 / OIDC, audience-binding, scope minimization,
  confused-deputy, discovery-metadata validation.
- **§5.1–5.3, §5.6** Tool/resource/prompt schema validation, `listChanged`
  rate-limiting, sessions-not-auth, idempotency keys.
- **§4.3** MCP Apps sandboxed rendering + CSP.
- **§1.1, §6.1, §10** Protocol-version pinning, context minimization/MIME, cache
  freshness, body/token/quota limits.

(We can *record* several of these in the trace, but *implementing* them is the
server author's responsibility.)

## Summary

| | count (approx) |
|---|---|
| 🟢 Enforce (kernel) — **only we do** | ~7 |
| 🔵 Detect / audit | ~7 |
| 🟡 Roadmap | ~4 |
| ⚪ Server-author's job | ~half the benchmark |

**Takeaway:** an emerging CIS standard independently prescribes Ring Zero's
architecture — untrusted self-description, operator-set policy, **OS-level kernel
enforcement**, least privilege, provenance, audit, containment. We own the
enforcement/isolation/authorization/audit half; the server author owns the
protocol/crypto half. The kernel-enforced recs (§9.2, §4.2.1, §5.4.1) are ours
alone.
