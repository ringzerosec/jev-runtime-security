# models

**Planned — not in this release.**

No weights ship in this repository, and no model runs anywhere in the product
today. The two checks that ship are deterministic rule-based scorers; see
`checks/README.md`.

This is deliberate rather than unfinished. A scoring model needs labelled
examples of real denials and real agent behaviour, and we have none yet. The
review queue that ships in this release is the thing that collects them: every
kernel denial and every check flag lands there with its trace attached and a
human sets one label. Those labels are the training rows.

## What will live here

| Piece | State |
|---|---|
| Option-scoring head and the fixed option sets for the six checks | option sets exist in `checks/src/lib.rs`; the head is planned |
| Training script | planned |
| Eval harness | planned |
| Exported ONNX artifacts | planned |

## The bar any model here has to clear

- **Reported calibration.** Expected calibration error, not just accuracy.
- **A shuffled-context control.** Score the same options against shuffled
  context. A model that does as well on shuffled context is reading option
  priors, not the situation, and does not ship.
- **Reproducible.** No accuracy claim that cannot be reproduced from a script
  in this repository.
- **Labelled weights.** Anything published is labelled with the dataset it was
  trained on and marked experimental.

## Also planned, and dependent on collected traces

Policy drafting, artifact labelling, denial triage, and intent–action
correlation. Each of these reads traces that only exist once the enforcement
layer has been running somewhere real. None of them is implemented.

Whatever arrives, the rule does not move: a model may make a proposed policy
stricter, never looser, and the kernel never calls one.

## The scanner model layer, and what is not measured

The skill scanner has an optional model layer (`[scanner.jev]`, off by default).
In this release its provider is a hosted endpoint selected by `base_url`; the
intended next step is a locally shipped fine-tuned model serving the same
contract, which removes the third-party call with no code change and does not
change anything measured here.
It scores instruction-bearing files — SKILL.md bodies, rules, MCP configs,
prompt templates, hook scripts — with a typed `choice` question, and it may
**raise** a file's severity or **add** a finding the deterministic patterns did
not produce. It is monotonic: it can never clear, downgrade or suppress a
pattern finding.

**Its benefit is unmeasured in this release.** The reason to build it is that
our patterns are public, so an injection can be phrased to avoid them, and a
model generalises to phrasings nobody enumerated. That is a plausible argument,
not a measured result. Nothing in this repository reproduces a case where the
model catches an evasion the patterns miss, so this release makes no such claim.
The layer is present and wired; whether it improves detection is an open
question here.

The included test (`tests/jev-stub.py` plus the inert fixture under a scanned
skills directory) proves the *mechanism* only: eligibility, attribution to the
model layer, the monotonic raise, and the loud-degradation report path. It does
not prove *efficacy*, and it is not written to.

### One thing that *was* measured: context contaminates a verdict

This layer used to put four files in one request, each with its own question.
Against the hosted endpoint (jev-1.13.0) that made the files score each other.
A plainly descriptive file answered `documentation` with confidence 1.0 when it
was the only file in the request, and `instructs_exfiltration` at 0.51 when it
shared a request with a file that did instruct exfiltration. The instructive
file scored the same either way.

Because this layer may only raise severity, that turns into a false Critical on
an innocent file. It now sends one file per request, which cannot contaminate.
Naming the state key inside each question also fixed it in every trial, but that
is a property of how a model reads a prompt rather than of the contract, so it
is kept as a second line of defence and not relied on.

Read that result as a warning about the whole layer: the verdict moved with
context that was not the file. That is the shuffled-context problem below,
showing up in production shape before anyone ran the control.

### What measuring it would require

The same bar the checks layer is held to:

- A labelled set of instruction files, benign and malicious, that can be
  redistributed or regenerated from a script in this repository.
- Both layers scored over that set.
- Reported **expected calibration error**, not just accuracy, and a
  **shuffled-context control** proving the model reads the file rather than the
  option priors.

The review queue is what collects the labelled material: every kernel denial
and every flag lands there for a human verdict, and those verdicts are the rows
a real evaluation would be built from. Until that evaluation exists and is
reproducible from this repo, the scanner model layer is a mechanism without a
measured benefit, and the docs say so.


## Taint from external content, and the taint-explosion risk

Ring Zero raises kernel taint on an agent's process tree when its transcript
shows external content was ingested — a web fetch, a web search, an MCP tool
result — and, with egress enforcement on, the kernel then holds that process to
an egress allowlist. The trigger is deterministic provenance: the tool the
agent invoked, read from the transcript. It is never a judgment that the content
is malicious, and a model may raise severity on top but may never clear taint.

**The risk is a taint explosion**: a trigger so broad that an ordinary coding
session is tainted within seconds, at which point narrowed egress is just
breakage. The mitigation is to ship only the clearest external signals and to
prove selectivity before widening.

**What ships:** web fetch, web search, MCP. **What is deliberately held back:**
"a read of a file outside the workspace." It is a real external signal, but it
is the one most likely to fire on a normal session, and it is not enabled until
its false-positive rate is measured.

**Selectivity, verified.** A session that uses only local tools — Read, Write,
Edit, Bash, Grep, Glob — is never tainted. This was checked on the VM: a
stand-in agent whose transcript contained only `Read` and `Bash` tool calls was
never tainted and connected off-allowlist freely, while one that recorded a
`WebFetch` was tainted and refused. So a plain coding session that does not
touch the web or an MCP server carries no taint and no egress narrowing.

**Measured with a real authenticated agent, and the result demoted this
trigger.** Asked to read a web page, a real Claude Code session did not call
`WebFetch` at all — it ran `curl -s https://example.com` through Bash. The
watcher correctly saw nothing, and the agent ingested external content with full
egress authority. The selectivity above is real, but it is selectivity over a
door real agents mostly do not use. The kernel signal below is now the primary
one, and this watcher is a supplement for what the kernel cannot attribute: an
MCP result on a connection already open, or a helper not tied to the agent tree.

**Detection gap, measured.** From a transcript record landing to taint being set
on the process tree: 106–135 ms across five runs on the VM, bounded above by the
500 ms poll interval plus a few ms of processing. Setting the taint itself takes
4–8 ms.


### The kernel signal, and the measurement that stops it shipping on

The transcript trigger above turned out to be pointed at a door real agents
mostly do not use. Asked to read a web page, a real Claude Code session ran
`curl -s https://example.com` through Bash. It never called a fetch tool, so the
watcher correctly saw nothing and the agent ingested external content with full
egress authority intact.

The kernel already has the fact. Every route to the network — a fetch tool,
`curl`, `wget`, a python one-liner, a script the agent wrote a minute ago — has
to call `connect(2)`, and the hook already knows whether the process is in a
tracked agent tree. So an off-allowlist connection by an agent-tree process now
raises taint, structurally, with no name to match and nothing to evade. The
transcript watcher stays, demoted to a supplement for what the kernel cannot
attribute: an MCP result on a connection already open, or a helper we failed to
tie to the tree.

Taint lands on the AGENT ROOT, not only the connecting process. That was not a
refinement, it was necessary: `curl` connected, was tainted, and exited in the
same breath, so the exit tracepoint dropped the entry before anything could use
it and the map read empty.

**And it is off by default, because it was measured and the number is bad.** A
session told explicitly not to touch the network, doing only local file work,
produced **18 tainted processes**. The rule fires on every session immediately,
which makes it meaningless.

The cause is the allowlist, not the rule. The daemon resolves the model API
hostnames once at startup and holds 42 addresses. `api.anthropic.com` is behind
a CDN, so the agent resolves the same name later and gets a different address —
160.79.104.10, which was not in the set. The agent's own calls to its own model
therefore read as off-allowlist.

**Static IP allowlisting cannot work for a CDN-fronted endpoint.** Re-resolving
on a timer only narrows the race: the daemon's answer and the agent's answer are
different answers to the same question, and asking more often does not make them
the same. The fix is to allow by NAME, learned from the DNS answers the machine
actually receives, admitting exactly those addresses for exactly the TTL the
record specifies. That is the standard technique; Cilium's DNS-based network
policy is the reference.

### What is built, and the one piece that is not

Built and tested (`agent/src/dns_allow.rs`, 14 tests): the DNS answer parser,
the name allowlist, the TTL-bounded learned set, and the manager that pushes
admitted addresses into the kernel egress map and revokes them on expiry.
Configured with `[egress] allow_names`, defaulting to the model API domains.

Details that matter, each pinned by a test: suffix matching is on label
boundaries, so `.anthropic.com` is not satisfied by `evil-anthropic.com` nor by
`anthropic.com.attacker.net` — the same substring trap that cost a day with
process names. TTLs are clamped to 30s–1h, so a one-second record cannot make
the list thrash and a ten-year one cannot pin an address forever. A later,
shorter answer never shortens an entry still in use. The parser bounds-checks
every length, caps compression-pointer jumps, and is exercised against
truncation at every offset and a self-referential pointer; malformed input
yields no records rather than a guess.

**Not built: the source of those answers.** Nothing calls `observe_response`
yet, so the learned set is always empty and `taint_on_egress` stays off. Two
candidates:

- A BPF capture of DNS responses on a `sys_exit_recvfrom`/`recvmsg` tracepoint
  filtered to monitored processes, in the style of the existing stdio capture.
  No new capability, but it needs the socket-to-port mapping at the tracepoint,
  which the current hooks do not carry.
- An `AF_PACKET` sniffer in the daemon for UDP port 53. Simpler to write, but it
  needs `CAP_NET_RAW`, which the daemon does not have and which would be a
  deliberate privilege widening to justify.

Until one lands, egress narrowing has no usable allowlist for a CDN-fronted
endpoint, `taint_on_egress` stays off, and this document does not claim it
works.
