# trace — the shared event format

One schema, written by both layers, joined on `session_id`. This is a public
interface: it is versioned, and a change to the option sets or the required
fields is a version bump, not a patch.

The join is the point of the project. The kernel records what an agent actually
did. The checks record what it looked like it was about to do. Same session id,
so a human — and later a model — can line the two up.

## Shape

```json
{
  "schema_version": 1,
  "event_type": "file_open",
  "host": "dev-laptop",
  "timestamp": "2026-09-21T09:14:22.318Z",
  "agent": {
    "session_id": "auto-claude-48201",
    "agent_type": "claude",
    "process": "cat",
    "parent_process": "claude",
    "pid": 48201,
    "uid": 1000
  },
  "args": { "target": "id_rsa", "path": "/home/dev/.aws/credentials" },
  "verdict": { "allowed": false, "reason": "protected file" },
  "policy_version": 1
}
```

### Required core — the kernel's record

| Field | Meaning |
|---|---|
| `schema_version` | Integer. `1` in this release. |
| `event_type` | `file_open`, `process_exec`, `network_connect`, `dns_query`, `llm_tool_call`, … |
| `timestamp` | RFC 3339, UTC. |
| `agent.session_id` | The join key. One agent process tree is one session. |
| `agent.pid`, `agent.uid` | Process identity, and the user the agent runs as. |
| `agent.process`, `agent.parent_process` | What ran, and what spawned it. |
| `args.target` | What was acted on. |
| `verdict.allowed` | `false` only where the kernel refused. See the scope note below. |
| `policy_version` | Which policy produced the verdict. |

### Optional block — the agent's context

Present when a harness hook reported it. Never contains raw prompt text; a
prompt is carried as a hash if it is carried at all.

| Field | Meaning |
|---|---|
| `args.hook` | Which hook fired (`PreToolUse`, …). |
| `args.action` | Normalised action class for the tool call. |
| `args.tool_input` | The arguments the harness was given, bounded and redacted. |
| `args.checks` | Array of check results, see below. |

### Check results

A check never returns a verdict. It returns one option from a fixed set, a
probability, a confidence, and short non-secret evidence.

```json
{
  "check": "tool_call_argument_risk",
  "option": "reads_sensitive_path",
  "probability": 0.9,
  "confidence": 0.9,
  "evidence": ["argument references .aws/credentials", "tool=Bash"],
  "provider": "jev"
}
```

Option sets are fixed per check and live in `checks/src/lib.rs`. Adding an
option is a schema change.

`provider` says which scorer decided: `jev` for the hosted model, or
`deterministic` for the local rule-based scorer. When a configured provider
could not be used, `provider` is `deterministic` and `provider_error` carries
the reason — so a reader can always tell a model score from a fallback:

```json
{
  "check": "sensitive_data_exposure",
  "option": "possible_secret",
  "probability": 0.5,
  "confidence": 0.4,
  "provider": "deterministic",
  "provider_error": "jev: 429 rate limited"
}
```

A provider may only ever raise a result to a more severe option. It cannot
downgrade one, and it cannot lower a score the local scorer already produced.

## What `verdict.allowed: false` means in this release

Only file open, create, delete and rename are refused in the kernel. Process
exec and network connect are recorded, not refused — those events will carry
`"allowed": true` even when they are the interesting part of an attack chain.
Read the event type before reading the verdict.

## Where it goes

The agent writes trace records to any sink you enable: HMAC-signed webhooks, a
local JSONL file, or a SIEM forwarder. Nothing leaves the machine by default.
See `docs/integrations.md` for the delivery contract, signing and redaction.
