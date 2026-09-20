# Integrations: detection webhooks

Ring Zero's daemon can hand agent activity to external detection systems — your own
rules engine, a SIEM pipeline, or an ML scoring service — through two extension points:

| | Event stream | Verdict hooks |
|---|---|---|
| Direction | daemon → receiver, fire-and-forget | daemon → receiver → daemon, request/response |
| Timing | async, queued, best-effort | sync, the daemon waits (default 250 ms) |
| Purpose | feed detection / analytics / storage | let an external system say *deny* before the daemon releases an event |
| Config | `[[webhooks.endpoints]]` | `[[webhooks.verdict_hooks]]` |
| Intended location | anywhere you can reach over HTTPS | localhost or the local network |

**Enforcement always stays in Ring Zero's kernel component and daemon.** External systems only
receive events and return verdicts. They never load code into the kernel, and a receiver cannot
change policy, disable enforcement, or reach into the daemon: the only thing it can say is
`allow` or `deny` for the events it was subscribed to.

**Nothing leaves your machine by default.** Webhooks are off until you add an endpoint or a hook
to the daemon config, and then events go only to the URLs you configured.

## Configuration

Webhooks are configured in the daemon's config file, `/etc/ringzero/daemon.toml`
(root-owned, mode 0640). Only root can change it. The daemon re-reads the file on
`SIGHUP` (`sudo systemctl reload ringzero-daemon`). The webhook section is validated strictly:
a config that fails validation makes the daemon **refuse to start**, and on reload the previous
webhook config stays active and the error is logged. There is no API or UI path that writes this
section.

```toml
[webhooks]
# Per-endpoint queue depth. When a receiver is slow or down, events beyond this
# are dropped (counted, never blocked on). Default 10000.
queue_size = 10000

# ── Async event stream ─────────────────────────────────────────────────────
[[webhooks.endpoints]]
name        = "ml-scorer"
url         = "https://scoring.internal.example.com/ringzero/events"
secret      = "change-me-32-bytes-of-randomness"   # HMAC-SHA256 signing key
event_types = ["*"]        # or a list: ["process_exec", "file_open", "network_connect", "threat"]
timeout_ms  = 5000         # per request (default 5000)
retries     = 3            # after the first failure, backoff 0.5s / 2s / 8s (default 3)

# ── Sync verdict hooks (opt-in per event type) ─────────────────────────────
[[webhooks.verdict_hooks]]
name        = "policy-engine"
url         = "http://127.0.0.1:8081/verdict"
event_types = ["process_exec", "file_open", "network_connect"]
timeout_ms  = 250          # default 250; max 10000
fail_mode   = "open"       # REQUIRED: "open" (allow on timeout/error) or "closed" (deny)
secret      = "another-secret"

# ── Redaction (applied to every payload before it leaves the daemon) ───────
[webhooks.redaction]
enabled          = true
builtin_patterns = true                       # API keys, tokens, JWTs, private keys, key=value secrets
patterns         = ["(?i)internal-ticket-[0-9]+"]  # extra regexes (Rust regex syntax)
drop_fields      = ["args.cmdline"]           # dotted paths removed from the payload entirely
replacement      = "[REDACTED]"
```

An endpoint may also be a local file: `url = "file:///var/log/ringzero/events.jsonl"` appends
one JSON line per event — `{"delivery_id", "timestamp", "signature", "event"}` — to that path
(created 0600, never through a symlink). Use it as an audit trail or to feed a log shipper.

Rules the validator enforces:

- `url` must be `http://` or `https://` with a host (or `file://` with an absolute path, for
  endpoints only). Redirects are never followed.
- Every verdict hook must state `fail_mode`. There is no default, on purpose: if the line is
  missing the config does not load.
- Verdict hooks can only subscribe to kernel-observed event types (`file_*`, `process_*`,
  `network_*`, `dns_query`, `mprotect_wx`). LLM/proxy events are stream-only.
- Regexes in `redaction.patterns` must compile.
- Names must be unique. A `secret`, if present, must be non-empty. Endpoints without a secret
  work but log a warning at startup — deliveries are then unsigned.

## Which events are sent

Every event the daemon attributes to an AI agent session, from four sources:

- **Kernel** (eBPF LSM): `file_open`, `file_create`, `file_delete`, `file_rename`,
  `process_exec`, `network_connect`, `network_send`, `dns_query`, `mprotect_wx`. `file_open`
  is only reported for protected or sensitive file names (the kernel discards the rest to keep
  the volume sane); the other kinds are reported for every operation of a monitored process.
- **Agent hooks** (`rz-hook`, installed into Claude Code and Codex by the package): the
  agent's tool calls as `llm_tool_call`, with `args.action` normalized to `file_read`,
  `file_write`, `file_edit`, `process_exec`, `file_search`, `network`, `delegate` or `other`,
  plus `args.tool_input` / `args.tool_response` (bounded to 16 KiB per string), `args.hook`
  (`PreToolUse` / `PostToolUse`), `args.phase` (`pre` / `post`), `args.cwd`,
  `args.transcript_path` and `args.agent_session_id`. Prompts and responses arrive as
  `llm_request` / `llm_response`. This is the layer that sees *what the agent intends to
  write* (file path and content) before the kernel sees the resulting syscalls.
- **TLS capture** (SSL uprobes and the local gateway): `llm_request`, `llm_response`,
  `llm_tool_call`, `prompt_injection`, `offensive_prompt`, `dlp_pii`, `proxy_block`.
- **Transcripts** (opt-in, `[transcripts] enabled = true`): `transcript_write` whenever lines
  are appended to an agent's session file (`~/.claude/projects/**/*.jsonl`,
  `~/.codex/sessions/**/*.jsonl`, `~/.gemini/tmp/**/*.json`, plus `extra_dirs`), with
  `args.lines` (the appended lines, each cut at 4 KiB), `args.transcript` and `args.agent`.
  The daemon never persists transcript content; it is only forwarded.
- **Daemon detections** as `event_type = "threat"`: attack chains, unsafe launch flags
  (`yolo_flag_detected`), shell-config tamper (`config_tamper`), privilege escalation,
  exfiltration scoring, injection findings in skill files, verdict-hook denies
  (`verdict_hook_deny`).

Events from processes that are not part of an agent session are not sent.

## Event schema (version 1)

One event per `POST`, `Content-Type: application/json`. Additive fields may appear within the
same `schema_version`; a breaking change bumps it.

```json
{
  "schema_version": 1,
  "id": "48213-1758326400123456789",
  "timestamp": "2026-09-20T09:00:00.123456789+00:00",
  "host": "dev-laptop",
  "event_type": "file_open",
  "agent": {
    "session_id": "auto-claude-48201",
    "agent_type": "claude",
    "process": "cat",
    "pid": 48213,
    "ppid": 48201,
    "parent_process": "claude",
    "uid": 1000
  },
  "args": {
    "target": "id_rsa",
    "path": "id_rsa"
  },
  "verdict": {
    "allowed": false,
    "reason": null
  }
}
```

Field notes:

- `event_type` is one of `file_open`, `file_create`, `file_delete`, `file_rename`, `file_write`,
  `process_exec`, `process_fork`, `process_exit`, `network_connect`, `network_send`,
  `network_recv`, `dns_query`, `mcp_tool_call`, `llm_request`, `llm_response`, `llm_tool_call`,
  `proxy_block`, `proxy_detection`, `dlp_pii`, `tamper_*`, `contained_*`, `offensive_prompt`,
  `prompt_injection`, `mprotect_wx`, `attack_chain`, `skill_file_change`, `skill_git_repo_drop`,
  `transcript_write`, or `threat`.
- `agent.session_id` / `agent.agent_type` are `null` when the daemon could not attribute the
  event to a session (rare; events are only sent for agent sessions).
- `args.target` is always present. For file events `args.path` repeats it (the kernel reports
  the final path component of the opened file). For network events `args.remote_ip` and
  `args.remote_port` are added. For `process_exec` `args.cmdline` holds the command line
  (redact or drop it if that is sensitive in your environment). When the daemon has correlated
  an LLM response with the event, `args.llm_context` is present.
- For `threat` events `args` is the daemon's detection payload as-is (free-form, keyed by
  `type`), and `verdict.allowed` is `null`.
- `verdict.allowed` is the daemon's decision at the time the event was published. For events
  decided by a verdict hook, `verdict.reason` starts with `[verdict hook <name>]`.

## Delivery headers and signature

Every request carries:

```
Content-Type:          application/json
User-Agent:            ringzero-daemon/<version>
X-RingZero-Schema:     1
X-RingZero-Event:      file_open
X-RingZero-Delivery:   4a3d7c3e-…            (random per attempt)
X-RingZero-Timestamp:  1758326400            (unix seconds, when the request was built)
X-RingZero-Signature:  v1=<hex>              (only when the endpoint has a secret)
```

The signature is `HMAC-SHA256(secret, "<X-RingZero-Timestamp>.<raw body>")`, hex encoded.
Verify it with a constant-time comparison and reject stale timestamps (a few minutes is a
sensible window) to stop replays:

```python
import hmac, hashlib, time

def verify(secret: bytes, headers, body: bytes, max_age=300) -> bool:
    ts = headers.get("X-RingZero-Timestamp", "")
    sig = headers.get("X-RingZero-Signature", "")
    if not ts.isdigit() or abs(time.time() - int(ts)) > max_age:
        return False
    expected = "v1=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)
```

Delivery semantics for the stream: each endpoint has its own bounded queue and sender task.
The event pipeline only ever does a non-blocking enqueue; a full queue drops the event and
increments `dropped_queue_full`. A `2xx` response is a success. `5xx`, `408`, `429`, and
connection errors are retried with exponential backoff; other `4xx` responses are not. There is
no batching and no ordering guarantee across endpoints.

## Verdict hooks

For each event whose type a hook subscribes to, the daemon POSTs the same payload (same
headers, same redaction) and waits up to `timeout_ms` for:

```json
{ "verdict": "allow" }
```
or
```json
{ "verdict": "deny", "reason": "credential read outside project dir" }
```

Anything else — a non-`2xx` status, a body over 64 KiB, JSON without `verdict`, an unknown
verdict value, a timeout, a connection error — is a *failure*, and the hook's `fail_mode`
decides: `open` allows the event, `closed` denies it. Every verdict and every failure is
logged (`journalctl -u ringzero-daemon | grep 'verdict hook'`) with the hook name, event type,
outcome, source (`receiver`, `fail_open`, `fail_closed`) and latency, and denies are written to
the audit log.

What a **deny** does: the event is marked blocked (`verdict.allowed = false`, reason
`[verdict hook <name>] …`), an audit entry and a `threat` event (`type: verdict_hook_deny`)
are written, and when the daemon runs in `enforce` mode it terminates the offending process
(`SIGKILL`, after re-checking the PID still belongs to the same process) and pushes a kernel
block rule for the event's target. For file events that rule is the file name (and, for
absolute paths, the file's inode), so the next open is refused inside the kernel. For network
events the remote IP is added to the kernel's block list, but in this release the
`socket_connect` hook only records connections and does not refuse them — the process
termination is the effective action there. In `observe` mode the deny is recorded and
broadcast but nothing is killed.

Be clear about what a sync hook can and cannot do. The kernel component decides each syscall
from its policy maps *inside the kernel*, without waiting for userspace; by the time the daemon
sees an event, that syscall has already been allowed or denied by the eBPF LSM programs. The
verdict hook therefore gates the daemon's release of the event and everything downstream
(process termination, kernel block rules for further attempts, session state, alerts, the event
stream) — it does not make the kernel hold the first in-flight syscall. If you need a file to be
unreadable from the very first attempt, use a file-access rule (`rz file-access add`), which is
enforced in-kernel.

Operational notes:

- Hooks are on the daemon's event hot path and are called sequentially in config order (first
  `deny` wins). Keep receivers fast and local. A hook pointed at a non-local address logs a
  warning at startup; remote ML systems should consume the async stream.
- After 5 consecutive failures a hook's circuit opens for 10 s: during that window the fail mode
  is applied immediately without calling the receiver, and the state change is logged.
- Verdict-gated events are processed one at a time, so a slow receiver stalls the daemon's
  event pipeline by up to `timeout_ms` per event. Timeouts and errors open the breaker after
  five in a row; a receiver that answers slowly but successfully never trips it, so keep local
  receivers fast. A receiver can never bypass a kernel-side block, and with
  `fail_mode = "closed"` it can only make things stricter.
- Verdict responses are parsed strictly; nothing in the response other than `verdict` and
  `reason` is used, and `reason` is only logged.

## Stats

`GET /api/v1/webhooks/stats` (bearer token, like every other API call) returns counters:
`enqueued`, `dropped_queue_full`, `delivered`, `delivery_failed`, `verdict_allow`,
`verdict_deny`, `verdict_failed`, plus the configured endpoint and hook names.

```sh
curl -s -H "Authorization: Bearer $(cat ~/.config/ringzero/api-token)" \
  http://127.0.0.1:7700/api/v1/webhooks/stats
```

## Example receivers

Two runnable receivers ship in [`guardrails/`](../guardrails/): `template/` (stdlib Python; edit
`policy.py::decide()`) and `nemo-guardrails/` (runs each event through NeMo Guardrails input
rails). Both verify signatures the way described above and come with a signed test script. The
minimal one below is the same idea in one file.

### Minimal receiver

A minimal receiver that verifies signatures, prints stream events, and answers verdict
requests. It denies any `file_open` of a `.pem` file and allows everything else.
Save as `receiver.py` and run `python3 receiver.py` (listens on 127.0.0.1:8081).

```python
#!/usr/bin/env python3
import hashlib, hmac, json, time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = b"change-me-32-bytes-of-randomness"

def verify(headers, body):
    ts = headers.get("X-RingZero-Timestamp", "")
    sig = headers.get("X-RingZero-Signature", "")
    if not ts.isdigit() or abs(time.time() - int(ts)) > 300:
        return False
    expected = "v1=" + hmac.new(SECRET, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if not verify(self.headers, body):
            self.send_response(401); self.end_headers(); return
        ev = json.loads(body)
        if self.path == "/events":                       # async stream
            print("event", ev["event_type"], ev["agent"]["process"], ev["args"].get("target"))
            self.send_response(204); self.end_headers(); return
        if self.path == "/verdict":                      # sync hook
            deny = ev["event_type"] == "file_open" and str(ev["args"].get("path", "")).endswith(".pem")
            reply = {"verdict": "deny", "reason": "pem read"} if deny else {"verdict": "allow"}
            out = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers(); self.wfile.write(out); return
        self.send_response(404); self.end_headers()

    def log_message(self, *a):  # keep stdout for events
        pass

HTTPServer(("127.0.0.1", 8081), Handler).serve_forever()
```

Point the daemon at it:

```toml
[[webhooks.endpoints]]
name   = "local-receiver"
url    = "http://127.0.0.1:8081/events"
secret = "change-me-32-bytes-of-randomness"

[[webhooks.verdict_hooks]]
name        = "local-receiver"
url         = "http://127.0.0.1:8081/verdict"
event_types = ["file_open"]
fail_mode   = "open"
secret      = "change-me-32-bytes-of-randomness"
```

then `sudo systemctl reload ringzero-daemon`. You can also poke the receiver by hand with a
signed request, exactly as the daemon would:

```sh
BODY='{"schema_version":1,"id":"t-1","timestamp":"2026-09-20T09:00:00Z","host":"x","event_type":"file_open","agent":{"session_id":"s","agent_type":"claude","process":"cat","pid":1,"ppid":0,"parent_process":"claude","uid":1000},"args":{"target":"server.pem","path":"server.pem"},"verdict":{"allowed":true,"reason":null}}'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac 'change-me-32-bytes-of-randomness' | awk '{print $NF}')
curl -s -X POST http://127.0.0.1:8081/verdict \
  -H 'Content-Type: application/json' \
  -H "X-RingZero-Timestamp: $TS" -H "X-RingZero-Signature: v1=$SIG" \
  -H 'X-RingZero-Event: file_open' -d "$BODY"
# → {"verdict": "deny", "reason": "pem read"}
```

## Example: feeding an external ML scoring service

An ML backend usually wants the full event history, not a 250 ms decision. Use the async
stream for that, and — only if you need real-time blocking — a *local* verdict hook that
consults a cached model score:

```toml
# 1. Ship every agent event to the scoring service (can be remote; signed; redacted).
[[webhooks.endpoints]]
name        = "ml-scoring"
url         = "https://ml.example.com/v1/ringzero/events"
secret      = "…"
event_types = ["*"]

[[webhooks.verdict_hooks]]
# 2. Optional: a small local sidecar that holds the latest per-session risk score the
#    ML service pushed back to it, and answers deny when the score is over a threshold.
#    It runs on this host, so it answers within the 250 ms budget; if it is down the
#    daemon fails open and the kernel-side rules still apply.
name        = "ml-sidecar"
url         = "http://127.0.0.1:8090/verdict"
event_types = ["process_exec", "network_connect"]
timeout_ms  = 250
fail_mode   = "open"

[webhooks.redaction]
drop_fields = ["args.cmdline", "args.llm_context"]   # keep prompts and full command lines local
```

Set `fail_mode = "closed"` on the sidecar instead if a missing score should block; the
kernel-side blocks configured with `rz file-access` are unaffected either way.
