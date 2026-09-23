# checks — scoring what an agent is about to do

**Enforcement is deterministic. Models never decide the syscall.** Nothing in
this directory can allow or deny anything. A check returns one option from a
fixed set, a probability and a confidence; the result is written into the trace
and joined to the kernel's decision by `session_id`. Checks run off the hot
path, on agent hook events, never inside a file-open, exec or connect hook, and
the kernel never waits on one.

## Providers

| Provider | What it is | When it runs |
|---|---|---|
| `jev` (**default**) | TypeSafe's hosted System One model. Calibration comes from the model, and it returns typed answers with its own confidence. | Whenever the checks layer is enabled and a key is configured. |
| `deterministic` | Local rule-based scorers. Fixed weights, so results are repeatable and auditable, but **not calibrated** against labelled data. | When you select it, and automatically as the fallback whenever the hosted provider is unavailable. |

The deterministic scorer also runs as a **floor** under the hosted provider. It
costs microseconds, so it always runs; a model answer may raise a result to a
more severe option, and may never clear a flag or lower a score. That is
enforced in `merge_monotonic`, which is the only path a remote answer takes
into a result.

Every result records which provider produced it, and a fallback records why:

```json
{ "check": "tool_call_argument_risk", "option": "reads_sensitive_path",
  "probability": 0.9, "confidence": 0.9, "provider": "deterministic",
  "provider_error": "jev: 429 rate limited" }
```

## The checks in this release

| # | Check | Question type | Options |
|---|---|---|---|
| 3 | `tool_call_argument_risk` | `choice` | `benign`, `unapproved_network_host`, `writes_outside_workspace`, `reads_sensitive_path` |
| 5 | `sensitive_data_exposure` | `noul` | `none`, `possible_secret`, `secret_pattern_matched` |

A `noul` is a probability in [0,1]; it is mapped onto the fixed option set with
fixed thresholds, so the option space never grows.

## Configuration

Off by default. With the default provider, turning it on calls a third-party
API — see the privacy note below.

```toml
[checks]
enabled  = true
provider = "jev"                          # or "deterministic" to stay local
workspace = "/home/dev/project"
approved_hosts = ["registry.npmjs.org"]

[checks.jev]
api_key_file = "/etc/ringzero/typesafe.key"   # 0600, root-owned. Never a key in the config.
model        = "jev-latest"
timeout_ms   = 1500
```

If `provider = "jev"` and the key file is missing, unreadable, or readable by
group or others, **the checks layer refuses to start** and logs one error
naming the path. It does not silently downgrade to local scoring: an operator
who asked for a model must know they did not get one. The rest of the daemon
keeps running.

## Privacy

While `enabled = false` — the default — nothing here leaves your machine.

With `enabled = true` and `provider = "jev"`, each scored tool call sends to
`https://api.typesafe.ai`:

- the tool name and its arguments
- the workspace path and the approved-host list
- a **hash** of the task

all passed through the `[webhooks.redaction]` redactor first, so secrets the
redactor matches are masked before the request is built.

**Raw prompt text is never sent.** The task travels as a hash, and the trace
format forbids raw prompts. Set `provider = "deterministic"` to keep scoring
entirely on the machine.

The provider is an endpoint selected by `base_url`. In this release the default
points at a hosted API; the intended next step is a locally shipped fine-tuned
model serving the same contract, which removes the third-party call with no code
change. `provider = "deterministic"` keeps everything local today.

Failures fail safe: on timeout, 401, 422, 429, 529, a transport error, a
malformed body or a missing typed field, the deterministic result is used and
the reason is recorded in the trace. Nothing blocks waiting on the network.

## Planned — not in this release

| # | Check | Why it is not here |
|---|---|---|
| 1 | Prompt injection in the user's prompt | Not wired to a provider yet. |
| 2 | Injection in tool **results** | Needs the fetched content on the hook path. This is where real agent attacks enter; it matters more than check 1. |
| 4 | Task–action mismatch | Needs the task and the action together. Strongest agent signal. |
| 6 | Untrusted-flow-to-action | Needs taint from a low-trust input through to a consequential action. |

No model weights ship in this repository; the hosted provider is an API call.
See `models/README.md` for what local models would require.

## Skill and plugin scanning

Static skill scanning is a solved, commoditised problem and a skill file is a
public artifact, so there is no data advantage in training our own model for
it. The agent wraps a scanner and expresses its verdict as one score in the
trace rather than reimplementing it. See `NOTICE` for attribution.
