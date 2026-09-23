# review — the queue that collects labelled data

Every kernel denial and every check flag lands here with its full trace
attached, and a human sets one label: `benign`, `real-threat`, or
`false-positive`.

There is no model in this component, by design. This is a table and a small
API, useful on day one because a person can read it, and it is how the labelled
denials that future triage and correlation models need get collected. Those
models are not in this release; see `models/README.md`.

## Implementation

The queue is a sled tree inside the agent, because it shares the agent's
storage and lifecycle: `agent/src/review.rs`. It is documented here because the
queue is an interface, not an internal detail.

Items live at `/var/lib/ringzero/review` (root) and are listed newest first.

## API

| Method | Path | Does |
|---|---|---|
| `GET` | `/api/v1/review?limit=100&unlabeled_only=true` | The inbox. Labelled items drop out by default. |
| `GET` | `/api/v1/review/stats` | Totals, and how labelled items came out. |
| `POST` | `/api/v1/review/{id}/label` | Body `{"label": "real-threat"}`. |

Reading the queue needs any valid token. Labelling is a mutating call, so it
needs the full-scope token — `sudo rz ...` or a root-side caller, not the
read-only token the installer leaves in the operator's home.

## Item shape

```json
{
  "id": "18446744073709551615-9f2c1a04",
  "created": "2026-09-21T09:14:22.318Z",
  "source": "kernel_deny",
  "session_id": "auto-claude-48201",
  "summary": "kernel denied FileOpen on '/home/dev/.aws/credentials' by cat (pid 48233)",
  "trace": { "…": "the full trace record" },
  "label": null,
  "labeled_at": null
}
```

`session_id` is the join key: the same key the kernel's events and the checks'
results carry, so one labelled item can be lined up against everything else
that happened in that agent run.
