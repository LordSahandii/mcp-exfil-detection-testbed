# Understanding the logs

Everything the testbed records lands under `logs/`. There are three kinds of
artifact, kept deliberately separate (raw capture → derived features → results),
plus the out-of-band prompt capture.

```
logs/
  raw/            <- 1 line per MCP message, byte-faithful (the proxy writes this)
    <server>.<label>.jsonl
  prompts.jsonl   <- user prompts (the proxy CANNOT see these; captured separately)
  opencode_events.jsonl  <- raw OpenCode message/tool events (plugin, for audit)
  features/
    calls.csv / calls.jsonl   <- 1 row per tool call + derived signals (the dataset)
    run_policy.jsonl          <- the authorized task policy per run (ground truth)
    sink_receipts.jsonl       <- what actually reached the sink (exfil ground truth)
  reports/
    baseline.json             <- per-tool benign statistics
    threshold_table.csv       <- per-tool size thresholds
    detections.jsonl          <- per-run alerts + evidence + prompt
    metrics.json              <- precision / recall / FPR
    channel_capacity.json     <- bytes-before-alert per sweep config
    report.md                 <- human-readable summary
```

File names in `raw/` are `<server_id>.<label>.jsonl`, e.g. `git.attack.jsonl`,
`filesystem.opencode.jsonl`. **label** = where the traffic came from
(`benign`, `attack`, `sweep`, `opencode`).

---

## 1. `logs/raw/<server>.<label>.jsonl` — raw MCP telemetry

One JSON object per MCP message, in both directions. This is the primary capture:
the proxy relays the bytes unchanged and writes a copy with metadata. Example
(a `tools/call` response):

```json
{
  "experiment_id": "mcp-baseline", "run_id": "attack-E2-003",
  "scenario_id": "E2", "server_id": "filesystem", "label": "attack",
  "connection_id": "3944af26710f", "timestamp_utc": "2026-10-27T06:34:39.978Z",
  "direction": "s2c", "kind": "response", "jsonrpc_id": 4, "method": "tools/call",
  "tool_name": "read_file", "tool_arguments": null, "operation_class": "read",
  "content_text_len": 50, "content_preview": "SYNTHETIC_SECRET ...",
  "content_truncated": false, "tools_digest": null,
  "is_error": false, "latency_ms": 5.65,
  "payload_bytes": 140, "payload_sha256": "377750fb..."
}
```

| field | meaning |
|---|---|
| `experiment_id` | fixed experiment tag (`mcp-baseline`) |
| `run_id` | groups all calls of one task/session (join key across servers) |
| `scenario_id` | E1–E6, `benign`, `CAP` (sweep), or `opencode` |
| `server_id` | which upstream server (`filesystem`, `git`, `memory`, `sink`, `poisoned`) |
| `label` | traffic class (`benign` / `attack` / `sweep` / `opencode`) |
| `connection_id` | one proxy↔server connection; unique per server process |
| `timestamp_utc` | when the message was seen |
| `direction` | `c2s` = client→server (request), `s2c` = server→client (response) |
| `kind` | `request`, `response`, `error`, or `notification` |
| `jsonrpc_id` | JSON-RPC id; pairs a request with its response **within one connection** |
| `method` | MCP method (`initialize`, `tools/list`, `tools/call`, `notifications/...`) |
| `tool_name` | for `tools/call`: which tool |
| `tool_arguments` | for requests: the full arguments object |
| `operation_class` | coarse intent we derive: `read` / `mutate` / `egress` / `other` |
| `content_text_len` | length of text content in a response (full, even if preview is cut) |
| `content_preview` | first 800 chars of response text (bounded, for the feature layer) |
| `content_truncated` | true if the real content was longer than the preview |
| `tools_digest` | for `tools/list`: `[{name, description_sha, schema_sha}]` (E3 poisoning) |
| `is_error` | response carried `isError: true` |
| `latency_ms` | request→response time (on the response row) |
| `payload_bytes` | size of this exact JSON-RPC line |
| `payload_sha256` | integrity hash of the raw line |

**How to correlate:** a request and its response share `(connection_id,
jsonrpc_id)`. All calls of one task share `run_id`. `jsonrpc_id` is **not** unique
across connections — always pair within a `connection_id`.

---

## 2. `logs/prompts.jsonl` — the prompts (captured out-of-band)

The proxy sits on the MCP channel and **never sees your prompt** — the prompt
goes from you to the LLM, a different channel. So prompts are captured two ways,
both writing here and both joinable to the MCP calls by `run_id`:

- **`opencode_batch.ps1`** (`source: "batch"`): logs each headless prompt and sets
  a matching `MCP_RUN_ID`, so the proxy stamps the same `run_id` on every MCP call.
- **the OpenCode plugin** (`source: "plugin"`, `.opencode/plugins/prompt-logger.js`):
  captures user prompts live in the TUI too.

```json
{"run_id":"oc-...-01","label":"opencode","source":"batch","role":"user",
 "timestamp_utc":"2026-10-27T08:21:36Z","text":"summarize the last 3 git commits"}
```

`analysis/analyze.py` reads this and attaches `prompt` to each run in
`detections.jsonl` (preferring the clean batch text, de-duped).

> Note: the deterministic drivers (`run_benign.py` / `run_attacks.py`) have no
> natural-language prompt — their "intent" is the task policy in `run_policy.jsonl`.

## 3. `logs/opencode_events.jsonl` — raw OpenCode events

Written by the plugin: raw `message.updated`, `message.part.updated`, and
`tool.execute.before` events. This is an audit/debug stream (it shows the model's
reasoning turns and assistant text); `prompts.jsonl` is the cleaned version.

---

## 4. `logs/features/`

- **`calls.csv` / `calls.jsonl`** — the **dataset**: one row per `tools/call`
  (request joined to response), with the raw metrics plus derived boolean signals
  (`sig_injection_in_output`, `sig_canary_in_output`, `sig_canary_in_args`,
  `sig_egress`, `sig_traversal_attempt`, `sig_boundary_denied`,
  `sig_tools_changed_in_session`, `sig_mutate_after_read`, `sig_cross_workspace`)
  and `prev_tool`. This is what you'd train/evaluate a detector on.
- **`run_policy.jsonl`** — the authorized task policy per run: `task_intent`
  (`read_only`/`read_write`), `allow_egress`, `allowed_write_roots`,
  `scope_workspace`, `approved_destinations`. This is **ground truth for intent**,
  not an observation — the detector compares behaviour against it.
- **`sink_receipts.jsonl`** — independent exfil ground truth: for every
  `send_report`, the destination, byte count, sha256, and which canary markers were
  present. This is how we tell "attempted send" from "data actually left".

## 5. `logs/reports/`

- **`baseline.json`** — per-`server.tool` benign stats (n, median, MAD, mean, std,
  p95, p99, max) for `request_bytes`, `response_bytes`, `content_text_len`,
  `latency_ms`, plus `calls_per_run`. This is RQ1: the envelope of normal traffic.
- **`threshold_table.csv`** — the same thresholds flattened to a table.
- **`detections.jsonl`** — one row per run: `alerted`, `rules_fired`,
  `max_evidence_level`, `bytes_before_alert`, `evidence[]`, `observations[]`, and
  (for OpenCode runs) the `prompt`.
- **`metrics.json`** — precision, recall, FPR, per-scenario recall (benign vs
  attack only; `sweep`/`opencode` runs are excluded from these numbers).
- **`channel_capacity.json`** — per sweep config, bytes-before-alert under three
  detector layers (L0 protocol-only, L1 +content markers, L2 +destination policy).
- **`report.md`** — the human-readable roll-up of all of the above.

---

## Quick recipes

```bash
# every tool call in one run, in order, across all servers:
#   filter logs/features/calls.jsonl by run_id, sort by timestamp.

# the prompt behind a flagged run:
#   look up run_id in logs/reports/detections.jsonl -> "prompt".

# did data actually leave in an E2 run?
#   check logs/features/sink_receipts.jsonl for canary_markers_found.
```
