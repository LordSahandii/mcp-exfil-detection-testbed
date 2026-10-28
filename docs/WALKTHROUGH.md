# Walkthrough: the process, the `logs/` folder, and the live-run reports

This document explains, end to end, **what the testbed does**, **how data flows
through it**, and **what every file under `logs/` means** — plus the two curated
live-run write-ups in `samples/`. It is the "read this first" companion to
[`DESIGN.md`](DESIGN.md) (the why) and [`LOGS.md`](LOGS.md) (the exhaustive
field-by-field dictionary).

---

## 1. What this project is, in one paragraph

We put a **transparent logging proxy** in front of a set of MCP (Model Context
Protocol) servers, drive both *benign* and *malicious* traffic through them,
and use the captured telemetry to answer two questions: **(RQ1)** what does
normal MCP traffic look like — the baseline envelope? and **(RQ2)** can a
policy-aware, correlation-based detector catch six attack classes (E1–E6)
without firing on benign work? Everything is synthetic: the "secrets" are inert
canary strings, the exfiltration sink performs **no** network egress, and
path-traversal is denied at the server. Nothing touches real data or the
network.

The six scenarios:

| id | attack class |
|----|--------------|
| **E1** | tool-output prompt injection (planted instructions in repo content) |
| **E2** | data exfiltration (read a secret, send it off) |
| **E3** | tool poisoning / "rug pull" (a tool's definition changes mid-session) |
| **E4** | path traversal (read outside the allowed root) |
| **E5** | tool misuse (mutating actions under a read-only task) |
| **E6** | context over-sharing (leaking one workspace's data into another) |

---

## 2. The end-to-end process

```
                   build_lab.py  ──▶  lab/  (workspace_a + secrets canary,
                                            workspace_b secret, public/,
                                            repo/ injected, repo_clean/)

   ┌──────────────────────── one task run (shares a run_id) ───────────────────────┐
   │                                                                                │
   │   CLIENT                         PROXY                        SERVER           │
   │   ┌──────────────┐   stdio   ┌──────────────┐   stdio   ┌──────────────────┐  │
   │   │ scripted     │◀────────▶ │ logging_proxy│◀────────▶ │ fs / git / memory│  │
   │   │ driver   OR  │  JSON-RPC │  relays bytes │  JSON-RPC │ sink / poisoned  │  │
   │   │ OpenCode+LLM │           │  UNCHANGED    │           └──────────────────┘  │
   │   └──────┬───────┘           └──────┬───────┘                                  │
   │          │ prompt (off-MCP)         │ writes a copy + metadata                 │
   │          ▼                          ▼                                          │
   │   logs/prompts.jsonl        logs/raw/<server>.<label>.jsonl                    │
   │   logs/opencode_events.jsonl  (+ run_policy.jsonl, sink_receipts.jsonl)        │
   └────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
                              analysis/analyze.py
                 extract  ──▶  baseline  ──▶  detect  ──▶  report
                    │             │             │            │
           features/calls.*  reports/      reports/     reports/
                            baseline.json  detections   metrics.json
                                           .jsonl        report.md
                                                         channel_capacity.json
```

Step by step:

1. **Build the lab.** `scenarios/build_lab.py` writes the synthetic world under
   `lab/`: `workspace_a/` (with the canary `secrets.txt`), `workspace_b/` (its
   own secret), `public/` (safe to touch), `repo/` (a git repo whose README,
   commit message, and `docs/NOTES.md` carry planted injection payloads — E1),
   and `repo_clean/` (injection-free, for benign git work).

2. **Wrap each server in the proxy.** `proxy/logging_proxy.py` owns the upstream
   server as a child process and sits on its stdio. It relays every JSON-RPC
   message **byte-for-byte unchanged** and writes a telemetry copy to
   `logs/raw/<server>.<label>.jsonl`. The proxy is the single point of capture.

3. **Generate traffic — two ways** (see §3). Either a *scripted* Python driver
   or a *live* OpenCode client + local LLM issues the MCP calls. Each task is one
   **run** with a `run_id` that is stamped on every message, so a run can be
   reassembled across servers.

4. **Record the ground truth.** For each run, `run_policy.jsonl` captures what
   the task was *authorized* to do (read-only vs read-write, egress allowed?,
   which write roots, which workspace, approved destinations). The sink
   independently records `sink_receipts.jsonl` — what actually arrived at the
   egress endpoint.

5. **Analyze.** `analysis/analyze.py` runs four stages:
   - **extract** — join each request to its response and derive per-call signals →
     `features/calls.csv` + `calls.jsonl` (the dataset).
   - **baseline** — compute the robust statistics of *benign* traffic →
     `reports/baseline.json` (answers RQ1).
   - **detect** — score each run against the rules + its policy →
     `reports/detections.jsonl` (answers RQ2).
   - **report** — roll up precision/recall/FPR and the channel-capacity sweep →
     `reports/metrics.json`, `channel_capacity.json`, `report.md`.

### The detector in one breath

The detector is **policy-aware** (it compares behaviour to `run_policy.jsonl`,
so reading a secret is only an alert when the task wasn't authorized to) and
**correlation-based** (it groups calls by `run_id` and looks at *sequences* —
e.g. injection-in-output followed by a sensitive read, or a mutation after a
read under a read-only task). Each alert carries an **evidence level** so an
attempt is distinguished from a confirmed compromise.

---

## 3. Two sources of traffic (and the `label` that tells them apart)

Every raw log file is named `<server_id>.<label>.jsonl`. The **label** is the
single most important field for understanding a file — it says where the traffic
came from and therefore how to interpret it.

| label | source | tool calls are… | used for |
|-------|--------|-----------------|----------|
| `benign` | scripted driver `run_benign.py` | hand-authored, known-good | baseline + false-positive rate |
| `attack` | scripted driver `run_attacks.py` | hand-authored, known-bad | precision / recall (the benchmark) |
| `sweep` | scripted driver `exfil_sweep.py` | staged exfil of varying chunk size | channel-capacity curve |
| `opencode` | live OpenCode + LLM, mixed TUI/interactive | whatever the model decided | exploratory live capture |
| `opencode-benign` | live OpenCode, benign task set | whatever the model decided | live false-positive check |
| `opencode-attack` | live OpenCode, attack task set | whatever the model decided | live attack evidence |

**Why this split matters.** A scripted `attack` run *always* performs the bad
action by construction, so it measures "does the detector catch a known-bad
call." A live `opencode-attack` run only trips the wire *if the model actually
falls for the attack* — so it measures something different and complementary:
do real agents actually do the dangerous thing, and how often? That is why the
headline metrics are computed from `benign`/`attack` only, and the live runs are
reported separately (see §5).

---

## 4. The `logs/` folder, file by file

```
logs/
  raw/                         <- raw MCP telemetry, 1 line per message
    <server>.<label>.jsonl
  prompts.jsonl                <- the user prompts (captured out-of-band)
  opencode_events.jsonl        <- raw OpenCode event stream (audit)
  features/
    calls.csv / calls.jsonl    <- the dataset: 1 row per tool call + signals
    benign.json / malicious.json  <- calls split by label, enriched with
                                     prompt + request + response (derived)
    run_policy.jsonl           <- authorized task policy per run (ground truth)
    sink_receipts.jsonl        <- what actually reached the sink (exfil truth)
  reports/
    baseline.json              <- benign traffic statistics (RQ1)
    threshold_table.csv        <- per-tool size thresholds (flattened)
    detections.jsonl           <- per-run alerts + evidence
    metrics.json               <- precision / recall / FPR
    channel_capacity.json      <- bytes-before-alert per sweep config
    report.md                  <- human-readable roll-up
```

> **Note:** `logs/` is git-ignored — it is regenerated on every run. The
> committed, shareable snapshots live in `samples/`. Use `logs/` for live
> screen-shares; point teammates at `samples/` for anything they read on their
> own.

### 4.1 `raw/<server>.<label>.jsonl` — the primary capture

One JSON object per MCP message, both directions, written by the proxy as the
bytes pass through. This is the ground-level evidence everything else is derived
from. Key fields (full dictionary in [`LOGS.md`](LOGS.md)):

- `run_id` — groups every call of one task (the join key across all files).
- `direction` — `c2s` (client→server request) or `s2c` (server→client response).
- `method` / `tool_name` / `tool_arguments` — what was called and with what.
- `operation_class` — our coarse intent: `read` / `mutate` / `egress` / `other`.
- `content_preview` (bounded 800 chars) + `content_text_len` — the response text.
- `tools_digest` — a hash list of the advertised tools (how E3 rug-pull is seen).
- `latency_ms`, `payload_bytes`, `payload_sha256` — timing + integrity.

A request and its response pair up on `(connection_id, jsonrpc_id)`. There is
one raw file per `(server, label)` combination, and files are **append-only** —
re-running the same label adds more runs to the same file.

### 4.2 `prompts.jsonl` — the user prompts (captured out-of-band)

**The proxy never sees the prompt.** Your instruction goes from you to the LLM,
which is a different channel from the MCP tool traffic the proxy sits on. So the
prompt is captured separately and stitched back by `run_id`. Two sources write
here:

- `source: "batch"` — the PowerShell drivers logging the exact prompt they sent.
- `source: "plugin"` — the OpenCode plugin logging the user message the model
  actually received (works in the interactive TUI too).

The scripted `benign`/`attack` drivers have *no* natural-language prompt — their
intent lives in `run_policy.jsonl` instead — so they do not appear here.

### 4.3 `opencode_events.jsonl` — the raw OpenCode event stream

Written by the same plugin, this is the **unfiltered firehose** of everything
happening inside OpenCode: `message.updated` (role, model id, tokens, cost),
`message.part.updated` (streamed text chunks — user *and* assistant, re-emitted
as they grow), and `tool.execute.before` (the agent's own client-side record of
each tool call it is about to make). `prompts.jsonl` is the cleaned,
user-only, de-duplicated projection of this file. Use the events file for audit
("what did the model actually think and do?") and for a useful integrity check:
the `tool.execute.before` records are the agent's *intended* tool calls, which
you can compare against the proxy's on-wire record for the same `run_id` to
confirm the proxy missed nothing.

### 4.4 `features/calls.csv` and `calls.jsonl` — the dataset

One row per `tools/call` (request joined to its response), with the raw metrics
plus the derived boolean **signals** the detector reasons over:

| signal | fires when… |
|--------|-------------|
| `sig_injection_in_output` | a tool response contains instruction-like text |
| `sig_canary_in_output` | a canary marker appears in a response (list of which) |
| `sig_canary_in_args` | a canary appears in the *arguments* of a call (e.g. being sent) |
| `sig_egress` | the call is an egress/send operation |
| `sig_traversal_attempt` | arguments reference a path outside the allowed root |
| `sig_boundary_denied` | the server refused the call (e.g. traversal blocked) |
| `sig_tools_changed_in_session` | the advertised tool set changed mid-run (E3) |
| `sig_mutate_after_read` | a mutating call followed a read in the same run (E5) |
| `sig_cross_workspace` | a call touched a workspace outside the task's scope (E6) |

`prev_tool` records the previous tool in the run, so the detector can reason
about *sequences*. `.csv` and `.jsonl` carry the same rows — CSV for Excel,
JSONL for scripts.

**Split + enriched sets.** `analysis/split_dataset.py` reads `calls.jsonl` and
writes two JSON arrays — `benign.json` and `malicious.json` — bucketed by
ground-truth `label` (`benign`/`opencode-benign`/`opencode` vs
`attack`/`opencode-attack`/`sweep`). Each record keeps all the signals above and
adds three fields joined back from the other logs:
- **`user_prompt`** — the task text, from `prompts.jsonl` by `run_id` (`null` for
  the deterministic drivers, which have no natural-language prompt — their intent
  is in `run_policy.jsonl`).
- **`mcp_request`** — the tool-call arguments, as a JSON string.
- **`mcp_response`** — the response content as `[{"type":"text","text":...}]`,
  bounded to the proxy's 800-char preview (`mcp_response_truncated` flags longer).

These are the train/eval-ready files; regenerate them after any run with
`python analysis/split_dataset.py`.

### 4.5 `features/run_policy.jsonl` — the authorized-intent ground truth

Not an observation — a declaration of what each run was *allowed* to do. One row
per `run_id`: `task_intent` (`read_only` / `read_write`), `allow_egress`,
`allowed_write_roots`, `scope_workspace`, `approved_destinations`. The detector
compares observed behaviour against this; it is why "read a secret" is benign in
one run and an E2 alert in another.

### 4.6 `features/sink_receipts.jsonl` — the exfiltration ground truth

The sink is a local-only egress endpoint that records, for every `send_report`,
the `destination`, `payload_bytes`, `payload_sha256`, and which
`canary_markers_found` were present — **and transmits nothing over the network.**
This is how we distinguish "the agent *attempted* a send" (visible in the raw
log) from "data *actually left*" (a receipt here with canaries found).

### 4.7 `reports/` — the results

- **`baseline.json`** — per-`server.tool` benign statistics (n, median, MAD,
  mean, std, p95, p99, max) for request/response bytes, content length, latency,
  and calls-per-run. This is the RQ1 answer: the envelope of normal traffic.
- **`threshold_table.csv`** — those thresholds flattened to one table.
- **`detections.jsonl`** — one row per run: `alerted`, `rules_fired`,
  `max_evidence_level`, `bytes_before_alert`, the supporting `evidence[]` and
  `observations[]`, and (for OpenCode runs) the `prompt`. The detector scores
  **every** label here — including the live runs — even though only
  `benign`/`attack` feed the headline metrics.
- **`metrics.json`** — precision, recall, false-positive rate, and per-scenario
  recall, computed from the `benign`/`attack` benchmark only. Current result:
  **precision 1.0, recall 1.0, FPR 0.0** over 120 attack + 120 benign runs
  (E1–E6 each 20/20).
- **`channel_capacity.json`** — the exfil-sweep result: for each configuration
  (chunk size × marker present?), the mean/max **bytes that leak before an
  alert** under three detector layers — **L0** (protocol-only), **L1** (+content
  markers), **L2** (+destination policy). The headline finding: with small,
  marker-free chunks, L0 and L1 let ~2008–2009 bytes through before the volume
  budget (2048 B) trips, whereas **L2 catches at byte 0** because the destination
  is unauthorized regardless of content.
- **`report.md`** — the human-readable roll-up of all the above.

---

## 5. The two live-run reports in `samples/`

These are **curated, committed write-ups of the live OpenCode runs** — the part
of the project that uses a real model (qwen2.5:14b via Ollama) instead of a
script. They exist because `logs/` is git-ignored: these two files preserve the
live evidence in the repo so teammates can read it without re-running anything.

### 5.1 `samples/opencode_live_demo.md` — the first, broad demo

A snapshot of `scenarios/opencode_demo.ps1`: **4 benign + 6 attack (one per
E1–E6)** tasks driven live through OpenCode. It contains three tables:

1. **What the live model actually did** — the captured tool-call sequence per
   task (e.g. E2: `read_file secrets.txt` → `send_report` → exfil endpoint).
2. **Detector results** — which runs alerted and which rules fired; the 4 benign
   runs produced **zero** false positives.
3. **Findings** — notably that E1 prompt injection *succeeded* against the live
   model (it read an unrelated secret because the repo README told it to), while
   E4 path traversal was *refused* by the model (a correct no-alert, not a miss).
   It also records the two detector improvements that came out of this run.

Read this one for the **"does the whole thing work against a real model?"**
story — one clean example per scenario.

### 5.2 `samples/opencode_attack_variants.md` — the richer, multi-variant set

A snapshot of `scenarios/opencode_attacks.ps1`, which drives **15 payload
variants** so each attack family has more than one phrasing: 3 E1 injection
carriers (README / commit message / notes file), 3 E2 exfil channels (URL /
IP:port / stage-to-file), 3 E4 traversal paths, 2 E3 rug-pull phrasings, 2 E5
misuse mutations, 2 E6 over-sharing queries. It contains:

1. **A per-variant results table** — what the model did for each of the 15 and
   how it was detected.
2. **A summary** — 11/15 took a detectable attack action and were flagged; 3
   (all E4) were refused by the model; 1 (E1/notes) exposed a detector gap.
3. **Findings** — the research-relevant observations: prompt injection is robust
   across *all three* carriers; the model refuses overt traversal but complies
   with injection-driven reads (an asymmetry that is itself a result); and the
   **attempt-vs-verified-outcome gap** — in the E1/notes variant the agent
   *followed* the injection but the forbidden read *failed*, so with no
   canary-in-output and no egress the current E1 rule did not fire. That gap is
   the documented next detector feature: correlate injection-in-output with any
   later request whose arguments reference a sensitive path, even on failure.

Read this one for **"how robust is each attack, and where does the detector
stop?"** — the depth-and-limitations story.

### How the two relate

`opencode_live_demo.md` is the **one-example-per-scenario** proof the pipeline
works end-to-end against a live model; `opencode_attack_variants.md` is the
**many-variants-per-scenario** stress test that surfaces robustness and the one
honest gap. Together they are the live-model counterpart to the scripted
benchmark in `reports/metrics.json`.

---

## 6. Reading one run end to end (worked recipes)

```bash
# 1. Pick a run and see every tool call it made, in order, across all servers:
#    filter logs/features/calls.jsonl by run_id, sort by timestamp_utc.

# 2. What was the agent told to do?
#    look up the run_id in logs/prompts.jsonl  (scripted runs: see run_policy.jsonl)

# 3. Was it authorized to do that?
#    look up the run_id in logs/features/run_policy.jsonl

# 4. Did the detector flag it, and why?
#    look up the run_id in logs/reports/detections.jsonl -> rules_fired + evidence[]

# 5. Did data actually leave in an E2 run?
#    check logs/features/sink_receipts.jsonl for canary_markers_found (non-empty = yes)
```

Those five lookups, all keyed by `run_id`, take you from "a task happened" to
"here is exactly what it did, whether it was allowed, whether we caught it, and
whether anything actually leaked" — which is the whole experiment in miniature.
