# MCP Traffic Baselining & Exfiltration Detection — Testbed

CMPT 782 — Cybersecurity Lab 1 (Fall 2026). A reproducible, **local, synthetic**
testbed that routes MCP traffic through an instrumented proxy, builds a benign
baseline, generates labelled E1–E6 attack traffic, and evaluates an interpretable
detector — including a tunable exfiltration sweep that measures channel capacity.

> Everything runs offline on the Python standard library. All data is synthetic
> lab canaries. The "sink" performs **no network egress** — it records local
> receipts only. Attack fixtures operate solely against the local lab.

---

## 1. Architecture

```
  scenario driver / OpenCode / Claude Desktop         (MCP client)
                     |  stdio (newline-delimited JSON-RPC)
                     v
          proxy/logging_proxy.py                        <-- captures every message
                     |  stdio                               to logs/raw/*.jsonl
                     v
          servers/*.py  (filesystem, git, memory, sink, poisoned)   (MCP servers)
```

The proxy **owns the upstream server process** and relays both streams
byte-for-byte, so JSON-RPC bodies are never mutated (minimally-modified raw
capture). Telemetry goes to a JSONL file and stderr — never the stdout JSON-RPC
channel.

## 2. Quick start

```powershell
# from F:\project0\MCP-Project
powershell -ExecutionPolicy Bypass -File run_all.ps1 -Fresh
```

That builds the lab, generates benign + attack + sweep corpora, and writes the
report. Open **`logs/reports/report.md`**.

Run pieces individually:

```powershell
python scenarios/build_lab.py   --lab-dir lab
python scenarios/run_benign.py  --runs 20
python scenarios/run_attacks.py --runs 20          # or: --only E1 E2
python scenarios/exfil_sweep.py --repeats 3
python analysis/analyze.py
```

## 3. What gets produced

| Path | Contents |
|---|---|
| `logs/raw/<server>.<label>.jsonl` | Raw per-message telemetry (identity, correlation, tool data, integrity) |
| `logs/features/calls.csv` / `.jsonl` | Per-call feature rows + derived detection signals (the **dataset**) |
| `logs/features/run_policy.jsonl` | Per-run authorized task policy (ground truth) |
| `logs/features/sink_receipts.jsonl` | Independent exfil ground truth (what actually reached the sink) |
| `logs/reports/baseline.json`, `threshold_table.csv` | Per-tool benign statistical envelope (RQ1) |
| `logs/reports/detections.jsonl` | Per-run alerts with 4-level evidence |
| `logs/reports/metrics.json` | Precision / recall / FPR / per-scenario recall |
| `logs/reports/channel_capacity.json` | Bytes-before-alert per sweep config (RQ4/RQ5) |
| `logs/reports/report.md` | Human-readable summary of everything |

## 4. Components

- **`proxy/logging_proxy.py`** — the instrumented stdio logging proxy. Client-
  agnostic: wrap any stdio MCP server with `-- <command>`.
- **`servers/`** — lab MCP servers:
  - `fs_server.py` — filesystem with a strict allowed root (E2/E4/E6).
  - `git_server.py` — wraps the system `git` CLI (E1/E5).
  - `memory_server.py` — workspace-tagged memory, non-enforcing by default (E6).
  - `sink_server.py` — local-only egress sink with receipts (E2 measurement).
  - `poisoned_server.py` — controlled tool poisoning / within-session rug pull (E3).
- **`scenarios/`** — `build_lab.py`, `run_benign.py`, `run_attacks.py`,
  `exfil_sweep.py`, and shared helpers (`labenv.py`, `common/mcplite.py`).
- **`analysis/analyze.py`** — extract → baseline → detect → report.

## 5. Experiment mapping (E1–E6)

| ID | Scenario | Server(s) | Detection signal | Evidence standard |
|---|---|---|---|---|
| E1 | Tool-output prompt injection | git + filesystem + sink | injected text in output **correlated with** a forbidden follow-on | compromise only if forbidden action occurs |
| E2 | Attempted data exfiltration | filesystem + sink | unapproved egress; canary in payload | attempt vs accepted vs sink-confirmed receipt |
| E3 | Tool poisoning / rug pull | poisoned | `tools/list_changed` + description/schema hash change | hash change ≠ malicious by itself |
| E4 | Path traversal | filesystem | out-of-root path request | refused = attempt (L2), not a confirmed bypass |
| E5 | Tool misuse | git + filesystem | mutate op under read-only task policy | misuse ≠ command injection |
| E6 | Context over-sharing | memory | cross-workspace marker vs task scope | shared graph alone ≠ auth flaw |

## 6. The detector (interpretable, policy-aware)

A run is alerted only when an action **violates the authorized task policy** or a
content signal is **corroborated** by a forbidden follow-on. Level-1 content
observations (e.g. injected text that is merely read) are logged but do not alert
on their own — this is what keeps the benign false-positive rate low.

Alerts carry a four-level evidence tag: **(1)** suspicious content observed,
**(2)** suspicious action requested, **(3)** action accepted/complete,
**(4)** independently verified (sink receipt). The channel-capacity sweep also
reports three detector layers: **L0** protocol-only (size+volume), **L1**
+content markers, **L2** +destination policy.

## 7. Driving traffic with a live LLM (optional, for ecological validity)

The deterministic drivers give you a clean labelled dataset immediately. To also
collect realistic agent traffic, point **OpenCode** at `config/opencode.json`
(it already wraps each server in the proxy) and run tasks with a local Qwen
(Ollama) or an OpenRouter model. A `config/claude_desktop_config.json` is also
provided. See `docs/DESIGN.md` for the OpenCode vs Claude Desktop recommendation.

## 8. Honesty about scope

These are **pilot** results on a controlled synthetic set: perfect separation
here reflects clean, distinct fixtures, not production reliability. The research
value is the methodology, the reproducible dataset, the per-tool threshold table,
and the **documented blind spots** (low-and-slow marker-free exfil under the
size envelope; content-dependent E1/E6). See `docs/DESIGN.md` for limitations.
