# Design decisions & recommendations

## 1. Proxy: build our own thin logging proxy (chosen) vs. existing projects

**Decision: build our own** — `proxy/logging_proxy.py` (~200 lines, stdlib only).

Why not the two you found:

- **`sparfenyuk/mcp-proxy`** is primarily a *transport bridge* (stdio ⇄ SSE/HTTP).
  Its job is protocol translation, not capture/feature extraction. Our design
  (Mia's report §2.1) explicitly wants to **preserve stdio end-to-end** and avoid
  translation, and it has no structured per-message telemetry layer.
- **FastMCP proxy (`FastMCP.as_proxy`)** mounts an upstream server and re-emits
  messages through its own MCP machinery. That **re-serializes** JSON-RPC bodies,
  which conflicts with the "minimally-modified raw capture" requirement, and it
  pulls in a large dependency for something we need to be transparent.

Our proxy instead owns the child process and relays the raw stdio bytes
unchanged, logging a copy. That is exactly what the project design calls for
("the proxy must own the child process and forward both request and response
streams") and it is small enough to audit and pin. It is also client-agnostic:
it wraps *any* stdio MCP server — our lab servers today, the official
`@modelcontextprotocol/*` servers tomorrow (see `config/opencode.json`).

If you later need HTTP transport, keep this proxy for capture and put
`mcp-proxy` *outside* it for the stdio⇄HTTP hop — the two compose.

## 2. Client: OpenCode vs Claude Desktop

**Recommendation: OpenCode** as the primary client; Claude Desktop supported as a
secondary (config provided).

| Factor | OpenCode | Claude Desktop |
|---|---|---|
| Reproducibility / scripting | CLI-driven, easy to automate repeatable task batches | GUI-only, manual |
| Prompt capture | Plugin can log user prompts (you mentioned this) | Not readily |
| Model flexibility | Local Qwen (Ollama) **or** OpenRouter | Anthropic models |
| MCP config | `type: local` stdio, matches our proxy | `mcpServers` stdio, also works |
| Fits the proposal | Matches your team's OpenCode-based logs already | — |

For a *reproducible research testbed* where you drive repeatable tasks and want
prompt-level capture, OpenCode wins. Use Claude Desktop only for spot-checking
ecological validity. **Note:** the LLM-in-the-loop path is for realism; the
deterministic drivers (`run_*.py`) are what guarantee a clean labelled dataset on
schedule, independent of model flakiness.

## 3. Why a deterministic driver *and* a live-LLM path

A live small Qwen on 8 GB CPU is slow and non-deterministic — fine for realism,
risky for "deliver a dataset tomorrow." The deterministic MCP client
(`common/mcplite.py` + `scenarios/*`) executes the fixed task library directly
through the proxy, producing reproducible, labelled traces now. The same proxy
and servers are reused unchanged under OpenCode for live runs, so the two corpora
are directly comparable.

## 4. Detector design rationale

- **Policy-aware + correlation-based.** An observed request is not a compromise.
  We attach an authorized task policy per run (`task_intent`, `allow_egress`,
  `allowed_write_roots`, `scope_workspace`, `approved_destinations`) and only
  alert on policy violations or corroborated content signals. This is what keeps
  benign FPR at 0 on the pilot set while still catching all six families.
- **Four evidence levels.** Every alert is tagged 1–4 (content → action → accepted
  → independently verified). A refused out-of-root read (E4) is an *attempt*,
  never a confirmed bypass.
- **Layered channel-capacity model (L0/L1/L2).** Separates what protocol-only
  features can catch from what needs content or policy awareness.

## 5. Limitations (state these in the paper)

- Pilot scale (20 benign iters × 6 task types; 20 × 6 attack runs; sweep × 3).
  Perfect separation reflects clean synthetic fixtures, **not** production
  reliability. Scale up repetitions, payload variants, and task diversity before
  any strong claim.
- The proxy sees MCP traffic only — not the user prompt, model reasoning,
  OpenCode built-in tools, server-internal file ops, or real network egress.
  Capture those separately when needed.
- stdio ≠ sandboxing. Restrict filesystem privileges and outbound network at the
  OS level for live runs.
- The volume budget in the capacity study is a chosen operating point, not a
  derived FP budget; sweep it against the benign distribution for the final table.

## 6. Suggested next steps

1. Scale corpora (`-Runs 50 -SweepRepeats 10`) and add payload/task variants.
2. Add a real benign egress baseline from live OpenCode runs; recompute the sink
   size envelope from that distribution.
3. Add rate/inter-arrival features (timestamps are already captured) for a true
   low-and-slow detector and a time-based volume budget.
4. Wrap the **official** MCP servers (flip `filesystem-official` to enabled) and
   measure cross-server transfer of the detector.
5. Ship the detector as an OpenCode/proxy plugin (the detector logic in
   `analysis/analyze.py:detect` is already self-contained).
