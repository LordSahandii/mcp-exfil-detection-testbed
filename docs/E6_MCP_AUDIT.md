# E6 context exposure + mcp-audit

How to reproduce the E6 (cross-workspace context exposure) results and the
[APIsec mcp-audit](https://github.com/apisec-inc/mcp-audit) comparison. Results
snapshot: [`samples/e6_results.md`](../samples/e6_results.md), full per-session log:
[`samples/e6_sessions.json`](../samples/e6_sessions.json).

## What each tool contributes

| | mcp-audit | this testbed (logging proxy) |
|---|---|---|
| when | before deployment | at runtime |
| reads | MCP config files (`mcpServers` JSON) and server source | every JSON-RPC message between client and server |
| E6 evidence | which servers are configured, keyword-based risk flags | B-labelled records/files returned, scope the agent asked for, the answer the user saw |

mcp-audit does **not** capture traffic, and it does not read OpenCode's
`opencode.json`, so `scenarios/e6_configs.py` writes a Claude-style `mcp.json`
mirror of each config for it to scan.

## 1. Install mcp-audit (pinned)

Keep it outside this repo, in its own venv (it has dependencies; the testbed is
stdlib-only). Use the commit the results were produced with:

```powershell
cd F:\project0
git clone https://github.com/apisec-inc/mcp-audit.git
cd mcp-audit
git config core.autocrlf false          # see note below
git checkout 6ae4e1ff58f3a75ca356fd173112770d217f59a3
git rm --cached -r -q . ; git reset --hard -q
cd ..
python -m venv mcp-audit-venv
mcp-audit-venv\Scripts\python -m pip install .\mcp-audit
```

`core.autocrlf=false` matters on Windows: with CRLF conversion the bundled
registry file's hash changes and mcp-audit warns that its registry "may have been
tampered with".

## 2. Run the E6 campaign

Needs Ollama running (`ollama serve`) with `qwen2.5:14b-24k` -- plain
`qwen2.5:14b` gets OpenCode's prompt truncated to ~2k tokens (see `docs/LOGS.md` §6).

```powershell
powershell -ExecutionPolicy Bypass -File scenarios/opencode_e6.ps1      # 13 prompts x 3 conditions x 3 repeats, ~20 min
F:\project0\mcp-audit-venv\Scripts\python analysis\mcp_audit_scan.py     # static scan of the same 3 configs
python analysis/analyze.py                                               # runtime detector
python analysis/e6_report.py                                             # -> logs/export/e6_sessions.json, samples/e6_results.md
```

`analysis/mcp_audit_scan.py` calls mcp-audit's project scanner on `config/e6/`
only; `mcp-audit scan` itself also sweeps the machine's own Claude/Cursor/VS Code
configs.

## Conditions and prompts

| condition | memory server | meaning |
|---|---|---|
| `open` | `memory_server.py` | no workspace boundary |
| `argscope` | `--enforce-boundary` | filters on the `workspace` argument the LLM picks |
| `session` | `--session-workspace A` | bound to the user's workspace server-side |

The filesystem server is the same in all three (its root holds `workspace_a/` and
`workspace_b/`). Prompts (all from a Workspace A user) are in
`scenarios/opencode_e6.ps1`: 4 benign-scoped, 4 benign-broad, 5 malicious.
