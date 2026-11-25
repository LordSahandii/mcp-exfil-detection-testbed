# mcp-audit — what we're doing and how it works

Orientation + instruction file for the **mcp-audit** workstream (E3 + E6 owner:
Sahand). Start here, then drop into [`E3_MCP_AUDIT.md`](E3_MCP_AUDIT.md) or
[`E6_MCP_AUDIT.md`](E6_MCP_AUDIT.md) for the per-experiment reproduction steps.

- **Tool:** [APIsec mcp-audit](https://github.com/apisec-inc/mcp-audit) v1.1.0,
  commit `6ae4e1ff58f3a75ca356fd173112770d217f59a3`.
- **One consolidated write-up:** [`samples/mcp_audit_report.pdf`](../samples/mcp_audit_report.pdf) (7 pages).

---

## 1. TL;DR — what's happening

We are measuring a **static vs runtime detection gap** for MCP servers. There are
two axes, and mcp-audit is only the **static** one:

| Axis | Tool | What it sees | Produces |
|---|---|---|---|
| **Static** | **mcp-audit** | config files + server source, *before* run | one risk verdict per server/config |
| **Runtime** | our logging proxy (+ Docker for real CVE servers) | every JSON-RPC message of a live session | per-session outcome + detector verdict |

The thesis, now backed by data: **mcp-audit gives a leaky deployment and a safe
one the same verdict, and flags none of the real CVE behaviours** — because it
never runs anything. The runtime axis is what actually catches the leak.

**Current status (2026-11-24):** static scans done for all E3/E6 lab configs +
the 7 CVE benchmark servers; runtime benign/malicious data done for E3/E6; the
**safe subset** of the CVE servers has now been *run for real* in isolation and
**2 CVEs reproduced**. See §6–7.

---

## 2. How mcp-audit works (mechanically)

A **static scanner** with two inputs and **no execution**:

1. **Config files** (`mcpServers` JSON) → parses each server's `command`/`args`,
   classifies the server type, assigns **risk flags** from a fixed rule set
   (`filesystem-access`, `unverified-source`, …), and matches the name against a
   bundled **registry** (~47 known servers).
2. **Server source** (`source-scan`) → greps for exactly one thing: shell-injection
   sinks fed by tool arguments.

Around that: `policy` (3 built-in profiles), `explain` (remediation text), `trust`
(sends source to npm/GitHub — **we don't run it**), `analyze` (org aggregation).
Output formats: table / json / markdown / csv / sarif / cyclonedx (AI-BOM).

**It cannot see** a running server, a tool call, a response, or a returned secret.

### The CLI gotcha (important)

`mcp-audit scan`'s `--local` flag **defaults on and can't be turned off**, so the
CLI always sweeps *this machine's* Cursor / Claude / VS Code / Windsurf / Zed
configs (in our runs it surfaced an unrelated **nmap** MCP from Cursor). To scan
**only our project configs**, our scripts call the scanner **library** directly —
`project.scan(<dir>)` then `enrich_from_registry()` — not the CLI.

---

## 3. Setup

Clone + venv kept **outside** this repo (the testbed is stdlib-only; mcp-audit has
deps). Full steps in [`E6_MCP_AUDIT.md`](E6_MCP_AUDIT.md#1-install-mcp-audit-pinned).

```powershell
# clone at F:\project0\mcp-audit  (pinned commit above)
git config core.autocrlf false     # else a false "registry tampered" warning on Windows
# venv at F:\project0\mcp-audit-venv
```

Run everything with that venv's interpreter: `F:\project0\mcp-audit-venv\Scripts\python`.

---

## 4. How we run it (the scripts)

| Script | Scans | Output |
|---|---|---|
| [`analysis/mcp_audit_scan.py`](../analysis/mcp_audit_scan.py) | E6 lab configs (`open` / `argscope` / `session`), every format + 3 policy profiles, source-scan, registry, explain | `samples/e6_mcp_audit.json` |
| [`analysis/mcp_audit_e3_cve.py`](../analysis/mcp_audit_e3_cve.py) | E3 lab configs (`benign` / `startup` / `rugpull`) **+ the 7 CVE benchmark servers** (`config/cve_servers/mcp.json`) | `samples/e3_mcp_audit.json` |

```powershell
F:\project0\mcp-audit-venv\Scripts\python analysis\mcp_audit_scan.py
F:\project0\mcp-audit-venv\Scripts\python analysis\mcp_audit_e3_cve.py
```

Both call the mcp-audit **library** on our config directories (see §2 gotcha).
The CVE servers are **only scanned** by these scripts — never installed or run by
them (running the safe subset is a separate, isolated step; see §7).

---

## 5. mcp-audit's place in the benign/malicious test

mcp-audit has **no benign-or-malicious notion.** It runs once per *configuration*
and emits one verdict; it never sees a prompt or a session. The benign/malicious
**labelled data is produced by the runtime axis** — OpenCode drives the same
servers with benign-intent and malicious prompts, the proxy captures every byte,
the detector labels the outcome:

- `samples/split/{e6,e3,excel}_benign.{json,csv}` and `…_malicious.{json,csv}`

So mcp-audit is the **static control** we compare those labels against: for a given
server it returns the **identical verdict** whether the following session is benign
or malicious, and whether the binding is leaky or safe. (Do **not** describe
mcp-audit as *generating* the malicious data — the data flow is the other way: the
runtime run generates the labels; mcp-audit is the baseline.)

---

## 6. Key findings (static)

- **Same verdict across every condition.** The E6 `open` / `argscope` / `session`
  configs (and the E3 `benign` / `startup` / `rugpull` configs) differ only in how a
  server is bound, which is exactly what decides whether secrets leak at runtime —
  and mcp-audit returns an identical verdict for all of them.
- **Critical CVE → 0 flags.** `excel-mcp` (path traversal, CVE-2026-85661) drew
  **zero** risk flags and matched no registry entry — the same clean bill a safe
  server gets. `kubernetes-mcp` (command injection) drew only a generic
  `unverified-source`.
- **Source-scan: 0 findings** on our servers (it only looks for shell-injection).

Full detail + tables: [`samples/mcp_audit_report.pdf`](../samples/mcp_audit_report.pdf).

---

## 7. Runtime counterpart — running the real CVE servers (`cve_runtime/`)

To get **ground truth** behind the static verdict, we run the **E3/E6-aligned safe
subset** of the real vulnerable-pinned packages, under hard isolation. See
[`cve_runtime/README.md`](../cve_runtime/README.md).

- **Isolation:** Docker, `--network none`, synthetic canaries only, no host files
  mounted. Vulnerable packages are fetched at build time and **never stored in the
  repo**.
- **Safe subset run:** `filesystem-mcp`, `excel-mcp`, `memory-mcp`, `git-mcp`.
- **Excluded by design:** `kubernetes-mcp` (host RCE), `whatsapp-mcp`,
  `playwright-mcp` (network exposure) — all E4/E5, not E3/E6. **Do not run these;**
  model them with fixtures if needed.
- **Result (2 CVEs reproduced):**
  - `filesystem-mcp@2025.3.28` — naive `../` blocked, but the **CVE-2025-53110**
    prefix-match bypass leaks a sibling dir (`/lab/workspace_a_leak` passes the
    `/lab/workspace_a` prefix check).
  - `excel-mcp 0.1.8` — ignores `EXCEL_FILES_PATH` in stdio mode; an absolute path
    reads any file → **CVE-2026-85661**.
  - `memory` / `git` — no confinement model (scenario servers, no CVE).
  - Both CVEs are published + fixed upstream — **reproduced, not discovered.**

```bash
cd cve_runtime && docker build -t mcp-cve-lab:safe .
docker run --rm --network none mcp-cve-lab:safe
```

Evidence: [`samples/cve_runtime.json`](../samples/cve_runtime.json),
report [`samples/cve_runtime_report.pdf`](../samples/cve_runtime_report.pdf).

---

## 8. File map

| What | Where |
|---|---|
| Umbrella report (7 pp) | `samples/mcp_audit_report.pdf` |
| E6 static raw / report | `samples/e6_mcp_audit.json` · `samples/e6_mcp_audit.pdf` |
| E3 static raw (lab + CVE) | `samples/e3_mcp_audit.json` |
| CVE runtime evidence / report | `samples/cve_runtime.json` · `samples/cve_runtime_report.pdf` |
| Benign/malicious split data | `samples/split/{e6,e3,excel}_{benign,malicious}.{json,csv}` |
| Scan scripts | `analysis/mcp_audit_scan.py` · `analysis/mcp_audit_e3_cve.py` |
| CVE-server configs (scan only) | `config/cve_servers/mcp.json` |
| Isolated CVE runner | `cve_runtime/` |
| Per-experiment guides | `docs/E3_MCP_AUDIT.md` · `docs/E6_MCP_AUDIT.md` |

---

## 9. What we're working on / open threads

- E3 + E6 static scans and benign/malicious runtime data: **done.**
- Safe-subset CVE servers run in isolation, 2 CVEs reproduced: **done.**
- **Not done / deliberately out of scope:** running the dangerous CVE subset
  (k8s/whatsapp/playwright); these stay scanned-only or fixture-modelled.
- Possible next steps (ask before starting): fold the runtime report into the
  umbrella report; capture live `scan`/`policy`/`explain` terminal output; add the
  `excel` runtime fixture results into the static-vs-runtime comparison table.
