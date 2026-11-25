# Group B CVE servers — isolated runtime reproduction

This harness **runs the real, vulnerable-pinned Group B MCP servers** (the "safe
subset": filesystem, memory, git, excel) to get *ground-truth* runtime evidence,
as opposed to the static mcp-audit scan (which only reads their config) and the
synthetic fixtures elsewhere in this repo.

It answers one question per server: **a server confined to Workspace A must never
return the Workspace-B canary — does it anyway?**

## Safety model

- Everything runs inside a Docker container launched with **`--network none`**, so
  the vulnerable servers have no network access at all.
- The vulnerable packages are installed at **build** time (the only step that
  touches the network) and are **never added to this repo** — the Dockerfile only
  pins the versions for `pip`/`npm` to fetch. The repo contains the recipe, not the
  vulnerable code.
- All data is **synthetic canaries** (`CANARY-A-7f3c9`, `WORKSPACE_B_SECRET-4471`,
  budget code `4471`) generated inside the container. No host file is mounted.
- The dangerous Group B servers (kubernetes RCE, whatsapp/playwright network
  exposure — all E4/E5, not E3/E6) are **deliberately excluded**. Do not add them
  to this harness; model them with fixtures if needed.

## Run it

```bash
docker build -t mcp-cve-lab:safe .
docker run --rm --network none --name run mcp-cve-lab:safe        # prints progress
# to keep the JSON:
docker run --network none --name run mcp-cve-lab:safe
docker cp run:/out/cve_runtime.json ../samples/cve_runtime.json
docker rm run
```

## Pinned versions (from `installed_versions.txt`)

| Server | Package @ version | CVE |
|---|---|---|
| filesystem-mcp | `@modelcontextprotocol/server-filesystem@2025.3.28` | CVE-2025-53110 |
| excel-mcp | `excel-mcp-server==0.1.8` (mcp 1.30.0) | CVE-2026-85661 |
| memory-mcp | `@modelcontextprotocol/server-memory@1.0.0` | none (scenario) |
| git-mcp | `mcp-server-git==2026.11.18` | none (scenario) |

Each Python server has its own venv so their conflicting `mcp` SDK pins do not
contaminate each other.

## Result (see `../samples/cve_runtime.json`)

| Server | Naive `../` | Documented bypass | Verdict |
|---|---|---|---|
| filesystem-mcp | **blocked** (access denied) | **prefix-sibling bypass leaks** `/lab/workspace_a_leak` while allowed root is `/lab/workspace_a` | **CVE-2025-53110 reproduced** |
| excel-mcp | rejected (needs absolute path) | absolute path **ignores `EXCEL_FILES_PATH`** → reads any file | **CVE-2026-85661 reproduced** |
| memory-mcp | n/a | no workspace model — whole graph readable by any caller | scenario, no boundary to bypass |
| git-mcp | n/a | scoped to the repo path it is given | scenario, runs clean |

**Tie-back:** mcp-audit statically scanned these *same* packages and flagged none
of these behaviours (excel: 0 flags; filesystem: only a generic `filesystem-access`
note, not the containment bypass). The runtime run is the ground truth behind the
static/runtime detection gap.
