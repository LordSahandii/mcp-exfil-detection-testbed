#!/usr/bin/env python3
"""
mcp_audit_e3_cve.py -- run APIsec mcp-audit (static) on (a) the three E3 lab
configs and (b) the team's shortlisted real MCP servers, pinned to their
vulnerable versions.

Run with the interpreter that has mcp-audit installed:

  F:/project0/mcp-audit-venv/Scripts/python analysis/mcp_audit_e3_cve.py

mcp-audit is a STATIC scanner: it reads config files and server source. It never
runs a server. This script writes config/cve_servers/mcp.json describing the
shortlisted servers (so mcp-audit has a real config to read) and scans it, then
scans config/e3/<condition>/mcp.json. Nothing here installs or executes any of
the real servers.

The CVE servers are the ones on the team's benchmark shortlist that align with E3
and/or E6. They are referenced by package name and a vulnerable version so the
config is realistic; they are not run.

Writes logs/e3/mcp_audit.json.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import mcp_audit
from mcp_audit.data import lookup_mcp
from mcp_audit.outputs.formatter import format_results
from mcp_audit.scanners import project

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "logs" / "e3" / "mcp_audit.json"
CVE_CONFIG = ROOT / "config" / "cve_servers" / "mcp.json"
E3_CONDITIONS = ("benign", "startup", "rugpull")

# Team shortlist, restricted to servers that align with E3 and/or E6, pinned to a
# vulnerable version. command/args are what a real deployment would use; they are
# fed to mcp-audit as config text only, never executed.
CVE_SERVERS = [
    {"name": "git-mcp", "aligns": ["E1", "E5", "E6"], "cve": None,
     "note": "poisoned-repository scenario (no CVE)",
     "command": "uvx", "args": ["mcp-server-git", "--repository", "/repo"]},
    {"name": "filesystem-mcp", "aligns": ["E3", "E6"], "cve": "CVE-2025-53110",
     "note": "directory-containment bypass; fixed in 2025.7.1",
     "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.3.28", "/data"]},
    {"name": "excel-mcp", "aligns": ["E3", "E6"], "cve": "CVE-2026-85661",
     "note": "path traversal in stdio mode when EXCEL_FILES_PATH unset; vulnerable 0.1.8",
     "command": "uvx", "args": ["excel-mcp-server@0.1.8", "stdio"]},
    {"name": "memory-mcp", "aligns": ["E1", "E6"], "cve": None,
     "note": "poisoned-observations scenario (no CVE)",
     "command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]},
    {"name": "kubernetes-mcp", "aligns": ["E5", "E6"], "cve": "CVE-2025-53355",
     "note": "command injection via execSync; fixed in 2.5.0",
     "command": "npx", "args": ["-y", "mcp-server-kubernetes@2.4.0"]},
    {"name": "whatsapp-mcp", "aligns": ["E2", "E3", "E6"], "cve": "CVE-2026-46555",
     "note": "unauthenticated bridge, path traversal in media_path; fixed in 0.2.1 (package name illustrative)",
     "command": "npx", "args": ["-y", "whatsapp-mcp-server@0.2.0"]},
    {"name": "playwright-mcp", "aligns": ["E4", "E5", "E6"], "cve": "CVE-2025-9611",
     "note": "DNS rebinding, missing Origin check; fixed in 0.0.40",
     "command": "npx", "args": ["-y", "@playwright/mcp@0.0.39", "--port", "8080"]},
]


def scan_config(cfg_dir: Path) -> dict:
    results = project.scan(cfg_dir)
    for r in results:
        r.enrich_from_registry()
    return {
        "scanned_file": str((cfg_dir / "mcp.json").relative_to(ROOT)).replace("\\", "/"),
        "servers": {r.name: {"risk_flags": r.risk_flags,
                             "registry_provider": (r.provider if r.is_known else None),
                             "registry_risk": (r.registry_risk if r.is_known else None),
                             "registry_verified": r.verified} for r in results},
        "findings": [{"flag": f["flag"], "severity": f["severity"], "affected": f["affected_mcps"]}
                     for f in json.loads(format_results(results, "json"))["findings"]],
    }


def main() -> int:
    # (b) build + scan the CVE-server config
    CVE_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    mcp_servers = {s["name"]: {"command": s["command"], "args": s["args"]} for s in CVE_SERVERS}
    CVE_CONFIG.write_text(json.dumps({
        "//": "Real MCP servers from the benchmark shortlist, pinned to vulnerable versions, for STATIC "
              "mcp-audit scanning only. These servers are never run by this project.",
        "mcpServers": mcp_servers}, indent=2), encoding="utf-8")
    cve_results = {r.name: r for r in project.scan(CVE_CONFIG.parent)}
    for r in cve_results.values():
        r.enrich_from_registry()
    cve_block = {}
    for s in CVE_SERVERS:
        r = cve_results.get(s["name"])
        entry = lookup_mcp(r.source, r.name) if r else None
        cve_block[s["name"]] = {
            "aligns_with": s["aligns"], "cve": s["cve"], "note": s["note"],
            "command": s["command"] + " " + " ".join(s["args"]),
            "risk_flags": r.risk_flags if r else [],
            "registry_provider": (r.provider if r and r.is_known else "Unknown"),
            "registry_risk": (r.registry_risk if r and r.is_known else "unknown"),
            "registry_match_name": entry["name"] if entry else None,
        }

    # (a) scan the three E3 lab configs
    lab = {c: scan_config(ROOT / "config" / "e3" / c) for c in E3_CONDITIONS}

    report = {
        "tool": {"name": "mcp-audit", "publisher": "APIsec",
                 "version": getattr(mcp_audit, "__version__", None)},
        "what_it_is": "Static scanner: reads MCP config files and server source before deployment. It does "
                      "not run servers or capture traffic. The CVE servers below were only scanned, not run.",
        "lab_configs": lab,
        "cve_servers": cve_block,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("E3 lab configs (poisoned-lab flags):",
          {c: lab[c]["servers"].get("poisoned-lab", {}).get("risk_flags") for c in E3_CONDITIONS})
    for name, v in cve_block.items():
        print(f"  {name:16} aligns={','.join(v['aligns_with']):10} cve={v['cve'] or '-':16} "
              f"flags={v['risk_flags'] or '[]'}  registry={v['registry_match_name']}")
    print(f"-> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
