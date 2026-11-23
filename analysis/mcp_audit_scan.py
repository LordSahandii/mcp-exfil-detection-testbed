#!/usr/bin/env python3
"""
mcp_audit_scan.py -- run APIsec mcp-audit's project scanner on the E6 lab configs.

Run it with the interpreter that has mcp-audit installed (it is a separate tool,
kept out of the testbed's stdlib-only environment):

  F:/project0/mcp-audit-venv/Scripts/python analysis/mcp_audit_scan.py

This calls the same scanner and registry enrichment `mcp-audit scan --path` uses,
but only on config/e6/<condition>/ -- the CLI always sweeps the machine's own
Claude/Cursor/VS Code/Windsurf/Zed configs too, which don't belong in lab data.

Writes logs/e6/mcp_audit_scan.json: {condition: mcp-audit's JSON report}.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import mcp_audit
from mcp_audit.outputs.formatter import format_results
from mcp_audit.scanners import project

ROOT = Path(__file__).resolve().parent.parent
CONDITIONS = ("open", "argscope", "session")
OUT = ROOT / "logs" / "e6" / "mcp_audit_scan.json"


def main() -> int:
    report = {"mcp_audit_version": getattr(mcp_audit, "__version__", None)}
    for condition in CONDITIONS:
        results = project.scan(ROOT / "config" / "e6" / condition)
        for r in results:
            r.enrich_from_registry()
        report[condition] = json.loads(format_results(results, "json"))
        flags = {r.name: r.risk_flags for r in results}
        print(f"{condition:9} {flags}")
    os.makedirs(OUT.parent, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"-> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
