#!/usr/bin/env python3
"""
mcp_audit_scan.py -- collect everything APIsec mcp-audit reports about the E6 lab.

Run it with the interpreter that has mcp-audit installed (it is a separate tool,
kept out of the testbed's stdlib-only environment):

  F:/project0/mcp-audit-venv/Scripts/python analysis/mcp_audit_scan.py

For each E6 configuration (config/e6/<condition>/mcp.json) it records:
  scan        mcp-audit's project scanner + registry enrichment (what `mcp-audit scan
              --path` does), in every output format it offers: json, markdown, csv,
              sarif, cyclonedx (AI-BOM)
  policy      `mcp-audit policy` against each bundled policy (strict / enterprise /
              permissive), fed the scan's JSON inventory
and once for the lab:
  source_scan        `mcp-audit source-scan` on the lab's server, proxy and library code
  registry_matches   which registry entry each server matched, and by which rule
  flag_explanations  `mcp-audit explain` text for every flag raised

Not run, on purpose (recorded in the output):
  scan --local  also sweeps this machine's own Claude/Cursor/VS Code/Windsurf/Zed configs
  trust         sends each server's source to npm/GitHub APIs; ours are local script paths
  analyze       aggregates configs collected across an organisation's machines

Writes logs/e6/mcp_audit.json.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import mcp_audit
from mcp_audit.data import get_registry, lookup_mcp
from mcp_audit.data.risk_definitions import get_risk_flag_info
from mcp_audit.outputs.formatter import format_results
from mcp_audit.scanners import project
from mcp_audit.scanners import source as source_scanner

ROOT = Path(__file__).resolve().parent.parent
CONDITIONS = ("open", "argscope", "session")
OUT = ROOT / "logs" / "e6" / "mcp_audit.json"
PKG = Path(mcp_audit.__file__).resolve().parent
CLI = [sys.executable, "-m", "mcp_audit.cli"]
SOURCE_DIRS = ("servers", "proxy", "common")
FORMATS = ("json", "markdown", "csv", "sarif", "cyclonedx")


def mcp_audit_commit() -> str | None:
    """The clone this venv was installed from (F:/project0/mcp-audit by default)."""
    repo = os.environ.get("MCP_AUDIT_REPO", str(ROOT.parent / "mcp-audit"))
    try:
        return subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def cli_json(args: list[str]) -> dict:
    """Run an mcp-audit command with --format json --output <tmp> and load the result."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.json"
        proc = subprocess.run(CLI + args + ["--format", "json", "--output", str(out)],
                              capture_output=True, text=True, cwd=ROOT)
        if not out.exists():
            return {"error": (proc.stderr or proc.stdout).strip()[-2000:], "exit_code": proc.returncode}
        data = json.loads(out.read_text(encoding="utf-8"))
        data["_exit_code"] = proc.returncode
        return data


def match_rule(source: str, name: str, entry: dict) -> str:
    s, n = source.lower(), name.lower()
    if entry["package"].lower() in s:
        return "package match"
    if entry.get("endpoint") and entry["endpoint"].lower() in s:
        return "endpoint match"
    if n in (entry["name"].lower(), entry["id"].lower()):
        return "exact name match"
    return "partial name match (fallback)"


def main() -> int:
    policies = sorted((PKG.parent / "policies").glob("*.yaml")) or \
               sorted((ROOT.parent / "mcp-audit" / "policies").glob("*.yaml"))
    report = {
        "tool": {"name": "mcp-audit", "publisher": "APIsec", "repo": "https://github.com/apisec-inc/mcp-audit",
                 "version": getattr(mcp_audit, "__version__", None), "commit": mcp_audit_commit()},
        "what_it_is": "A static scanner: reads MCP configuration files (mcpServers JSON) and MCP server "
                      "source code before deployment. It does not run servers or capture MCP traffic.",
        "not_run": {
            "scan --local": "also sweeps this machine's own Claude/Cursor/VS Code/Windsurf/Zed configs; "
                            "the project scanner was run on the lab configs only",
            "trust": "sends each server's source to the npm and GitHub APIs; the lab's sources are local "
                     "script paths, which it would query npm for as package names",
            "analyze": "aggregates configs collected from many machines (collectors/); not applicable",
        },
        "configs": {},
    }
    flags_seen, matches = set(), {}

    for condition in CONDITIONS:
        cfg_dir = ROOT / "config" / "e6" / condition
        results = project.scan(cfg_dir)
        for r in results:
            r.enrich_from_registry()
            flags_seen.update(r.risk_flags)
            entry = lookup_mcp(r.source, r.name)
            if entry and r.name not in matches:
                matches[r.name] = {"matched_registry_entry": entry,
                                   "match_rule": match_rule(r.source, r.name, entry),
                                   "server_actually_is": "the testbed's own lab server (not this package)"}
        outputs = {}
        for fmt in FORMATS:
            text = format_results(results, fmt)
            outputs[fmt] = json.loads(text) if fmt in ("json", "sarif", "cyclonedx") else text
        with tempfile.TemporaryDirectory() as tmp:
            inv = Path(tmp) / "inventory.json"
            inv.write_text(json.dumps(outputs["json"]), encoding="utf-8")
            policy = {p.stem: cli_json(["policy", "--policy", str(p), "--input", str(inv)]) for p in policies}
        report["configs"][condition] = {
            "scanned_file": str((cfg_dir / "mcp.json").relative_to(ROOT)).replace("\\", "/"),
            "memory_server_flags": next((r.args[next(i for i, a in enumerate(r.args)
                                                     if a.endswith("memory_server.py")) + 1:]
                                         for r in results if r.name == "memory-lab"), None),
            "scan": outputs["json"],
            "scan_markdown": outputs["markdown"],
            "scan_csv": outputs["csv"],
            "sarif": outputs["sarif"],
            "cyclonedx_aibom": outputs["cyclonedx"],
            "policy": policy,
        }
        print(f"{condition:9} flags={ {r.name: r.risk_flags for r in results} } "
              f"policy={ {k: (v.get('violations'), v.get('warnings'), v.get('compliant')) for k, v in policy.items()} }")

    report["source_scan"] = {}
    for d in SOURCE_DIRS:
        res = cli_json(["source-scan", str(ROOT / d)])
        files = sorted((ROOT / d).rglob("*.py"))
        res["files_recognised_as_mcp_server"] = [
            p.name for p in files if source_scanner._looks_like_mcp_server(p.read_text(encoding="utf-8"), p.suffix)]
        res["checks_for"] = "shell-injection sinks fed by tool arguments (the only source-scan rule)"
        report["source_scan"][d] = res
    report["registry_matches"] = matches
    report["registry_size"] = len(get_registry()["mcps"])
    report["flag_explanations"] = {f: get_risk_flag_info(f) for f in sorted(flags_seen)}

    def verdict(c):
        s = report["configs"][c]
        return json.dumps({"flags": {m["name"]: m["risk_flags"] for m in s["scan"]["mcps"]},
                           "findings": [(f["flag"], f["severity"]) for f in s["scan"]["findings"]],
                           "policy": {k: [(r["name"], r["status"], r["reasons"]) for r in v.get("results", [])]
                                      for k, v in s["policy"].items()}}, sort_keys=True)
    report["same_verdict_for_all_configs"] = len({verdict(c) for c in CONDITIONS}) == 1

    os.makedirs(OUT.parent, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("source-scan:", {d: (v["files_recognised_as_mcp_server"], v.get("finding_count"))
                           for d, v in report["source_scan"].items()})
    print("same verdict for all configs:", report["same_verdict_for_all_configs"])
    print(f"-> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
