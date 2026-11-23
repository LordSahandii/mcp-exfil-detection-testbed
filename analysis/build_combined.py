#!/usr/bin/env python3
"""
build_combined.py -- consolidate all E3 and E6 testing into one JSON file.

Reads the per-experiment snapshots in samples/ and writes one self-describing
bundle: the prompt catalogue, both runtime campaigns (every session with its
prompt, tool calls, answer, outcome and detector verdict), and the mcp-audit
static results (lab configs and the shortlisted vulnerable CVE servers).

Reads   samples/e6_sessions.json, samples/e3_sessions.json      (runtime)
        samples/e6_mcp_audit.json, samples/e3_mcp_audit.json     (full mcp-audit output)
Writes  samples/e3_e6_all_tests.json

Run from the project root:  python analysis/build_combined.py
"""
from __future__ import annotations

import datetime as dt
import json
import os

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLES = os.path.join(ROOT, "samples")
OUT = os.path.join(SAMPLES, "e3_e6_all_tests.json")


def load(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return json.load(fh)


def prompt_catalogue(sessions):
    """Unique prompts (prompt_class, variant) -> full text, in first-seen order."""
    seen, out = set(), []
    for s in sessions:
        key = (s["prompt_class"], s["variant"])
        if key in seen:
            continue
        seen.add(key)
        out.append({"prompt_class": s["prompt_class"], "variant": s["variant"],
                    "scenario": s["scenario"], "label": s["label"], "text": s["prompt"]})
    return out


def main() -> int:
    e6 = load("e6_sessions.json")
    e3 = load("e3_sessions.json")
    e6_audit = load("e6_mcp_audit.json")
    e3_audit = load("e3_mcp_audit.json")

    doc = {
        "about": {
            "title": "MCP security testing: E3 and E6 with mcp-audit and vulnerable servers",
            "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "experiments": {
                "E3": "Tool poisoning / rug pull -- a benign request against a maliciously-described tool.",
                "E6": "Context exposure -- cross-workspace over-sharing through memory and filesystem servers.",
            },
            "what_is_here": "Two live OpenCode campaigns (runtime traffic captured by the logging proxy) plus "
                            "APIsec mcp-audit's static results on the lab configs and on the team's shortlisted "
                            "real MCP servers pinned to their vulnerable versions.",
            "environment": "Everything is synthetic and local. Canary secrets (CANARY-A-7f3c9; "
                           "WORKSPACE_B_SECRET-4471), a local sink that performs no network egress, denied "
                           "out-of-root reads. The real CVE servers were only statically scanned, never run.",
            "files": {
                "this_file": "samples/e3_e6_all_tests.json -- the consolidated bundle (you are here)",
                "e6_sessions": "samples/e6_sessions.json -- E6 runtime sessions",
                "e3_sessions": "samples/e3_sessions.json -- E3 runtime sessions",
                "e6_mcp_audit_raw": "samples/e6_mcp_audit.json -- full mcp-audit output for E6 (all formats)",
                "e3_mcp_audit_raw": "samples/e3_mcp_audit.json -- full mcp-audit output for E3 + CVE servers",
                "pdf": "samples/mcp_e3_e6_report.pdf -- the combined report",
            },
        },
        "prompts": {
            "E6": prompt_catalogue(e6["sessions"]),
            "E3": prompt_catalogue(e3["sessions"]),
        },
        "E6": {
            "experiment": "context exposure",
            "conditions": e6["about"]["conditions"],
            "prompt_classes": e6["about"]["prompt_classes"],
            "exposure_definitions": e6.get("exposure_definitions"),
            "summary": e6["summary"],
            "mcp_audit": e6["mcp_audit"],
            "sessions": e6["sessions"],
        },
        "E3": {
            "experiment": "tool poisoning / rug pull",
            "conditions": e3["about"]["conditions"],
            "prompt_classes": e3["about"]["prompt_classes"],
            "outcomes": e3["about"].get("outcomes"),
            "summary": e3["summary"],
            "mcp_audit": e3["mcp_audit"],
            "sessions": e3["sessions"],
        },
        "mcp_audit": {
            "tool": e3_audit.get("tool") or e6_audit.get("tool"),
            "what_it_is": e3_audit.get("what_it_is"),
            "e6_lab_full": e6_audit,
            "e3_lab_and_cve_full": e3_audit,
        },
    }

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
    n6, n3 = len(e6["sessions"]), len(e3["sessions"])
    print(f"consolidated {n6} E6 + {n3} E3 sessions, "
          f"{len(doc['prompts']['E6'])} E6 + {len(doc['prompts']['E3'])} E3 prompts, "
          f"mcp-audit (lab + {len(e3_audit.get('cve_servers', {}))} CVE servers)")
    print(f"-> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
