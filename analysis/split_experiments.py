#!/usr/bin/env python3
"""
split_experiments.py -- split the E3, E6 and Excel-CVE runtime sessions into
separate benign and malicious files, per experiment, for easier downstream
processing.

The mcp-audit static results are already separated by experiment
(samples/e6_mcp_audit.json, samples/e3_mcp_audit.json); the benign/malicious
distinction only applies to the live sessions, so this splits those.

Reads   samples/e6_sessions.json, samples/e3_sessions.json,
        samples/excel_cve_sessions.json
Writes  samples/split/<exp>_<label>.json  (self-describing: about + sessions)
        samples/split/<exp>_<label>.csv   (one row per session, flat, readable)
        for exp in {e6, e3, excel} and label in {benign, malicious}

Run from the project root:  python analysis/split_experiments.py
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import os

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLES = os.path.join(ROOT, "samples")
OUTDIR = os.path.join(SAMPLES, "split")

# per-experiment: source file, the per-session measure key, and the field in it
# that names the outcome for that experiment.
EXPERIMENTS = {
    "e6": {"src": "e6_sessions.json", "measure": "e6", "outcome_field": "exposure",
           "name": "E6 context exposure"},
    "e3": {"src": "e3_sessions.json", "measure": "e3", "outcome_field": "outcome",
           "name": "E3 tool poisoning / rug pull"},
    "excel": {"src": "excel_cve_sessions.json", "measure": "xl", "outcome_field": "outcome",
              "name": "Excel MCP CVE-2026-85661 path traversal"},
}
CSV_FIELDS = ["run_id", "experiment", "label", "scenario", "condition", "prompt_class", "variant",
              "model", "campaign", "outcome", "detector_alerted", "detector_rules", "n_tool_calls",
              "tool_sequence", "prompt", "agent_answer"]


def load(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return json.load(fh)


def flat(text):
    """Collapse whitespace to single spaces so each CSV field stays on one line."""
    return " ".join((text or "").split())


def csv_row(s, exp, meas_key, outcome_field):
    det = s.get("detector") or {}
    return {
        "run_id": s["run_id"], "experiment": exp, "label": s["label"], "scenario": s.get("scenario"),
        "condition": s.get("condition"), "prompt_class": s.get("prompt_class"), "variant": s.get("variant"),
        "model": s.get("model"), "campaign": s.get("campaign"),
        "outcome": (s.get(meas_key) or {}).get(outcome_field),
        "detector_alerted": bool(det.get("rules_fired")),
        "detector_rules": "; ".join(det.get("rules_fired") or []),
        "n_tool_calls": s.get("n_tool_calls"),
        "tool_sequence": " > ".join(f'{c["server"]}.{c["tool"]}' for c in s.get("tool_calls", [])),
        "prompt": flat(s.get("prompt")),
        "agent_answer": flat(s.get("agent_answer")),
    }


def main() -> int:
    os.makedirs(OUTDIR, exist_ok=True)
    total = 0
    for exp, cfg in EXPERIMENTS.items():
        doc = load(cfg["src"])
        src_about = doc.get("about") or {}
        # Carry over the source legends that make the outcomes readable, when present.
        legends = {k: src_about[k] for k in ("cve", "conditions", "prompt_classes", "outcomes")
                   if src_about.get(k)}
        for label in ("benign", "malicious"):
            sessions = [s for s in doc["sessions"] if s["label"] == label]
            out = {
                "about": {
                    "experiment": cfg["name"],
                    "label": label,
                    "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "source": f"samples/{cfg['src']}",
                    "sessions": len(sessions),
                    **legends,
                    "note": "Synthetic, local. One record per live OpenCode session: prompt, condition, "
                            "every tool call (arguments + response), the agent's answer, the experiment "
                            "outcome, and the detector verdict. Label is ground truth from the driver.",
                },
                "sessions": sessions,
            }
            base = os.path.join(OUTDIR, f"{exp}_{label}")
            with open(base + ".json", "w", encoding="utf-8") as fh:
                json.dump(out, fh, indent=2, ensure_ascii=False)
            with open(base + ".csv", "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
                w.writeheader()
                for s in sessions:
                    w.writerow(csv_row(s, exp, cfg["measure"], cfg["outcome_field"]))
            total += len(sessions)
            print(f"  {exp}_{label:9} {len(sessions):3} sessions -> split/{exp}_{label}.json + .csv")
    n_files = 2 * len(EXPERIMENTS)
    print(f"wrote {total} sessions across {n_files} benign/malicious files -> {OUTDIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
