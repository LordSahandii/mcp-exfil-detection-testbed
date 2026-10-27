"""
labenv.py -- shared helpers for scenario drivers.

Builds proxy-wrapped MCP client connections. Every upstream server is launched
*through* logging_proxy.py so all traffic is captured, exactly as in the real
OpenCode/Claude deployment. Connections in one logical "run" share a run_id so
the analysis layer can stitch cross-server sequences together.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "common"))
from mcplite import Client  # noqa: E402

LAB = os.path.join(ROOT, "lab")
LOG_RAW = os.path.join(ROOT, "logs", "raw")
LOG_FEAT = os.path.join(ROOT, "logs", "features")
SINK_RECEIPTS = os.path.join(LOG_FEAT, "sink_receipts.jsonl")
PY = sys.executable


def _server_cmd(server_id: str) -> list[str]:
    s = os.path.join(ROOT, "servers")
    if server_id == "filesystem":
        return [PY, os.path.join(s, "fs_server.py"), "--root", LAB]
    if server_id == "sink":
        return [PY, os.path.join(s, "sink_server.py"), "--receipts", SINK_RECEIPTS]
    if server_id == "memory":
        return [PY, os.path.join(s, "memory_server.py")]
    if server_id == "git":
        return [PY, os.path.join(s, "git_server.py"), "--repo", os.path.join(LAB, "repo")]
    if server_id.startswith("poisoned"):
        mode = server_id.split(":", 1)[1] if ":" in server_id else "benign"
        return [PY, os.path.join(s, "poisoned_server.py"), "--mode", mode]
    raise ValueError(f"unknown server_id {server_id}")


def connect(server_id: str, label: str, run_id: str, scenario_id: str) -> Client:
    """Open an MCP client to `server_id` through the logging proxy."""
    logical = server_id.split(":", 1)[0]
    env = {**os.environ,
           "MCP_RUN_ID": run_id,
           "MCP_SCENARIO_ID": scenario_id,
           "MCP_EXPERIMENT_ID": "mcp-baseline"}
    cmd = [
        PY, os.path.join(ROOT, "proxy", "logging_proxy.py"),
        "--log-dir", LOG_RAW,
        "--server-id", logical,
        "--label", label,
        "--run-id", run_id,
        "--scenario-id", scenario_id,
        "--", *_server_cmd(server_id),
    ]
    c = Client(cmd, env=env)
    c.initialize()
    return c


def new_run_id(prefix: str, i: int) -> str:
    return f"{prefix}-{i:03d}"


import json  # noqa: E402

RUN_POLICY = os.path.join(LOG_FEAT, "run_policy.jsonl")


APPROVED_DESTINATION = "https://reports.internal.lab/post"


def write_policy(run_id: str, label: str, scenario_id: str,
                 task_intent: str = "read_write",
                 allow_egress: bool = False,
                 allowed_write_roots=None,
                 scope_workspace: str | None = None,
                 approved_destinations=None):
    """Record the authorized task policy for a run (ground truth for the detector).

    This encodes what the task was *allowed* to do, independent of what happened,
    per the project's policy evidence model (task_intent_label, allowed_roots,
    approved_destinations, workspace_label).
    """
    os.makedirs(LOG_FEAT, exist_ok=True)
    rec = {
        "run_id": run_id, "label": label, "scenario_id": scenario_id,
        "task_intent": task_intent, "allow_egress": allow_egress,
        "allowed_write_roots": allowed_write_roots or [],
        "scope_workspace": scope_workspace,
        "approved_destinations": approved_destinations or [],
    }
    with open(RUN_POLICY, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
