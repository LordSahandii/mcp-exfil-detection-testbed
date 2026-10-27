#!/usr/bin/env python3
"""
logging_proxy.py -- instrumented MCP stdio logging proxy.

Sits transparently between an MCP client (OpenCode / Claude Desktop / the lab
driver) and an upstream MCP server:

    client  <--stdio-->  logging_proxy  <--stdio-->  upstream MCP server

It owns the upstream server child process and forwards both request and response
streams byte-for-byte, so JSON-RPC bodies are never mutated (the "minimally
modified raw capture" requirement from the project design). Every message is
recorded as one JSON line of structured telemetry; telemetry goes to a file and
to stderr, never to the stdout JSON-RPC channel.

Usage:
    python logging_proxy.py --log-dir LOGS --server-id filesystem --label benign \
        -- npx -y @modelcontextprotocol/server-filesystem F:\\path\\to\\allowed

Everything after `--` is the upstream server launch command.

The raw record schema (one per message) follows the project's Minimum Telemetry
and Evidence Model (identity / correlation / tool data / integrity).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Recorder:
    """Thread-safe JSONL writer for raw telemetry records."""

    def __init__(self, path: str, verbose: bool = False):
        self.path = path
        self.verbose = verbose
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")

    def write(self, record: dict):
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
        # Optional human-visible trace on stderr (never the JSON-RPC stdout channel).
        # Off by default: at high message volume, a parent shell that wraps stderr
        # (e.g. PowerShell `2>$null`) can stall, so only emit when asked.
        if self.verbose:
            sys.stderr.write(
                f"[proxy {record.get('server_id')}] {record['direction']:>3} "
                f"{record.get('method') or record.get('kind'):<28} "
                f"id={record.get('jsonrpc_id')} "
                f"{record.get('tool_name') or ''} "
                f"{record['payload_bytes']}B {record.get('latency_ms','')}\n"
            )
            sys.stderr.flush()

    def close(self):
        with self._lock:
            self._fh.close()


class Proxy:
    def __init__(self, args):
        self.server_id = args.server_id
        self.label = args.label
        self.run_id = args.run_id or uuid.uuid4().hex[:12]
        self.connection_id = uuid.uuid4().hex[:12]
        self.scenario_id = args.scenario_id
        self.experiment_id = args.experiment_id

        log_name = f"{self.server_id}.{self.label}.jsonl"
        verbose = args.verbose or os.environ.get("MCP_PROXY_VERBOSE") == "1"
        self.recorder = Recorder(os.path.join(args.log_dir, log_name), verbose=verbose)

        # id -> context captured at request time, for response correlation
        self._req_ctx: dict = {}
        self._ctx_lock = threading.Lock()

        self.upstream = subprocess.Popen(
            args.server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

    # -- helpers ---------------------------------------------------------- #
    def _classify(self, msg: dict) -> str:
        if "method" in msg and "id" in msg:
            return "request"
        if "method" in msg and "id" not in msg:
            return "notification"
        if "id" in msg and "result" in msg:
            return "response"
        if "id" in msg and "error" in msg:
            return "error"
        return "unknown"

    def _operation_class(self, method: str, tool_name: str) -> str:
        name = (tool_name or "").lower()
        if method != "tools/call":
            return method or ""
        if any(k in name for k in ("write", "commit", "add", "create", "update", "put", "delete", "exec", "run", "push")):
            return "mutate"
        if any(k in name for k in ("read", "get", "list", "search", "status", "diff", "log", "query", "fetch")):
            return "read"
        if any(k in name for k in ("send", "publish", "post", "upload", "sink")):
            return "egress"
        return "other"

    def _record(self, direction: str, raw: bytes, msg: dict):
        kind = self._classify(msg)
        method = msg.get("method")
        mid = msg.get("id")
        tool_name = None
        tool_args = None
        latency_ms = None
        content_text_len = None
        content_preview = None
        content_truncated = None
        tools_digest = None
        is_error = None

        if kind == "request" and method == "tools/call":
            params = msg.get("params") or {}
            tool_name = params.get("name")
            tool_args = params.get("arguments")

        # Correlate: remember request context by id; attach it on the response.
        if kind == "request":
            with self._ctx_lock:
                self._req_ctx[mid] = {
                    "method": method,
                    "tool_name": tool_name,
                    "t": time.monotonic(),
                }
        elif kind in ("response", "error"):
            with self._ctx_lock:
                ctx = self._req_ctx.pop(mid, None)
            if ctx:
                method = method or ctx["method"]
                tool_name = tool_name or ctx["tool_name"]
                latency_ms = round((time.monotonic() - ctx["t"]) * 1000, 2)
            if kind == "response":
                result = msg.get("result") or {}
                is_error = bool(result.get("isError", False))
                texts = []
                for block in result.get("content", []) or []:
                    if isinstance(block, dict) and block.get("type") == "text":
                        texts.append(block.get("text", ""))
                full = "\n".join(texts)
                content_text_len = len(full)
                # Bounded preview for the derived-feature layer (not unbounded content).
                cap = 800
                content_preview = full[:cap]
                content_truncated = len(full) > cap
                # Tool-definition fingerprints for E3 (poisoning / rug pull).
                tools = result.get("tools")
                if isinstance(tools, list):
                    tools_digest = []
                    for t in tools:
                        if not isinstance(t, dict):
                            continue
                        dsha = hashlib.sha256((t.get("description") or "").encode("utf-8")).hexdigest()[:16]
                        ssha = hashlib.sha256(
                            json.dumps(t.get("inputSchema") or {}, sort_keys=True).encode("utf-8")
                        ).hexdigest()[:16]
                        tools_digest.append({"name": t.get("name"),
                                             "description_sha": dsha, "schema_sha": ssha})

        record = {
            # identity
            "experiment_id": self.experiment_id,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "server_id": self.server_id,
            "label": self.label,
            # correlation
            "connection_id": self.connection_id,
            "timestamp_utc": utcnow_iso(),
            "direction": direction,                 # c2s (client->server) or s2c
            "kind": kind,
            "jsonrpc_id": mid,
            "method": method,
            # tool data
            "tool_name": tool_name,
            "tool_arguments": tool_args,
            "operation_class": self._operation_class(method, tool_name),
            "content_text_len": content_text_len,
            "content_preview": content_preview,
            "content_truncated": content_truncated,
            "tools_digest": tools_digest,
            "is_error": is_error,
            "latency_ms": latency_ms,
            # integrity
            "payload_bytes": len(raw),
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
        }
        self.recorder.write(record)

    # -- pump threads ----------------------------------------------------- #
    def _pump(self, src, dst, direction: str):
        try:
            for raw in src:
                stripped = raw.strip()
                if stripped:
                    try:
                        msg = json.loads(stripped.decode("utf-8"))
                        self._record(direction, stripped, msg)
                    except Exception:
                        pass  # never let logging break the relay
                dst.write(raw)
                dst.flush()
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    def _pump_stderr(self):
        try:
            for raw in self.upstream.stderr:
                sys.stderr.write("[upstream] " + raw.decode("utf-8", "replace"))
                sys.stderr.flush()
        except Exception:
            pass

    def run(self) -> int:
        t_up = threading.Thread(
            target=self._pump,
            args=(sys.stdin.buffer, self.upstream.stdin, "c2s"),
            daemon=True,
        )
        t_down = threading.Thread(
            target=self._pump,
            args=(self.upstream.stdout, sys.stdout.buffer, "s2c"),
            daemon=True,
        )
        t_err = threading.Thread(target=self._pump_stderr, daemon=True)
        t_up.start()
        t_down.start()
        t_err.start()

        rc = self.upstream.wait()
        t_down.join(timeout=2)
        self.recorder.close()
        return rc


def main(argv=None):
    parser = argparse.ArgumentParser(description="Instrumented MCP stdio logging proxy")
    parser.add_argument("--log-dir", required=True, help="Directory for JSONL telemetry")
    parser.add_argument("--server-id", default="server", help="Logical upstream server name")
    parser.add_argument("--label", default="benign", help="Traffic label (benign/attack/...)")
    parser.add_argument("--run-id", default=os.environ.get("MCP_RUN_ID"), help="Run identifier")
    parser.add_argument("--scenario-id", default=os.environ.get("MCP_SCENARIO_ID"), help="Scenario id (E1..E6)")
    parser.add_argument("--experiment-id", default=os.environ.get("MCP_EXPERIMENT_ID", "mcp-baseline"))
    parser.add_argument("--verbose", action="store_true",
                        help="Print a per-message trace to stderr (off by default)")
    parser.add_argument("server_cmd", nargs=argparse.REMAINDER,
                        help="-- followed by the upstream server command")
    args = parser.parse_args(argv)

    cmd = args.server_cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("No upstream server command given after '--'")
    args.server_cmd = cmd

    proxy = Proxy(args)
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
