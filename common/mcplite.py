"""
mcplite -- a tiny, dependency-free MCP (Model Context Protocol) stdio layer.

This module implements just enough of MCP over stdio to build small, controlled
lab servers and a scripted client driver for the SFU / CMPT 782 "MCP Traffic
Baselining and Exfiltration Detection" testbed.

Transport: newline-delimited JSON-RPC 2.0 over stdin/stdout (UTF-8), per the MCP
stdio transport specification. One JSON object per line; no embedded newlines.
Logging / telemetry MUST go to stderr or a file, never to stdout.

Nothing here depends on the `mcp` / `fastmcp` PyPI packages, so the testbed runs
offline and is immune to SDK version churn.
"""
from __future__ import annotations

import json
import sys
import threading
import queue
import subprocess
from typing import Any, Callable, Optional

PROTOCOL_VERSION = "2025-06-18"


# --------------------------------------------------------------------------- #
# Low-level framing helpers
# --------------------------------------------------------------------------- #
def encode(msg: dict) -> bytes:
    """Serialize a JSON-RPC message to a single newline-terminated UTF-8 line."""
    return (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def iter_messages(stream):
    """Yield parsed JSON objects from a binary, line-delimited input stream."""
    for raw in stream:
        line = raw.strip()
        if not line:
            continue
        try:
            yield json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            # Malformed line: skip rather than crash the transport.
            continue


# --------------------------------------------------------------------------- #
# Server side
# --------------------------------------------------------------------------- #
class Tool:
    def __init__(self, name: str, description: str, input_schema: dict,
                 handler: Callable[[dict], Any]):
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.handler = handler

    def spec(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class Server:
    """
    Minimal MCP server. Register tools, then call run().

    The handler for a tool receives the `arguments` dict and returns either a
    string (wrapped as a single text content block) or a full dict with keys
    {content, isError}. Raising an exception is reported as an MCP tool error.
    """

    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self._tools: dict[str, Tool] = {}
        self._lock = threading.Lock()
        self._out = sys.stdout.buffer
        self._out_lock = threading.Lock()

    # -- registration ----------------------------------------------------- #
    def tool(self, name: str, description: str, input_schema: Optional[dict] = None):
        def deco(fn):
            self.add_tool(name, description, input_schema or {"type": "object", "properties": {}}, fn)
            return fn
        return deco

    def add_tool(self, name, description, input_schema, handler):
        with self._lock:
            self._tools[name] = Tool(name, description, input_schema, handler)

    def replace_tools(self, tools: list[Tool]):
        """Swap the entire tool table (used for controlled E3 rug-pull fixtures)."""
        with self._lock:
            self._tools = {t.name: t for t in tools}

    def notify_tools_changed(self):
        self._send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})

    # -- io --------------------------------------------------------------- #
    def _send(self, msg: dict):
        with self._out_lock:
            self._out.write(encode(msg))
            self._out.flush()

    def _result(self, mid, result):
        self._send({"jsonrpc": "2.0", "id": mid, "result": result})

    def _error(self, mid, code, message):
        self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}})

    # -- main loop -------------------------------------------------------- #
    def run(self):
        for msg in iter_messages(sys.stdin.buffer):
            method = msg.get("method")
            mid = msg.get("id")
            if method == "initialize":
                self._result(mid, {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": self.name, "version": self.version},
                })
            elif method == "notifications/initialized":
                continue  # notification, no response
            elif method == "ping":
                self._result(mid, {})
            elif method == "tools/list":
                with self._lock:
                    tools = [t.spec() for t in self._tools.values()]
                self._result(mid, {"tools": tools})
            elif method == "tools/call":
                self._handle_call(msg)
            elif mid is not None:
                self._error(mid, -32601, f"Method not found: {method}")
            # unknown notifications are ignored

    def _handle_call(self, msg):
        mid = msg.get("id")
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        with self._lock:
            tool = self._tools.get(name)
        if tool is None:
            self._error(mid, -32602, f"Unknown tool: {name}")
            return
        try:
            out = tool.handler(args)
        except Exception as exc:  # report as tool error, not transport error
            self._result(mid, {
                "content": [{"type": "text", "text": f"ERROR: {exc}"}],
                "isError": True,
            })
            return
        if isinstance(out, dict) and "content" in out:
            self._result(mid, out)
        else:
            self._result(mid, {
                "content": [{"type": "text", "text": str(out)}],
                "isError": False,
            })


# --------------------------------------------------------------------------- #
# Client side
# --------------------------------------------------------------------------- #
class Client:
    """
    Minimal MCP stdio client. Spawns a command (which may be the logging proxy
    wrapping an upstream server), performs the handshake, and exposes
    list_tools() / call_tool(). Server->client notifications are collected.
    """

    def __init__(self, command: list[str], env: Optional[dict] = None, cwd: Optional[str] = None):
        self.command = command
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # let upstream/proxy stderr pass through to our console
            env=env,
            cwd=cwd,
            bufsize=0,
        )
        self._id = 0
        self._pending: dict[int, queue.Queue] = {}
        self._pending_lock = threading.Lock()
        self.notifications: list[dict] = []
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        for msg in iter_messages(self.proc.stdout):
            mid = msg.get("id")
            if mid is not None and ("result" in msg or "error" in msg):
                with self._pending_lock:
                    q = self._pending.pop(mid, None)
                if q is not None:
                    q.put(msg)
            elif msg.get("method", "").startswith("notifications/"):
                self.notifications.append(msg)

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _send(self, msg: dict):
        self.proc.stdin.write(encode(msg))
        self.proc.stdin.flush()

    def _request(self, method: str, params: Optional[dict] = None, timeout: float = 30.0) -> dict:
        mid = self._next_id()
        q: queue.Queue = queue.Queue()
        with self._pending_lock:
            self._pending[mid] = q
        self._send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        try:
            resp = q.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(f"Timed out waiting for response to {method}")
        if "error" in resp:
            raise RuntimeError(f"RPC error for {method}: {resp['error']}")
        return resp.get("result", {})

    def _notify(self, method: str, params: Optional[dict] = None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    # -- public API ------------------------------------------------------- #
    def initialize(self, client_name: str = "lab-driver") -> dict:
        result = self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": client_name, "version": "1.0.0"},
        })
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict]:
        return self._request("tools/list").get("tools", [])

    def call_tool(self, name: str, arguments: Optional[dict] = None) -> dict:
        return self._request("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self):
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def text_of(call_result: dict) -> str:
    """Extract concatenated text content from a tools/call result."""
    parts = []
    for block in call_result.get("content", []):
        if block.get("type") == "text":
            parts.append(block.get("text", ""))
    return "\n".join(parts)
