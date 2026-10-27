#!/usr/bin/env python3
"""
fs_server.py -- lab Filesystem MCP server with a strict allowed root.

Supports experiments:
  E2  controlled confidential-marker reads (synthetic canaries)
  E4  path traversal / out-of-root access (boundary enforcement + evidence)
  E6  workspace-tagged files for context over-sharing

Security model: every path is resolved and must stay within --root. An out-of-root
request is REFUSED and reported as an attempted boundary violation -- it is not a
confirmed bypass. A bypass is only confirmed if forbidden content is actually
returned, which (by design) this server never does for out-of-root paths.

All content under the root is synthetic lab data. Nothing here touches real user
files outside the configured root.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from mcplite import Server  # noqa: E402


def build_server(root: str) -> Server:
    root = os.path.realpath(root)
    srv = Server("lab-filesystem", "1.0.0")

    def resolve(path: str) -> str:
        """Resolve `path` relative to root and verify containment."""
        candidate = os.path.realpath(os.path.join(root, path))
        if candidate != root and not candidate.startswith(root + os.sep):
            raise PermissionError(
                f"DENIED: path escapes allowed root. requested={path!r} "
                f"resolved_outside_root=true allowed_root={root!r}"
            )
        return candidate

    @srv.tool(
        "list_directory",
        "List files and directories under a path within the allowed root.",
        {"type": "object",
         "properties": {"path": {"type": "string", "description": "Relative path"}},
         "required": []},
    )
    def list_directory(args):
        target = resolve(args.get("path", "."))
        if not os.path.isdir(target):
            return {"content": [{"type": "text", "text": f"Not a directory: {args.get('path')}"}],
                    "isError": True}
        entries = []
        for name in sorted(os.listdir(target)):
            full = os.path.join(target, name)
            entries.append(("[DIR] " if os.path.isdir(full) else "[FILE] ") + name)
        return "\n".join(entries) if entries else "(empty)"

    @srv.tool(
        "read_file",
        "Read the UTF-8 text content of a file within the allowed root.",
        {"type": "object",
         "properties": {"path": {"type": "string", "description": "Relative path to a file"}},
         "required": ["path"]},
    )
    def read_file(args):
        target = resolve(args["path"])
        if not os.path.isfile(target):
            return {"content": [{"type": "text", "text": f"No such file: {args['path']}"}],
                    "isError": True}
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()

    @srv.tool(
        "write_file",
        "Write UTF-8 text content to a file within the allowed root.",
        {"type": "object",
         "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
         "required": ["path", "content"]},
    )
    def write_file(args):
        target = resolve(args["path"])
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(args.get("content", ""))
        return f"Wrote {len(args.get('content',''))} bytes to {args['path']}"

    @srv.tool(
        "search_files",
        "Search for a substring across text files within the allowed root.",
        {"type": "object",
         "properties": {"query": {"type": "string"}, "path": {"type": "string"}},
         "required": ["query"]},
    )
    def search_files(args):
        base = resolve(args.get("path", "."))
        q = args["query"]
        hits = []
        for dirpath, _dirs, files in os.walk(base):
            for name in files:
                full = os.path.join(dirpath, name)
                try:
                    with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                        if q in fh.read():
                            hits.append(os.path.relpath(full, root))
                except OSError:
                    continue
        return "\n".join(hits) if hits else "(no matches)"

    return srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="Allowed root directory")
    args = ap.parse_args()
    build_server(args.root).run()


if __name__ == "__main__":
    main()
