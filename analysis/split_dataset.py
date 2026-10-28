#!/usr/bin/env python3
"""
split_dataset.py -- split the per-call feature dataset into a benign set and a
malicious set, by ground-truth label, and enrich each record with the driving
prompt and the raw MCP request/response.

Reads   logs/features/calls.jsonl   (one row per tool call, with derived signals)
        logs/prompts.jsonl          (user prompts, joined by run_id)
        logs/raw/*.jsonl            (tool_arguments + response content, joined by
                                     connection_id + jsonrpc_id)
Writes  logs/features/benign.json       (JSON array of benign calls)
        logs/features/malicious.json    (JSON array of malicious calls)

Each output record keeps all the derived signals AND adds:
  user_prompt   -- the prompt that drove the run (null for the deterministic
                   drivers, which have no natural-language prompt -- see
                   run_policy.jsonl for their intent)
  mcp_request   -- the tool-call arguments, as a JSON string
  mcp_response  -- the response content, as a JSON string ([{type,text}, ...]);
                   bounded to the proxy's 800-char preview (mcp_response_truncated
                   flags when the real content was longer)

Bucketing is by the `label` stamped at capture time (the ground truth):
  benign     <- benign, opencode-benign, opencode   (authorized/benign work)
  malicious  <- attack, opencode-attack, sweep      (designed attacks / exfil)

Run from the project root:  python analysis/split_dataset.py
"""
from __future__ import annotations

import collections
import glob
import json
import os
import sys

BENIGN_LABELS = {"benign", "opencode-benign", "opencode"}
MALICIOUS_LABELS = {"attack", "opencode-attack", "sweep"}

SRC = os.path.join("logs", "features", "calls.jsonl")
PROMPTS = os.path.join("logs", "prompts.jsonl")
RAW_GLOB = os.path.join("logs", "raw", "*.jsonl")
OUT_BENIGN = os.path.join("logs", "features", "benign.json")
OUT_MALICIOUS = os.path.join("logs", "features", "malicious.json")


def load_prompts() -> dict:
    """run_id -> clean prompt text. Prefer the batch driver's text (clean) over
    the plugin's (which wraps the prompt in literal quotes)."""
    batch, plugin = {}, {}
    if not os.path.exists(PROMPTS):
        return {}
    with open(PROMPTS, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            rid = r.get("run_id")
            if not rid:
                continue
            text = (r.get("text") or "").strip()
            if r.get("source") == "batch":
                batch.setdefault(rid, text)
            else:
                plugin.setdefault(rid, text.strip('"'))
    out = dict(plugin)
    out.update(batch)  # batch wins
    return out


def load_raw() -> dict:
    """(connection_id, jsonrpc_id) -> {args, content, is_error, truncated}."""
    reqs, resps = {}, {}
    for path in glob.glob(RAW_GLOB):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                key = (r.get("connection_id"), r.get("jsonrpc_id"))
                if r.get("direction") == "c2s" and r.get("method") == "tools/call":
                    reqs[key] = r.get("tool_arguments")
                elif r.get("direction") == "s2c":
                    resps[key] = (r.get("content_preview"), bool(r.get("is_error")),
                                  bool(r.get("content_truncated")))
    merged = {}
    for key in set(reqs) | set(resps):
        args = reqs.get(key)
        prev, is_err, trunc = resps.get(key, (None, None, None))
        merged[key] = {"args": args, "content": prev, "is_error": is_err,
                       "truncated": trunc}
    return merged


def main() -> int:
    if not os.path.exists(SRC):
        print(f"ERROR: {SRC} not found. Run analysis/analyze.py first.", file=sys.stderr)
        return 1

    prompts = load_prompts()
    raw = load_raw()

    benign, malicious = [], []
    by_label = collections.Counter()
    scen_by_label = collections.defaultdict(collections.Counter)
    unknown = collections.Counter()
    enriched_prompt = 0

    with open(SRC, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            label = row.get("label")
            by_label[label] += 1
            scen_by_label[label][row.get("scenario_id")] += 1

            rid = row.get("run_id")
            key = (row.get("connection_id"), row.get("jsonrpc_id"))
            rawhit = raw.get(key, {})

            user_prompt = prompts.get(rid)
            if user_prompt:
                enriched_prompt += 1

            args = rawhit.get("args")
            mcp_request = json.dumps(args, ensure_ascii=False) if args is not None else "{}"

            content = rawhit.get("content")
            if content is None:
                mcp_response = "[]"
            else:
                mcp_response = json.dumps([{"type": "text", "text": content}],
                                          ensure_ascii=False)

            # friend-style fields first, then the original signals/metrics.
            rec = collections.OrderedDict()
            for k in ("run_id", "scenario_id", "label", "server_id", "tool_name",
                      "operation_class"):
                rec[k] = row.get(k)
            rec["user_prompt"] = user_prompt
            rec["mcp_request"] = mcp_request
            rec["mcp_response"] = mcp_response
            rec["mcp_response_truncated"] = rawhit.get("truncated")
            rec["is_error"] = rawhit.get("is_error", row.get("is_error"))
            for k, v in row.items():
                if k not in rec:
                    rec[k] = v

            if label in BENIGN_LABELS:
                benign.append(rec)
            elif label in MALICIOUS_LABELS:
                malicious.append(rec)
            else:
                unknown[label] += 1

    with open(OUT_BENIGN, "w", encoding="utf-8") as fh:
        json.dump(benign, fh, indent=2, ensure_ascii=False)
    with open(OUT_MALICIOUS, "w", encoding="utf-8") as fh:
        json.dump(malicious, fh, indent=2, ensure_ascii=False)

    print("calls per label (scenarios seen):")
    for label, n in by_label.most_common():
        bucket = ("benign" if label in BENIGN_LABELS
                  else "malicious" if label in MALICIOUS_LABELS else "UNKNOWN")
        print(f"  {str(label):18} {n:5}  -> {bucket:9}  {dict(scen_by_label[label])}")
    if unknown:
        print(f"\nWARNING: unmapped labels skipped: {dict(unknown)}", file=sys.stderr)

    print(f"\nenriched {enriched_prompt} calls with a user_prompt "
          f"(deterministic driver runs have none -- see run_policy.jsonl)")
    print(f"wrote {len(benign):5} benign calls    -> {OUT_BENIGN}")
    print(f"wrote {len(malicious):5} malicious calls -> {OUT_MALICIOUS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
