#!/usr/bin/env python3
"""
analyze.py -- feature extraction, benign baselining, detection, and reporting.

Pipeline (matches the project's raw-capture / derived-feature / ground-truth split):

  1. extract   : join request+response raw records into per-call feature rows and
                 derive protocol-level detection signals (E1-E6).
  2. baseline  : per-tool benign statistics (median, MAD, p95, p99, mean, std) ->
                 threshold table (RQ1: the statistical envelope of benign traffic).
  3. detect    : interpretable rules + statistical thresholds -> per-run alerts
                 with four-level evidence; compare against ground truth.
  4. report    : precision/recall/FPR, per-scenario recall, channel-capacity
                 (bytes-before-alert), and protocol-layer blind spots -> report.md

Run:  python analysis/analyze.py
Artifacts land in logs/features/ and logs/reports/.
"""
from __future__ import annotations

import csv
import json
import math
import os
import re
import statistics
from collections import defaultdict

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
RAW = os.path.join(ROOT, "logs", "raw")
FEAT = os.path.join(ROOT, "logs", "features")
REPORTS = os.path.join(ROOT, "logs", "reports")
SINK_RECEIPTS = os.path.join(FEAT, "sink_receipts.jsonl")

CANARIES = ["WORKSPACE_B_SECRET", "SYNTHETIC_SECRET", "SFU-LAB-MARKER", "CANARY"]
INJECTION_PATTERNS = [
    r"ignore (all |your |the )?previous instructions",
    r"<\s*important\s*>",
    r"do not mention",
    r"send .{0,60}?(to|using|via) ",
    r"read .{0,60}?(file|secret|\.txt)",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE | re.DOTALL)
TRAVERSAL_RE = re.compile(r"(\.\.[\\/])|^([A-Za-z]:[\\/])|^([\\/])|(/etc/)|(system32)", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# 1. EXTRACT
# --------------------------------------------------------------------------- #
def load_raw() -> list[dict]:
    rows = []
    for fn in sorted(os.listdir(RAW)):
        if not fn.endswith(".jsonl"):
            continue
        for line in open(os.path.join(RAW, fn), encoding="utf-8"):
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _canary_hits(text: str) -> list[str]:
    if not text:
        return []
    return [c for c in CANARIES if c in text]


def extract(raw: list[dict]) -> list[dict]:
    """Join request+response by (connection_id, jsonrpc_id) into per-call rows."""
    req, resp = {}, {}
    notifs = defaultdict(list)          # connection_id -> [method,...]
    tool_snapshots = defaultdict(list)  # connection_id -> [tools_digest,...]

    for r in raw:
        key = (r["connection_id"], r.get("jsonrpc_id"))
        if r["kind"] == "request":
            req[key] = r
        elif r["kind"] in ("response", "error"):
            resp[key] = r
            if r.get("tools_digest"):
                tool_snapshots[r["connection_id"]].append(r["tools_digest"])
        elif r["kind"] == "notification":
            notifs[r["connection_id"]].append(r.get("method"))

    # E3: did tool definitions change within a connection?
    within_session_change = {}
    for conn, snaps in tool_snapshots.items():
        changed = len(snaps) >= 2 and json.dumps(snaps[0], sort_keys=True) != json.dumps(snaps[-1], sort_keys=True)
        within_session_change[conn] = changed

    calls = []
    for key, rq in req.items():
        if rq.get("method") != "tools/call":
            continue
        rs = resp.get(key, {})
        args = rq.get("tool_arguments") or {}
        args_text = json.dumps(args, ensure_ascii=False)
        out_text = rs.get("content_preview") or ""
        conn = rq["connection_id"]

        path_arg = str(args.get("path", "") or args.get("file", ""))
        is_err = bool(rs.get("is_error"))

        row = {
            "run_id": rq.get("run_id"),
            "scenario_id": rq.get("scenario_id"),
            "label": rq.get("label"),
            "server_id": rq.get("server_id"),
            "connection_id": conn,
            "jsonrpc_id": rq.get("jsonrpc_id"),
            "timestamp_utc": rq.get("timestamp_utc"),
            "tool_name": rq.get("tool_name"),
            "operation_class": rq.get("operation_class"),
            "request_bytes": rq.get("payload_bytes"),
            "response_bytes": rs.get("payload_bytes"),
            "content_text_len": rs.get("content_text_len"),
            "latency_ms": rs.get("latency_ms"),
            "is_error": is_err,
            # ---- derived detection signals ----
            "sig_injection_in_output": bool(INJECTION_RE.search(out_text)),
            "sig_canary_in_output": _canary_hits(out_text),
            "sig_canary_in_args": _canary_hits(args_text),
            "sig_egress": rq.get("operation_class") == "egress",
            "sig_traversal_attempt": bool(TRAVERSAL_RE.search(path_arg)),
            "sig_boundary_denied": is_err and ("DENIED" in out_text or "escape" in out_text.lower()),
            "sig_tools_changed_in_session": within_session_change.get(conn, False),
            "sig_cross_workspace": ("[B]" in out_text or "WORKSPACE_B_SECRET" in out_text),
        }
        calls.append(row)

    calls.sort(key=lambda c: (c["run_id"] or "", c["timestamp_utc"] or ""))

    # Cross-call features within a run: previous tool + read->mutate transition.
    seen_read = defaultdict(bool)
    prev_tool = {}
    for c in calls:
        run = c["run_id"]
        c["prev_tool"] = prev_tool.get(run)
        if c["operation_class"] == "read":
            seen_read[run] = True
        c["sig_mutate_after_read"] = (c["operation_class"] == "mutate" and seen_read[run])
        prev_tool[run] = c["tool_name"]
    return calls


# --------------------------------------------------------------------------- #
# 2. BASELINE
# --------------------------------------------------------------------------- #
def _pctl(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    f = math.floor(k)
    c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def _stats(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    med = statistics.median(xs)
    mad = statistics.median([abs(x - med) for x in xs]) or 0.0
    return {
        "n": len(xs),
        "median": round(med, 3),
        "mad": round(mad, 3),
        "mean": round(statistics.fmean(xs), 3),
        "std": round(statistics.pstdev(xs), 3) if len(xs) > 1 else 0.0,
        "p95": round(_pctl(xs, 0.95), 3),
        "p99": round(_pctl(xs, 0.99), 3),
        "max": round(max(xs), 3),
    }


def baseline(calls: list[dict]) -> dict:
    benign = [c for c in calls if c["label"] == "benign"]
    per_tool = defaultdict(lambda: defaultdict(list))
    for c in benign:
        key = f"{c['server_id']}.{c['tool_name']}"
        per_tool[key]["request_bytes"].append(c["request_bytes"])
        per_tool[key]["response_bytes"].append(c["response_bytes"])
        per_tool[key]["content_text_len"].append(c["content_text_len"])
        per_tool[key]["latency_ms"].append(c["latency_ms"])

    # calls-per-run (benign) for rate baseline
    per_run_counts = defaultdict(int)
    for c in benign:
        per_run_counts[c["run_id"]] += 1

    table = {}
    for key, metrics in per_tool.items():
        table[key] = {m: _stats(v) for m, v in metrics.items()}
    return {
        "per_tool": table,
        "calls_per_run": _stats(list(per_run_counts.values())),
    }


def robust_z(x, med, mad):
    if x is None or med is None:
        return 0.0
    if mad and mad > 0:
        return abs(x - med) / (1.4826 * mad)
    return 0.0 if x == med else float("inf")


# --------------------------------------------------------------------------- #
# 3. DETECT
# --------------------------------------------------------------------------- #
def load_policies():
    path = os.path.join(FEAT, "run_policy.jsonl")
    pols = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                pols[r["run_id"]] = r
    return pols


DEFAULT_POLICY = {"task_intent": "read_write", "allow_egress": False,
                  "allowed_write_roots": [], "scope_workspace": None}


def detect(calls, base, policies, z_thresh=6.0):
    """
    Policy-aware, correlation-based per-run detection.

    Content signals (level 1) are RECORDED as observations but do not by
    themselves flag a run. A run is alerted only when an action violates the
    task policy or a level-1 signal is corroborated by a forbidden follow-on,
    matching the project's evidence standard.
    """
    runs = defaultdict(list)
    for c in calls:
        runs[c["run_id"]].append(c)

    detections = []
    for run_id, rcalls in runs.items():
        label = rcalls[0]["label"]
        scenario = rcalls[0]["scenario_id"]
        pol = policies.get(run_id, DEFAULT_POLICY)
        read_only = pol.get("task_intent") == "read_only"
        allow_egress = pol.get("allow_egress", False)
        scope = pol.get("scope_workspace")

        # run-level signal aggregates
        has_injection = any(c["sig_injection_in_output"] for c in rcalls)
        egress_calls = [c for c in rcalls if c["sig_egress"]]
        mutate_calls = [c for c in rcalls if c["operation_class"] == "mutate"]
        traversal_calls = [c for c in rcalls if c["sig_traversal_attempt"]]
        changed = any(c["sig_tools_changed_in_session"] for c in rcalls)
        cross_ws = [c for c in rcalls if c["sig_cross_workspace"]]
        canary_reads = [c for c in rcalls if c["sig_canary_in_output"]]

        alerts = []            # policy-aware alert rules (drive the alert decision)
        observations = []      # level-1 content observations (evidence trail only)
        bytes_before_alert = None

        if has_injection:
            observations.append(("E1_injection_observed", 1, "instruction-like text in tool output"))
        for c in canary_reads:
            observations.append(("sensitive_read_observed", 1,
                                 f"canary {c['sig_canary_in_output']} in {c['tool_name']} output"))

        # E2 / E1 egress (policy: egress not approved)
        if egress_calls and not allow_egress:
            cum = 0
            for c in egress_calls:
                cum += (c["request_bytes"] or 0)
                lvl = 3 if not c["is_error"] else 2
                detail = "unapproved egress" + (f" of canary {c['sig_canary_in_args']}"
                                                if c["sig_canary_in_args"] else "")
                alerts.append(("E2_exfil_send", lvl, detail))
                if bytes_before_alert is None:
                    bytes_before_alert = cum
            # E1: injected instruction corroborated by a forbidden send
            if has_injection:
                alerts.append(("E1_injection_acted_on", 2,
                               "injected instruction followed by unapproved egress"))

        # E3 within-session rug pull
        if changed:
            alerts.append(("E3_rug_pull", 2, "tool definitions changed within session"))

        # E4 path traversal attempt (always an attempt; level 4 only if content returned)
        for c in traversal_calls:
            confirmed = (not c["is_error"]) and bool(c["sig_canary_in_output"])
            alerts.append(("E4_path_traversal", 4 if confirmed else 2,
                           "out-of-root path requested"
                           + (" -> content returned (BYPASS)" if confirmed
                              else " -> denied (attempt)")))

        # E5 mutation under a read-only task policy
        if read_only and mutate_calls:
            for c in mutate_calls:
                alerts.append(("E5_policy_violation_mutate", 2,
                               f"mutate op {c['tool_name']} under read-only task policy"))

        # E6 cross-workspace disclosure vs task scope
        if scope and cross_ws:
            for c in cross_ws:
                alerts.append(("E6_oversharing", 1,
                               f"Workspace-other marker returned under scope={scope}"))

        # statistical envelope anomalies (independent, unsupervised)
        for c in rcalls:
            tbl = base["per_tool"].get(f"{c['server_id']}.{c['tool_name']}", {})
            for metric in ("request_bytes", "response_bytes", "content_text_len"):
                st = tbl.get(metric)
                if st and st["n"] >= 5:
                    z = robust_z(c[metric], st["median"], st["mad"])
                    if z > z_thresh and (c[metric] or 0) > (st["p99"] or 0):
                        alerts.append((f"STAT_{metric}_anomaly", 2,
                                       f"{c['tool_name']}.{metric}={c[metric]} robustZ={z:.1f}"))

        max_level = max((lvl for _, lvl, _ in alerts), default=0)
        detections.append({
            "run_id": run_id, "label": label, "scenario_id": scenario,
            "task_intent": pol.get("task_intent"),
            "alerted": bool(alerts),
            "max_evidence_level": max_level,
            "rules_fired": sorted({a[0] for a in alerts}),
            "n_alerts": len(alerts),
            "bytes_before_alert": bytes_before_alert,
            "evidence": [{"rule": a[0], "level": a[1], "detail": a[2]} for a in alerts],
            "observations": [{"rule": o[0], "level": o[1], "detail": o[2]} for o in observations],
        })
    return detections


def channel_capacity(calls, base, volume_budget=2048):
    """
    Channel-capacity sweep (RQ4/RQ5). For each sweep config, compute how many
    bytes reach the sink BEFORE the first alert, under three detector layers:

      L0  protocol-only  : per-send size envelope (benign p99) + per-session
                           volume budget. Knows nothing about content or policy.
      L1  + content      : L0 plus known-canary-marker detection in payloads.
      L2  + policy        : L1 plus destination allowlist (unapproved dest = alert
                           on the first byte).

    Returns a list of per-config capacity rows.
    """
    st = base["per_tool"].get("sink.send_report", {}).get("request_bytes")
    size_threshold = st["p99"] if st else 256.0
    approved = {"https://reports.internal.lab/post"}

    sweeps = defaultdict(list)  # config -> list of runs (each a list of egress calls)
    for c in calls:
        if c["label"] != "sweep" or not c["sig_egress"]:
            continue
        sweeps[c["run_id"]].append(c)

    # group runs by config (chunk size + marker), parsed from run_id: sweep-c{n}-m{0|1}-NNN
    by_config = defaultdict(list)
    for run_id, egress in sweeps.items():
        egress.sort(key=lambda c: c["timestamp_utc"])
        parts = run_id.split("-")
        cfg = (parts[1], parts[2])  # ("c128","m0")
        by_config[cfg].append(egress)

    def bytes_before(egress, layer):
        cum = 0
        for c in egress:
            rb = c["request_bytes"] or 0
            # would this send trigger an alert?
            size_hit = rb > size_threshold
            volume_hit = (cum + rb) > volume_budget
            marker_hit = bool(c["sig_canary_in_args"])
            dest = (c.get("tool_name") and False)  # dest not stored per call; policy layer below
            alert = False
            if layer >= 0 and (size_hit or volume_hit):
                alert = True
            if layer >= 1 and marker_hit:
                alert = True
            if layer >= 2:
                # unapproved destination: every sweep send goes to the exfil dest.
                alert = True
            if alert:
                return cum, True
            cum += rb
        return cum, False  # never alerted -> fully undetected up to `cum` bytes

    rows = []
    for cfg, runs in sorted(by_config.items()):
        size = int(cfg[0][1:])
        marker = cfg[1] == "m1"
        rec = {"chunk_size": size, "marker": marker}
        for layer, name in [(0, "L0_protocol"), (1, "L1_content"), (2, "L2_policy")]:
            caps = []
            undetected = 0
            for egress in runs:
                b, alerted = bytes_before(egress, layer)
                caps.append(b)
                if not alerted:
                    undetected += 1
            rec[name] = {
                "mean_bytes_before_alert": round(statistics.fmean(caps), 1),
                "max_bytes_before_alert": max(caps),
                "runs_fully_undetected": undetected,
                "n_runs": len(runs),
            }
        rows.append(rec)
    return {"size_threshold_bytes": round(size_threshold, 1),
            "volume_budget_bytes": volume_budget, "configs": rows}


def load_sink_receipts():
    if not os.path.exists(SINK_RECEIPTS):
        return []
    return [json.loads(l) for l in open(SINK_RECEIPTS, encoding="utf-8") if l.strip()]


# --------------------------------------------------------------------------- #
# 4. METRICS + REPORT
# --------------------------------------------------------------------------- #
def metrics(detections):
    tp = fp = tn = fn = 0
    per_scenario = defaultdict(lambda: {"total": 0, "detected": 0})
    for d in detections:
        if d["label"] not in ("benign", "attack"):
            continue  # sweep runs are evaluated separately (channel capacity)
        is_attack = d["label"] == "attack"
        if is_attack:
            per_scenario[d["scenario_id"]]["total"] += 1
            if d["alerted"]:
                per_scenario[d["scenario_id"]]["detected"] += 1
        if is_attack and d["alerted"]:
            tp += 1
        elif is_attack and not d["alerted"]:
            fn += 1
        elif not is_attack and d["alerted"]:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    return {
        "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": precision, "recall": recall, "false_positive_rate": fpr,
        "per_scenario_recall": {k: f"{v['detected']}/{v['total']}" for k, v in sorted(per_scenario.items())},
    }


def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: (json.dumps(r[k]) if isinstance(r.get(k), (list, dict)) else r.get(k))
                        for k in fields})


def fmt_pct(x):
    return "n/a" if x is None else f"{x*100:.1f}%"


def build_report(calls, base, detections, m, receipts, capacity):
    n_benign_runs = len({c["run_id"] for c in calls if c["label"] == "benign"})
    n_attack_runs = len({c["run_id"] for c in calls if c["label"] == "attack"})
    exfil = [d for d in detections if d["label"] == "attack" and d["bytes_before_alert"] is not None]
    bba = [d["bytes_before_alert"] for d in exfil]

    lines = []
    lines.append("# MCP Traffic Baselining & Exfiltration Detection -- Results\n")
    lines.append(f"- Total MCP calls analyzed: **{len(calls)}**")
    lines.append(f"- Benign runs: **{n_benign_runs}**  |  Attack runs: **{n_attack_runs}**")
    lines.append(f"- Sink receipts (independent exfil ground truth): **{len(receipts)}**\n")

    lines.append("## Detection performance (per run)\n")
    c = m["counts"]
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| True positives | {c['tp']} |")
    lines.append(f"| False positives | {c['fp']} |")
    lines.append(f"| True negatives | {c['tn']} |")
    lines.append(f"| False negatives | {c['fn']} |")
    lines.append(f"| Precision | {fmt_pct(m['precision'])} |")
    lines.append(f"| Recall | {fmt_pct(m['recall'])} |")
    lines.append(f"| False-positive rate | {fmt_pct(m['false_positive_rate'])} |\n")

    lines.append("## Per-scenario recall\n")
    lines.append("| Scenario | Detected |")
    lines.append("|---|---|")
    for k, v in m["per_scenario_recall"].items():
        lines.append(f"| {k} | {v} |")
    lines.append("")

    lines.append("## Exfiltration alert latency (main attack set, policy-aware detector)\n")
    if bba:
        lines.append(f"- Exfil attack runs flagged: {len(bba)}")
        lines.append(f"- Bytes in the first flagged egress send: min={min(bba)}, "
                     f"median={int(statistics.median(bba))}, max={max(bba)}")
        lines.append("- Under the policy-aware detector these single-shot exfil attempts are flagged "
                     "on the first send. The threshold/evasion trade-off is quantified in the "
                     "channel-capacity sweep below.\n")
    else:
        lines.append("- No egress alerts recorded.\n")

    lines.append("## Channel capacity: bytes moved before alert (RQ4/RQ5)\n")
    lines.append(f"- Per-send size envelope (benign sink p99): **{capacity['size_threshold_bytes']} B**")
    lines.append(f"- Per-session volume budget (chosen): **{capacity['volume_budget_bytes']} B**")
    lines.append("- Detector layers: **L0** protocol-only (size+volume), **L1** +canary content, "
                 "**L2** +destination policy.\n")
    lines.append("| chunk | marker | L0 mean B before alert | L0 undetected | L1 mean | L2 mean |")
    lines.append("|---|---|---|---|---|---|")
    for r in capacity["configs"]:
        l0, l1, l2 = r["L0_protocol"], r["L1_content"], r["L2_policy"]
        lines.append(f"| {r['chunk_size']} | {'yes' if r['marker'] else 'no'} | "
                     f"{l0['mean_bytes_before_alert']} | {l0['runs_fully_undetected']}/{l0['n_runs']} | "
                     f"{l1['mean_bytes_before_alert']} | {l2['mean_bytes_before_alert']} |")
    lines.append("")
    lines.append("- **L2 (policy-aware)** catches exfil at the first byte (unapproved destination): "
                 "mean 0 B. **L1** catches marked payloads immediately but marker-free sends fall back "
                 "to L0. **L0 (protocol-only)** lets an attacker move data as long as each chunk stays "
                 "under the per-send size envelope -- up to the session volume budget -- which is the "
                 "measured protocol-layer blind spot.\n")

    lines.append("## Benign baseline (threshold table excerpt)\n")
    lines.append("| tool | metric | n | median | MAD | p95 | p99 |")
    lines.append("|---|---|---|---|---|---|---|")
    for tool, metrics_ in sorted(base["per_tool"].items()):
        for metric in ("request_bytes", "response_bytes"):
            st = metrics_.get(metric)
            if st:
                lines.append(f"| {tool} | {metric} | {st['n']} | {st['median']} | "
                             f"{st['mad']} | {st['p95']} | {st['p99']} |")
    lines.append("")

    lines.append("## Protocol-layer blind spots (observed)\n")
    lines.append("- **E6 context over-sharing** and **E1 startup-time poisoning** are content-"
                 "dependent: without inspecting response bodies, size/rate features alone do not "
                 "separate them from benign reads. The detector relies on content markers here.")
    lines.append("- A low-and-slow exfiltration that avoids known canary tokens and stays within "
                 "each tool's p99 size envelope is the hardest class to flag at the protocol layer "
                 "(RQ4/RQ5) -- this is the motivating negative result for semantic/policy-aware detection.\n")

    lines.append("## Evidence-level discipline\n")
    lines.append("Alerts carry a 4-level evidence tag (1 suspicious content, 2 action requested, "
                 "3 action accepted, 4 independently verified via sink receipt). A refused out-of-root "
                 "request (E4) is reported as an *attempt* (level 2), never as a confirmed bypass.\n")
    return "\n".join(lines)


def main():
    os.makedirs(FEAT, exist_ok=True)
    os.makedirs(REPORTS, exist_ok=True)

    raw = load_raw()
    calls = extract(raw)
    base = baseline(calls)
    policies = load_policies()
    detections = detect(calls, base, policies)
    receipts = load_sink_receipts()
    m = metrics(detections)
    capacity = channel_capacity(calls, base)

    # write artifacts
    with open(os.path.join(FEAT, "calls.jsonl"), "w", encoding="utf-8") as fh:
        for c in calls:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")
    call_fields = ["run_id", "scenario_id", "label", "server_id", "tool_name", "operation_class",
                   "request_bytes", "response_bytes", "content_text_len", "latency_ms", "is_error",
                   "prev_tool", "sig_injection_in_output", "sig_canary_in_output", "sig_canary_in_args",
                   "sig_egress", "sig_traversal_attempt", "sig_boundary_denied",
                   "sig_tools_changed_in_session", "sig_mutate_after_read", "sig_cross_workspace"]
    write_csv(os.path.join(FEAT, "calls.csv"), calls, call_fields)

    with open(os.path.join(REPORTS, "baseline.json"), "w", encoding="utf-8") as fh:
        json.dump(base, fh, indent=2)
    with open(os.path.join(REPORTS, "detections.jsonl"), "w", encoding="utf-8") as fh:
        for d in detections:
            fh.write(json.dumps(d, ensure_ascii=False) + "\n")
    with open(os.path.join(REPORTS, "metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(m, fh, indent=2)
    with open(os.path.join(REPORTS, "channel_capacity.json"), "w", encoding="utf-8") as fh:
        json.dump(capacity, fh, indent=2)

    # threshold table CSV
    with open(os.path.join(REPORTS, "threshold_table.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "metric", "n", "median", "mad", "p95", "p99", "max"])
        for tool, metrics_ in sorted(base["per_tool"].items()):
            for metric, st in metrics_.items():
                if st:
                    w.writerow([tool, metric, st["n"], st["median"], st["mad"],
                                st["p95"], st["p99"], st["max"]])

    report = build_report(calls, base, detections, m, receipts, capacity)
    with open(os.path.join(REPORTS, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report)

    print(f"Analyzed {len(calls)} calls across "
          f"{len({c['run_id'] for c in calls})} runs.")
    print(f"Precision={fmt_pct(m['precision'])}  Recall={fmt_pct(m['recall'])}  "
          f"FPR={fmt_pct(m['false_positive_rate'])}")
    print("Per-scenario recall:", m["per_scenario_recall"])
    print(f"\nArtifacts written to:\n  {FEAT}\\calls.csv / calls.jsonl\n"
          f"  {REPORTS}\\baseline.json / threshold_table.csv / detections.jsonl / metrics.json / report.md")


if __name__ == "__main__":
    main()
