# Sample output

A committed snapshot of one full `run_all.ps1` pass (20 iterations × 6 benign
task types, 20 × E1–E6 attack runs, exfiltration sweep × 3). Regenerate with:

```powershell
powershell -ExecutionPolicy Bypass -File run_all.ps1 -Fresh
```

| File | What it is |
|---|---|
| `report.md` | Human-readable summary (metrics, channel capacity, blind spots) |
| `metrics.json` | Precision / recall / FPR / per-scenario recall |
| `baseline.json` | Per-tool benign statistical envelope |
| `threshold_table.csv` | Per-tool size thresholds (median/MAD/p95/p99) |
| `channel_capacity.json` | Bytes-before-alert per sweep config (L0/L1/L2) |
| `detections.jsonl` | Per-run alerts with 4-level evidence |
| `calls.csv` | The per-call feature dataset (1504 rows) |

Headline pilot result: precision 100%, recall 100%, FPR 0% across E1–E6 on this
controlled synthetic set. These are pilot numbers — see `../docs/DESIGN.md` §5.
