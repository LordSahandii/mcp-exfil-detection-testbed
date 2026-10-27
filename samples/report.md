# MCP Traffic Baselining & Exfiltration Detection -- Results

- Total MCP calls analyzed: **1504**
- Benign runs: **120**  |  Attack runs: **120**
- Sink receipts (independent exfil ground truth): **804**

## Detection performance (per run)

| Metric | Value |
|---|---|
| True positives | 120 |
| False positives | 0 |
| True negatives | 120 |
| False negatives | 0 |
| Precision | 100.0% |
| Recall | 100.0% |
| False-positive rate | 0.0% |

## Per-scenario recall

| Scenario | Detected |
|---|---|
| E1 | 20/20 |
| E2 | 20/20 |
| E3 | 20/20 |
| E4 | 20/20 |
| E5 | 20/20 |
| E6 | 20/20 |

## Exfiltration alert latency (main attack set, policy-aware detector)

- Exfil attack runs flagged: 40
- Bytes in the first flagged egress send: min=238, median=241, max=245
- Under the policy-aware detector these single-shot exfil attempts are flagged on the first send. The threshold/evasion trade-off is quantified in the channel-capacity sweep below.

## Channel capacity: bytes moved before alert (RQ4/RQ5)

- Per-send size envelope (benign sink p99): **544.8 B**
- Per-session volume budget (chosen): **2048 B**
- Detector layers: **L0** protocol-only (size+volume), **L1** +canary content, **L2** +destination policy.

| chunk | marker | L0 mean B before alert | L0 undetected | L1 mean | L2 mean |
|---|---|---|---|---|---|
| 1024 | no | 0.0 | 0/3 | 0.0 | 0.0 |
| 1024 | yes | 0.0 | 0/3 | 0.0 | 0.0 |
| 128 | no | 2009.0 | 0/3 | 2009.0 | 0.0 |
| 128 | yes | 1824.0 | 0/3 | 0.0 | 0.0 |
| 256 | no | 1660.0 | 0/3 | 1660.0 | 0.0 |
| 256 | yes | 1728.0 | 0/3 | 0.0 | 0.0 |
| 512 | no | 0.0 | 0/3 | 0.0 | 0.0 |
| 512 | yes | 0.0 | 0/3 | 0.0 | 0.0 |
| 64 | no | 2008.0 | 0/3 | 2008.0 | 0.0 |
| 64 | yes | 1920.0 | 0/3 | 0.0 | 0.0 |

- **L2 (policy-aware)** catches exfil at the first byte (unapproved destination): mean 0 B. **L1** catches marked payloads immediately but marker-free sends fall back to L0. **L0 (protocol-only)** lets an attacker move data as long as each chunk stays under the per-send size envelope -- up to the session volume budget -- which is the measured protocol-layer blind spot.

## Benign baseline (threshold table excerpt)

| tool | metric | n | median | MAD | p95 | p99 |
|---|---|---|---|---|---|---|
| filesystem.list_directory | request_bytes | 40 | 108.5 | 2.5 | 111.0 | 111.0 |
| filesystem.list_directory | response_bytes | 40 | 154.0 | 3.0 | 157.0 | 157.0 |
| filesystem.read_file | request_bytes | 60 | 126.0 | 0.0 | 126.0 | 126.0 |
| filesystem.read_file | response_bytes | 60 | 143.0 | 0.0 | 143.0 | 143.0 |
| filesystem.search_files | request_bytes | 20 | 126.0 | 0.0 | 127.0 | 127.0 |
| filesystem.search_files | response_bytes | 20 | 101.0 | 0.0 | 116.0 | 116.0 |
| filesystem.write_file | request_bytes | 20 | 165.0 | 0.0 | 165.0 | 165.0 |
| filesystem.write_file | response_bytes | 20 | 128.0 | 0.0 | 128.0 | 128.0 |
| git.git_log | request_bytes | 40 | 102.0 | 0.0 | 102.0 | 102.0 |
| git.git_log | response_bytes | 40 | 391.0 | 0.0 | 391.0 | 391.0 |
| git.git_show | request_bytes | 20 | 102.0 | 0.0 | 102.0 | 102.0 |
| git.git_show | response_bytes | 20 | 439.0 | 0.0 | 439.0 | 439.0 |
| git.git_status | request_bytes | 20 | 92.0 | 0.0 | 92.0 | 92.0 |
| git.git_status | response_bytes | 20 | 144.0 | 0.0 | 144.0 | 144.0 |
| git.read_file | request_bytes | 20 | 109.0 | 0.0 | 109.0 | 109.0 |
| git.read_file | response_bytes | 20 | 350.0 | 0.0 | 350.0 | 350.0 |
| memory.search_memory | request_bytes | 40 | 127.0 | 0.0 | 133.0 | 133.0 |
| memory.search_memory | response_bytes | 40 | 254.0 | 0.0 | 254.0 | 254.0 |
| poisoned.get_weather | request_bytes | 20 | 110.0 | 1.0 | 111.0 | 111.0 |
| poisoned.get_weather | response_bytes | 20 | 143.0 | 1.0 | 144.0 | 144.0 |
| sink.send_report | request_bytes | 20 | 431.0 | 73.0 | 531.85 | 544.77 |
| sink.send_report | response_bytes | 20 | 199.0 | 0.0 | 199.0 | 199.0 |

## Protocol-layer blind spots (observed)

- **E6 context over-sharing** and **E1 startup-time poisoning** are content-dependent: without inspecting response bodies, size/rate features alone do not separate them from benign reads. The detector relies on content markers here.
- A low-and-slow exfiltration that avoids known canary tokens and stays within each tool's p99 size envelope is the hardest class to flag at the protocol layer (RQ4/RQ5) -- this is the motivating negative result for semantic/policy-aware detection.

## Evidence-level discipline

Alerts carry a 4-level evidence tag (1 suspicious content, 2 action requested, 3 action accepted, 4 independently verified via sink receipt). A refused out-of-root request (E4) is reported as an *attempt* (level 2), never as a confirmed bypass.
