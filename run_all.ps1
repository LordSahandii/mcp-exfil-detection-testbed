<#
  run_all.ps1 -- one-command pipeline for the MCP traffic baselining testbed.

  Builds the synthetic lab, generates the benign corpus, the labelled E1-E6
  attack corpus, and the tunable exfiltration sweep (all through the logging
  proxy), then runs feature extraction, baselining, detection and reporting.

  Usage:
    powershell -ExecutionPolicy Bypass -File run_all.ps1
    powershell -ExecutionPolicy Bypass -File run_all.ps1 -Runs 30 -SweepRepeats 5 -Fresh
#>
param(
  [int]$Runs = 20,
  [int]$SweepRepeats = 3,
  [switch]$Fresh
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Py = "python"

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

if ($Fresh) {
  Step "Clearing previous logs"
  Remove-Item -Force -ErrorAction SilentlyContinue "$Root/logs/raw/*.jsonl"
  Remove-Item -Force -ErrorAction SilentlyContinue "$Root/logs/features/*.jsonl"
  Remove-Item -Force -ErrorAction SilentlyContinue "$Root/logs/features/*.csv"
  Remove-Item -Force -ErrorAction SilentlyContinue "$Root/logs/reports/*"
}

Step "Building synthetic lab fixtures"
& $Py "$Root/scenarios/build_lab.py" --lab-dir "$Root/lab"

Step "Generating BENIGN corpus ($Runs iterations x 6 task types)"
& $Py "$Root/scenarios/run_benign.py" --runs $Runs

Step "Generating ATTACK corpus (E1-E6, $Runs runs each)"
& $Py "$Root/scenarios/run_attacks.py" --runs $Runs

Step "Running exfiltration sweep ($SweepRepeats repeats)"
& $Py "$Root/scenarios/exfil_sweep.py" --repeats $SweepRepeats

Step "Analyzing (features -> baseline -> detect -> report)"
& $Py "$Root/analysis/analyze.py"

Step "Done"
Write-Host "Report:   $Root/logs/reports/report.md"
Write-Host "Dataset:  $Root/logs/features/calls.csv  (and calls.jsonl)"
Write-Host "Raw logs: $Root/logs/raw/*.jsonl"
