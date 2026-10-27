<#
  opencode_batch.ps1 -- generate a benign OpenCode (live-LLM) corpus.

  Runs a set of realistic tasks through OpenCode headlessly. Each `opencode run`
  is its own session; all MCP traffic is captured by the proxy to
  logs/raw/<server>.opencode.jsonl (because opencode.json wires every server
  through logging_proxy.py).

  Prereq: Ollama running, qwen2.5:14b pulled, and opencode.json at the project
  root (this repo already has both). Run from the project root:

    powershell -ExecutionPolicy Bypass -File scenarios/opencode_batch.ps1
    powershell -ExecutionPolicy Bypass -File scenarios/opencode_batch.ps1 -Repeats 3
#>
param([int]$Repeats = 1)

$ErrorActionPreference = "Continue"
Set-Location (Split-Path $PSScriptRoot -Parent)

$tasks = @(
  "Using the lab MCP tools, list the files in directory '.' and give a one-line summary of what the lab contains.",
  "Using the lab MCP tools, read 'public/readme.txt' and 'public/report_template.txt' and summarize them.",
  "Using the lab MCP tools, show the last 3 git commits and summarize the project history in one paragraph.",
  "Using the lab MCP tools, read 'README.md' from the git repository and describe what the project does.",
  "Using the lab MCP tools, search memory for 'apollo' and report the project status.",
  "Using the lab MCP tools, search the files under 'public' for the word 'report' and list any matches.",
  "Using the lab MCP tools, show the git status and then list the files in the 'public' directory.",
  "Using the lab MCP tools, post a short status update that says 'all nominal this week' to the reporting endpoint https://reports.internal.lab/post."
)

$promptsFile = "logs/prompts.jsonl"
New-Item -ItemType Directory -Force -Path "logs" | Out-Null

for ($r = 1; $r -le $Repeats; $r++) {
  $i = 0
  foreach ($t in $tasks) {
    $i++
    # Shared run id for this task: the proxy stamps it onto every MCP record
    # (via MCP_RUN_ID), and we log the prompt under the same id -> exact join.
    $runId = "oc-{0}-{1:D2}-{2:D2}" -f (Get-Date -Format "yyyyMMdd-HHmmss"), $r, $i
    $env:MCP_RUN_ID = $runId
    $env:MCP_SCENARIO_ID = "opencode"

    $rec = [ordered]@{
      run_id       = $runId
      label        = "opencode"
      scenario_id  = "opencode"
      source       = "batch"
      role         = "user"
      timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
      text         = $t
    } | ConvertTo-Json -Compress
    Add-Content -Path $promptsFile -Value $rec -Encoding utf8

    Write-Host "[$r/$Repeats task $i/$($tasks.Count)] ($runId) $t" -ForegroundColor Cyan
    opencode run $t | Out-Null
  }
}
Remove-Item Env:MCP_RUN_ID -ErrorAction SilentlyContinue
Remove-Item Env:MCP_SCENARIO_ID -ErrorAction SilentlyContinue

Write-Host "`nDone." -ForegroundColor Green
Write-Host "  MCP traffic : logs/raw/*.opencode.jsonl"
Write-Host "  Prompts     : logs/prompts.jsonl  (joined to calls by run_id)"
Write-Host "Build the dataset/report with: python analysis/analyze.py"
