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

for ($r = 1; $r -le $Repeats; $r++) {
  $i = 0
  foreach ($t in $tasks) {
    $i++
    Write-Host "[$r/$Repeats task $i/$($tasks.Count)] $t" -ForegroundColor Cyan
    opencode run $t | Out-Null
  }
}
Write-Host "`nDone. Captured traffic is in logs/raw/*.opencode.jsonl" -ForegroundColor Green
Write-Host "Build the dataset/report with: python analysis/analyze.py"
