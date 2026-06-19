# run-pipeline-session.ps1 - batch CRS rule-generation pipeline (SESSION-SHARED variant)
#
# Khác với run-pipeline.ps1: 3 step của CÙNG một CVE chạy chung MỘT session
# (step đầu mở --session-id, các step sau --resume), context bị cắt giữa các CVE.
# Mục đích: benchmark xem chia sẻ context trong 1 CVE có rẻ hơn cold-start mỗi step không.
#
# So sánh:
#   run-pipeline.ps1          --no-session-persistence mỗi step (3 cold start/CVE)
#   run-pipeline-session.ps1  --session-id step1 + --resume step2/3 (1 session/CVE)
#
# Usage (from repo root):
#   .\run-pipeline-session.ps1 -List cve-list.txt
#   .\run-pipeline-session.ps1 -List cve-list.txt -GenVariants root-cause-only
#   .\run-pipeline-session.ps1 -List cve-list.txt -Resume          # skip IDs that already have output
#   .\run-pipeline-session.ps1 -List cve-list.txt -MaxBudgetUsd 2.00 -MaxTurns 20
#
# cve-list.txt: one template path per line (relative to repo root); # = comment.
#
# Steps per template:
#   1. crs-retrieve-analyze  --gen-variants=off  -> out/<id>/verdict.json
#   2. crs-variant-gen       --gen-variants=<mode> (self-gates on scope_gate)
#   3. crs-rule-author       (self-gates on scope_gate + coverage)
#
# Skills self-gate: scope_gate in {virtual-patch-only, out-of-scope-structural}
# causes Step 2 and Step 3 to HALT early without error.
#
# Per-step debug logs: out/<id>/claude-step<N>.log
# Token/cost summary printed at end of each step and pipeline end.
#
# NOTE -Resume (skip) vs session --resume: -Resume bỏ qua step đã có output file.
# Nếu step 1 bị skip (verdict.json đã có), không còn live session để resume —
# step kế tiếp chạy SẼ tự mở session mới làm anchor (xem $script:sessionStarted).

param(
    [Parameter(Mandatory)][string]$List,
    [ValidateSet("class-only","root-cause-only","all-triggered-rules")]
    [string]$GenVariants = "class-only",
    [string]$Model = "claude-sonnet-4-6",
    [string]$LogFile = "pipeline-run.log",
    [decimal]$MaxBudgetUsd = 5.50,
    [int]$MaxTurns = 50,
    [switch]$Resume
)

$ErrorActionPreference = "Continue"

# cumulative token/cost counters across all steps and all CVEs
$totals = @{ input=0; output=0; cache_read=0; cache_write=0; cost=[double]0 }

# per-CVE session state (reset in the loop)
$script:sessionId      = $null
$script:sessionStarted = $false

function Log($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

function RunClaude($prompt, $id, $step) {
    $debugLog = "out/$id/claude-step$step.log"

    # First live step of this CVE anchors the session (--session-id); the rest resume it.
    # This keeps the 3 steps in ONE context so handoff files + template stay cache-read,
    # instead of being re-fed as fresh input on each cold start.
    if (-not $script:sessionStarted) {
        $sessionArgs = @("--session-id", $script:sessionId)
        $script:sessionStarted = $true
        $sessionMode = "open $($script:sessionId.Substring(0,8))"
    } else {
        $sessionArgs = @("--resume", $script:sessionId)
        $sessionMode = "resume $($script:sessionId.Substring(0,8))"
    }
    Log "    [session] $sessionMode"

    $raw = claude -p $prompt `
        --dangerously-skip-permissions `
        --model $Model `
        --output-format json `
        @sessionArgs `
        --exclude-dynamic-system-prompt-sections `
        --max-turns $MaxTurns `
        --max-budget-usd $MaxBudgetUsd `
        --debug-file $debugLog `
        --name "crs-$id-s$step"

    $rc = $LASTEXITCODE

    # dump raw output for post-hoc inspection / parse debugging
    $rawLog = "out/$id/claude-step$step.raw.json"
    $raw | Set-Content -Path $rawLog -Encoding utf8

    # parse token usage and cost from JSON response (PS 5.1-compatible, no ?? operator)
    try {
        $obj = ($raw -join "`n") | ConvertFrom-Json
        $u = $obj.usage
        if ($null -ne $u) {
            $in  = if ($null -ne $u.input_tokens)               { [int]$u.input_tokens }               else { 0 }
            $out = if ($null -ne $u.output_tokens)              { [int]$u.output_tokens }              else { 0 }
            $cr  = if ($null -ne $u.cache_read_input_tokens)    { [int]$u.cache_read_input_tokens }    else { 0 }
            $cw  = if ($null -ne $u.cache_creation_input_tokens){ [int]$u.cache_creation_input_tokens } else { 0 }
            $cost = if ($null -ne $obj.total_cost_usd)          { [double]$obj.total_cost_usd }        else { [double]0 }

            $script:totals.input      += $in
            $script:totals.output     += $out
            $script:totals.cache_read += $cr
            $script:totals.cache_write+= $cw
            $script:totals.cost       += $cost

            $turns      = if ($null -ne $obj.num_turns)       { [int]$obj.num_turns }            else { 0 }
            $durSec     = if ($null -ne $obj.duration_ms)     { [int]$obj.duration_ms / 1000.0 } else { 0 }
            $stopR      = if ($null -ne $obj.stop_reason)     { $obj.stop_reason }               else { "?" }
            $termR      = if ($null -ne $obj.terminal_reason) { $obj.terminal_reason }           else { "?" }
            $isErr      = if ($null -ne $obj.is_error)        { $obj.is_error }                  else { $false }
            $apiErr     = if ($null -ne $obj.api_error_status){ $obj.api_error_status }          else { $null }
            $resultText = if ($null -ne $obj.result)          { $obj.result }                    else { "" }
            $permDenials= if ($null -ne $obj.permission_denials) { @($obj.permission_denials).Count } else { 0 }

            Log ("    [tokens] in={0} out={1} cache_read={2} cache_write={3} cost=`${4:F4} | turns={5} dur={6:F1}s stop={7} term={8}" `
                -f $in, $out, $cr, $cw, $cost, $turns, $durSec, $stopR, $termR)
            if ($resultText -ne "") { Log "    [result] $resultText" }
            if ($isErr)             { Log "    [ERROR] is_error=true api_error_status=$apiErr" }
            if ($permDenials -gt 0) { Log "    [WARN] permission_denials=$permDenials" }
        }
    } catch {}

    return $rc
}

# ── load list ────────────────────────────────────────────────────────────────
if (-not (Test-Path $List)) { Write-Error "$List not found"; exit 1 }
$templates = Get-Content $List |
    Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' } |
    ForEach-Object { $_.Trim() }

Log "=== pipeline start (SESSION-SHARED): $($templates.Count) template(s), model=$Model, gen-variants=$GenVariants, max-budget=`$$MaxBudgetUsd/step, max-turns=$MaxTurns ==="

$stats = @{ ok=0; covered=0; skipped=0; warn=0 }

foreach ($tpl in $templates) {
    $id  = [System.IO.Path]::GetFileNameWithoutExtension($tpl)
    $out = "out/$id"

    New-Item -ItemType Directory -Force $out | Out-Null

    # fresh session per CVE — context CVE trước bị cắt sạch tại đây
    $script:sessionId      = [guid]::NewGuid().ToString()
    $script:sessionStarted = $false

    Log "--- [$id] $tpl  (session $($script:sessionId.Substring(0,8)))"

    # ── Step 1: analyze ───────────────────────────────────────────────────────
    $verdictPath = "$out/verdict.json"
    if ($Resume -and (Test-Path $verdictPath)) {
        Log "  Step 1: skip (resume - verdict.json exists)"
    } else {
        Log "  Step 1: crs-retrieve-analyze --gen-variants=off"
        $rc = RunClaude "Invoke Skill(crs-retrieve-analyze) - args: --gen-variants=off $tpl" $id 1
        if ($rc -ne 0) { Log "  WARN: claude exited $rc at Step 1" }
    }

    if (-not (Test-Path $verdictPath)) {
        Log "  WARN: verdict.json missing - skipping $id"
        $stats.warn++; continue
    }

    $verdict = Get-Content $verdictPath -Raw | ConvertFrom-Json
    if ($null -ne $verdict.root_causes) {
        Log "  covered - no new rule needed"
        $stats.covered++; continue
    }

    # ── Step 2: variant-gen ───────────────────────────────────────────────────
    $extPath = "$out/extended-requests.json"
    if ($Resume -and (Test-Path $extPath)) {
        Log "  Step 2: skip (resume - extended-requests.json exists)"
    } else {
        Log "  Step 2: crs-variant-gen --gen-variants=$GenVariants"
        $rc = RunClaude "Invoke Skill(crs-variant-gen) - args: --gen-variants=$GenVariants out/$id/variant-handoff.json out/$id/probe.json template: $tpl" $id 2
        if ($rc -ne 0) { Log "  WARN: claude exited $rc at Step 2" }
    }

    # ── Step 3: rule-author ───────────────────────────────────────────────────
    $newPath = "$out/new.json"
    if ($Resume -and (Test-Path $newPath)) {
        Log "  Step 3: skip (resume - new.json exists)"
        $stats.ok++; continue
    }

    Log "  Step 3: crs-rule-author"
    $rc = RunClaude "Invoke Skill(crs-rule-author) - out/$id/verdict.json  template: $tpl" $id 3
    if ($rc -ne 0) { Log "  WARN: claude exited $rc at Step 3" }

    if (Test-Path $newPath) {
        Log "  done -> $newPath"
        $stats.ok++
    } else {
        Log "  WARN: new.json missing after Step 3"
        $stats.warn++
    }
}

Log ("=== pipeline end (SESSION-SHARED): ok={0} covered={1} warn={2} | tokens in={3} out={4} cache_read={5} cache_write={6} total_cost=`${7:F4} ===" `
    -f $stats.ok, $stats.covered, $stats.warn, `
       $totals.input, $totals.output, $totals.cache_read, $totals.cache_write, $totals.cost)
