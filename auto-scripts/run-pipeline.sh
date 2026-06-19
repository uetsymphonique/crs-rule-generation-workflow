#!/usr/bin/env bash
# run-pipeline.sh - batch CRS rule-generation pipeline
#
# Usage (from repo root):
#   ./run-pipeline.sh --list cve-list.txt
#   ./run-pipeline.sh --list cve-list.txt --gen-variants root-cause-only
#   ./run-pipeline.sh --list cve-list.txt --resume
#   ./run-pipeline.sh --list cve-list.txt --max-budget-usd 2.00 --max-turns 20
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
# Requires: claude CLI, jq

set -euo pipefail

# ── defaults ─────────────────────────────────────────────────────────────────
LIST=""
GEN_VARIANTS="class-only"
MODEL="claude-sonnet-4-6"
LOG_FILE="pipeline-run.log"
MAX_BUDGET_USD="5.50"
MAX_TURNS="50"
RESUME=0

# ── arg parse ─────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)           LIST="$2";           shift 2 ;;
        --gen-variants)   GEN_VARIANTS="$2";   shift 2 ;;
        --model)          MODEL="$2";           shift 2 ;;
        --log-file)       LOG_FILE="$2";        shift 2 ;;
        --max-budget-usd) MAX_BUDGET_USD="$2";  shift 2 ;;
        --max-turns)      MAX_TURNS="$2";       shift 2 ;;
        --resume)         RESUME=1;             shift   ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$LIST" ]]; then
    echo "Error: --list is required" >&2
    exit 1
fi

case "$GEN_VARIANTS" in
    class-only|root-cause-only|all-triggered-rules) ;;
    *) echo "Error: --gen-variants must be class-only, root-cause-only, or all-triggered-rules" >&2; exit 1 ;;
esac

# ── cumulative counters ───────────────────────────────────────────────────────
TOT_IN=0; TOT_OUT=0; TOT_CR=0; TOT_CW=0
TOT_COST="0"

# ── helpers ───────────────────────────────────────────────────────────────────
log() {
    local line="[$(date '+%H:%M:%S')] $*"
    echo "$line"
    echo "$line" >> "$LOG_FILE"
}

jq_str() {
    # safe jq: returns default if field is null/missing
    local json="$1" expr="$2" default="$3"
    local val
    val=$(echo "$json" | jq -r "$expr // empty" 2>/dev/null || true)
    echo "${val:-$default}"
}

jq_int() {
    local json="$1" expr="$2"
    local val
    val=$(echo "$json" | jq -r "$expr // 0" 2>/dev/null || true)
    echo "${val:-0}"
}

run_claude() {
    local prompt="$1" id="$2" step="$3"
    local debug_log="out/$id/claude-step${step}.log"
    local raw_log="out/$id/claude-step${step}.raw.json"

    local raw
    raw=$(claude -p "$prompt" \
        --dangerously-skip-permissions \
        --model "$MODEL" \
        --output-format json \
        --no-session-persistence \
        --exclude-dynamic-system-prompt-sections \
        --max-turns "$MAX_TURNS" \
        --max-budget-usd "$MAX_BUDGET_USD" \
        --debug-file "$debug_log" \
        --name "crs-${id}-s${step}" 2>&1) || true
    local rc=$?

    echo "$raw" > "$raw_log"

    # parse fields with jq
    local in_tok out_tok cr cw cost turns dur_ms dur_sec stop_r term_r is_err api_err result_text perm_denials

    in_tok=$(jq_int "$raw" '.usage.input_tokens')
    out_tok=$(jq_int "$raw" '.usage.output_tokens')
    cr=$(jq_int      "$raw" '.usage.cache_read_input_tokens')
    cw=$(jq_int      "$raw" '.usage.cache_creation_input_tokens')
    cost=$(jq_str    "$raw" '.total_cost_usd'      "0")
    turns=$(jq_int   "$raw" '.num_turns')
    dur_ms=$(jq_int  "$raw" '.duration_ms')
    stop_r=$(jq_str  "$raw" '.stop_reason'         "?")
    term_r=$(jq_str  "$raw" '.terminal_reason'     "?")
    is_err=$(jq_str  "$raw" '.is_error'            "false")
    api_err=$(jq_str "$raw" '.api_error_status'    "")
    result_text=$(jq_str "$raw" '.result'          "")
    perm_denials=$(jq_int "$raw" '.permission_denials | length')

    dur_sec=$(awk "BEGIN { printf \"%.1f\", $dur_ms / 1000 }")
    cost_fmt=$(awk "BEGIN { printf \"%.4f\", $cost }")

    # accumulate totals
    TOT_IN=$((TOT_IN   + in_tok))
    TOT_OUT=$((TOT_OUT + out_tok))
    TOT_CR=$((TOT_CR   + cr))
    TOT_CW=$((TOT_CW   + cw))
    TOT_COST=$(awk "BEGIN { printf \"%.4f\", $TOT_COST + $cost }")

    log "    [tokens] in=${in_tok} out=${out_tok} cache_read=${cr} cache_write=${cw} cost=\$${cost_fmt} | turns=${turns} dur=${dur_sec}s stop=${stop_r} term=${term_r}"
    [[ -n "$result_text" ]]      && log "    [result] ${result_text}"
    [[ "$is_err" == "true" ]]    && log "    [ERROR] is_error=true api_error_status=${api_err}"
    [[ "$perm_denials" -gt 0 ]]  && log "    [WARN] permission_denials=${perm_denials}"

    return $rc
}

# ── load list ─────────────────────────────────────────────────────────────────
if [[ ! -f "$LIST" ]]; then
    echo "Error: $LIST not found" >&2
    exit 1
fi

mapfile -t TEMPLATES < <(grep -v '^\s*#' "$LIST" | grep -v '^\s*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

STAT_OK=0; STAT_COVERED=0; STAT_WARN=0

log "=== pipeline start: ${#TEMPLATES[@]} template(s), model=${MODEL}, gen-variants=${GEN_VARIANTS}, max-budget=\$${MAX_BUDGET_USD}/step, max-turns=${MAX_TURNS} ==="

for tpl in "${TEMPLATES[@]}"; do
    id="${tpl%.*}"           # strip extension
    id="${id##*/}"           # basename (last path component)
    out="out/$id"

    mkdir -p "$out"
    log "--- [$id] $tpl"

    # ── Step 1: analyze ───────────────────────────────────────────────────────
    verdict_path="$out/verdict.json"
    if [[ "$RESUME" -eq 1 && -f "$verdict_path" ]]; then
        log "  Step 1: skip (resume - verdict.json exists)"
    else
        log "  Step 1: crs-retrieve-analyze --gen-variants=off"
        run_claude "Invoke Skill(crs-retrieve-analyze) - args: --gen-variants=off $tpl" "$id" 1 || \
            log "  WARN: claude exited $? at Step 1"
    fi

    if [[ ! -f "$verdict_path" ]]; then
        log "  WARN: verdict.json missing - skipping $id"
        STAT_WARN=$((STAT_WARN + 1))
        continue
    fi

    root_causes=$(jq -r '.root_causes // empty' "$verdict_path" 2>/dev/null || true)
    if [[ -n "$root_causes" ]]; then
        log "  covered - no new rule needed"
        STAT_COVERED=$((STAT_COVERED + 1))
        continue
    fi

    # ── Step 2: variant-gen ───────────────────────────────────────────────────
    ext_path="$out/extended-requests.json"
    if [[ "$RESUME" -eq 1 && -f "$ext_path" ]]; then
        log "  Step 2: skip (resume - extended-requests.json exists)"
    else
        log "  Step 2: crs-variant-gen --gen-variants=${GEN_VARIANTS}"
        run_claude "Invoke Skill(crs-variant-gen) - args: --gen-variants=${GEN_VARIANTS} out/${id}/variant-handoff.json out/${id}/probe.json template: $tpl" "$id" 2 || \
            log "  WARN: claude exited $? at Step 2"
    fi

    # ── Step 3: rule-author ───────────────────────────────────────────────────
    new_path="$out/new.json"
    if [[ "$RESUME" -eq 1 && -f "$new_path" ]]; then
        log "  Step 3: skip (resume - new.json exists)"
        STAT_OK=$((STAT_OK + 1))
        continue
    fi

    log "  Step 3: crs-rule-author"
    run_claude "Invoke Skill(crs-rule-author) - out/${id}/verdict.json  template: $tpl" "$id" 3 || \
        log "  WARN: claude exited $? at Step 3"

    if [[ -f "$new_path" ]]; then
        log "  done -> $new_path"
        STAT_OK=$((STAT_OK + 1))
    else
        log "  WARN: new.json missing after Step 3"
        STAT_WARN=$((STAT_WARN + 1))
    fi
done

TOT_COST_FMT=$(awk "BEGIN { printf \"%.4f\", $TOT_COST }")
log "=== pipeline end: ok=${STAT_OK} covered=${STAT_COVERED} warn=${STAT_WARN} | tokens in=${TOT_IN} out=${TOT_OUT} cache_read=${TOT_CR} cache_write=${TOT_CW} total_cost=\$${TOT_COST_FMT} ==="
