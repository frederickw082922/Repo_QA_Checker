#!/usr/bin/env bash
# Run all QA check and fix scripts against an Ansible Lockdown role.
#
# Works with any Ansible Lockdown benchmark role:
#   - CIS roles:  UBUNTU20-CIS, UBUNTU22-CIS, RHEL8-CIS, RHEL9-CIS, AMAZON2-CIS, etc.
#   - STIG roles: RHEL8-STIG, RHEL9-STIG, UBUNTU22-STIG, AMAZON2023-STIG, etc.
#
# Benchmark type (CIS vs STIG) is auto-detected from defaults/main.yml variable patterns.
# No configuration needed — just point it at any Lockdown role repo root.
#
# Usage:
#   ./run_all_checks.sh <repo_path>              # Full scan (checks + fix dry-run)
#   ./run_all_checks.sh <repo_path> --fix        # Full scan + apply all fixes
#   ./run_all_checks.sh <repo_path> --checks     # Only run check scripts (read-only)
#   ./run_all_checks.sh <repo_path> --dry-run    # Only run fix scripts (report only)
#
# Examples:
#   ./run_all_checks.sh ~/repos/UBUNTU20-CIS
#   ./run_all_checks.sh ~/repos/RHEL9-STIG --fix
#   ./run_all_checks.sh /path/to/AMAZON2-CIS --checks
#
# <repo_path> must be the root of the Ansible role containing:
#   defaults/main.yml, tasks/, handlers/, templates/
#
# Exit codes:
#   0 = all checks clean (or --fix applied successfully)
#   1 = warnings or issues found (dry-run mode)
#   2 = invalid arguments or missing repo structure

set -uo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# Handle --help as first argument
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    grep '^#' "$0" | sed 's/^# \?//' | head -25
    exit 0
fi

REPO="${1:?Usage: $0 <repo_path> [--fix|--checks|--dry-run|--help]}"
# Resolve to absolute path so scripts work regardless of cwd
REPO="$(cd "$REPO" 2>/dev/null && pwd)" || { echo "Error: $1 is not a valid directory" >&2; exit 2; }
MODE="${2:-}"
START_TIME=$(date +%s)

# ── Pre-flight checks ────────────────────────────────────────

if ! command -v python3 &>/dev/null; then
    echo "Error: python3 not found in PATH" >&2
    exit 2
fi

# ── Validate repo structure ──────────────────────────────────

if [[ ! -d "$REPO" ]]; then
    echo "Error: $REPO is not a directory" >&2
    exit 2
fi

if [[ ! -f "$REPO/defaults/main.yml" ]]; then
    echo "Error: $REPO/defaults/main.yml not found — is this an Ansible role?" >&2
    exit 2
fi

if [[ ! -d "$REPO/tasks" ]]; then
    echo "Error: $REPO/tasks/ not found — is this an Ansible role?" >&2
    exit 2
fi

# ── Parse flags ──────────────────────────────────────────────

FIX_FLAG=""
RUN_CHECKS=true
RUN_FIXES=true

case "$MODE" in
    --fix)     FIX_FLAG="--fix" ;;
    --checks)  RUN_FIXES=false ;;
    --dry-run) RUN_CHECKS=false ;;
    --help|-h) grep '^#' "$0" | sed 's/^# \?//' | head -25; exit 0 ;;
    "")        ;;
    *)         echo "Unknown flag: $MODE"; echo "Valid: --fix, --checks, --dry-run, --help"; exit 2 ;;
esac

# Resolve display name for mode
if [[ -n "$FIX_FLAG" ]]; then
    MODE_LABEL="fix (applying changes)"
elif ! $RUN_FIXES; then
    MODE_LABEL="checks only (read-only)"
elif ! $RUN_CHECKS; then
    MODE_LABEL="dry-run (fix preview)"
else
    MODE_LABEL="full scan (report only)"
fi

# ── Counters ─────────────────────────────────────────────────

PASS=0
WARN=0
TOTAL=0

run_script() {
    local label="$1"
    local script="$2"
    shift 2

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $label"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ ! -f "$SCRIPTS_DIR/$script" ]]; then
        echo "  SKIP: $script not found"
        return
    fi

    ((TOTAL++)) || true
    output=$(python3 "$SCRIPTS_DIR/$script" "$@" 2>&1)
    script_exit=$?
    echo "$output"

    # Each check_*.py / fix_*.py exits 0 when clean, 1 when issues found.
    # Trust the exit code rather than grepping output; the regex-on-output
    # approach mis-scored scripts whose tails happened to contain ": 0"
    # (clean indicator) while their bodies emitted real warnings.
    if [[ $script_exit -eq 0 ]]; then
        ((PASS++)) || true
    else
        ((WARN++)) || true
    fi
}

# ── Header ───────────────────────────────────────────────────

ROLE_NAME=$(basename "$REPO")
echo "============================================================"
echo "  Ansible Lockdown QA — Full Scan"
echo "  Role: $ROLE_NAME"
echo "  Path: $REPO"
echo "  Mode: $MODE_LABEL"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"

# ── Check Scripts ─────────────────────────────────────────────

if $RUN_CHECKS; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  CHECK SCRIPTS (read-only analysis)                     ║"
    echo "╚══════════════════════════════════════════════════════════╝"

    run_script "File Modes (relative symbolic)"   check_file_modes.py     "$REPO" --tasks-only
    run_script "Register Variable Order"          check_register_order.py "$REPO"
    run_script "Rule Coverage (defaults/tasks)"   check_rule_coverage.py  "$REPO"
    run_script "Tag Completeness"                 check_tags_completeness.py "$REPO"
    run_script "Template Headers"                 check_template_headers.py "$REPO"
    run_script "Variable Naming"                  check_var_naming.py     "$REPO"
    run_script "Audit Template Keys"              check_audit_keys.py     "$REPO"
    run_script "Audit Variable Placement"         check_audit_vars.py     "$REPO"
    run_script "shell pipefail"                   check_shell_pipefail.py     "$REPO"
fi

# ── Fix Scripts (dry-run or --fix) ────────────────────────────

if $RUN_FIXES; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    if [[ -n "$FIX_FLAG" ]]; then
        echo "║  FIX SCRIPTS (applying fixes)                          ║"
    else
        echo "║  FIX SCRIPTS (dry-run — add --fix to apply)            ║"
    fi
    echo "╚══════════════════════════════════════════════════════════╝"

    run_script "FQCN Modules"                fix_fqcn.py           "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "Missing changed_when"        fix_changed_when.py   "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "File Modes (legacy octal)"   fix_file_modes.py     "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "File Modes (absolute sym)"   check_file_modes.py   "$REPO" --tasks-only ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "Handler References"          fix_handler_refs.py   "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "Single-item when/tags"       fix_when_inline.py    "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "Warn Count Blocks"           fix_warn_count.py     "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "Spelling"                    fix_spelling.py       "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "Grammar"                     fix_grammar.py        "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "Company Naming"              fix_company_naming.py "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "ignore_errors to failed_when" fix_ignore_errors.py "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "Missing no_log"              fix_no_log.py         "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "Missing loop_control"        fix_loop_control.py   "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
    run_script "shell pipefail"              fix_shell_pipefail.py "$REPO" ${FIX_FLAG:+"$FIX_FLAG"}
fi

# ── Summary ───────────────────────────────────────────────────

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "============================================================"
echo "  Summary — $ROLE_NAME"
echo "============================================================"
echo "  Scripts run: $TOTAL"
echo "  Clean:       $PASS"
echo "  Warnings:    $WARN"
echo "  Duration:    ${ELAPSED}s"
echo "  Mode:        $MODE_LABEL"
if [[ -z "$FIX_FLAG" && $WARN -gt 0 ]]; then
    echo ""
    echo "  Run with --fix to apply automatic fixes"
fi
echo "============================================================"

# Exit 1 if warnings found in report-only mode
if [[ -z "$FIX_FLAG" && $WARN -gt 0 ]]; then
    exit 1
fi
exit 0
