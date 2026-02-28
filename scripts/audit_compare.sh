#!/bin/bash
#
# Goss Audit Comparison Wrapper
#
# This script simplifies comparing audit files by:
# - Auto-discovering the most recent pre/post audit files
# - Supporting various output formats
# - Generating timestamped reports
#
# Usage:
#   ./audit_compare.sh                          # Auto-find latest files in /var/tmp
#   ./audit_compare.sh -d /path/to/audits       # Specify audit directory
#   ./audit_compare.sh -p pre.json -o post.json # Specify files directly
#   ./audit_compare.sh -f markdown -r report.md # Markdown output to file

set -e

# Default values
AUDIT_DIR="/var/tmp"
PRE_FILE=""
POST_FILE=""
FORMAT="text"
OUTPUT=""
TITLE=""
STRICT=""
NO_REPORT=""
SUMMARY_ONLY=""
SERVE=""
SERVE_PORT=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Compare pre and post remediation Goss audit results.

Options:
    -d, --dir DIR       Directory containing audit files (default: /var/tmp)
    -p, --pre FILE      Pre-remediation audit JSON file
    -o, --post FILE     Post-remediation audit JSON file
    -f, --format FMT    Output format: text, markdown, json, html (default: text)
    -r, --report FILE   Write report to specific file (default: auto-named)
    -n, --no-report     Print to stdout only, do not write a report file
    -t, --title NAME    Benchmark name for report title (default: auto-detected)
    -s, --strict        Exit 1 on regressions or still-failed controls
    -u, --summary-only  Show only summary and changes breakdown
    -S, --serve [PORT]  Launch web UI on PORT (default: 9090)
    -l, --list          List available audit files and exit
    -h, --help          Show this help message

Exit Codes:
    0   No regressions detected
    1   Regressions detected (or still-failed in strict mode)
    2   Input/parsing error

Examples:
    $(basename "$0")                              # Auto-find latest, write auto-named report
    $(basename "$0") -d /opt/audits               # Use custom directory
    $(basename "$0") -p pre.json -o post.json     # Specify files
    $(basename "$0") -f markdown -r report.md     # Markdown to specific file
    $(basename "$0") -f html                      # HTML report (auto-named)
    $(basename "$0") -n                           # Print to stdout only
    $(basename "$0") -t "RHEL9 CIS"               # Custom benchmark title
    $(basename "$0") -s                           # Strict mode for CI
    $(basename "$0") -S                           # Web UI on port 9090
    $(basename "$0") -S 9090                      # Web UI on port 9090
    $(basename "$0") -l                           # List available files
EOF
    exit 0
}

list_audit_files() {
    echo "Available audit files in $AUDIT_DIR:"
    echo ""
    echo "Pre-remediation audits:"
    find "$AUDIT_DIR" -maxdepth 1 -name "*_pre_scan_*.json" 2>/dev/null | sort -r | head -10 || echo "  None found"
    echo ""
    echo "Post-remediation audits:"
    find "$AUDIT_DIR" -maxdepth 1 -name "*_post_scan_*.json" 2>/dev/null | sort -r | head -10 || echo "  None found"
}

find_latest_audit() {
    local pattern=$1
    find "$AUDIT_DIR" -maxdepth 1 -name "*${pattern}*.json" 2>/dev/null | sort -r | head -1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--dir)
            AUDIT_DIR="$2"
            shift 2
            ;;
        -p|--pre)
            PRE_FILE="$2"
            shift 2
            ;;
        -o|--post)
            POST_FILE="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -r|--report)
            OUTPUT="$2"
            shift 2
            ;;
        -t|--title)
            TITLE="$2"
            shift 2
            ;;
        -n|--no-report)
            NO_REPORT="yes"
            shift
            ;;
        -s|--strict)
            STRICT="yes"
            shift
            ;;
        -u|--summary-only)
            SUMMARY_ONLY="yes"
            shift
            ;;
        -S|--serve)
            SERVE="yes"
            # Check if next argument is a port number
            if [[ -n "$2" ]] && [[ "$2" =~ ^[0-9]+$ ]]; then
                SERVE_PORT="$2"
                shift 2
            else
                shift
            fi
            ;;
        -l|--list)
            list_audit_files
            exit 0
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

# Serve mode: skip file validation and launch web UI
if [[ -n "$SERVE" ]]; then
    CMD="python3 ${SCRIPT_DIR}/audit_compare.py --serve"
    if [[ -n "$SERVE_PORT" ]]; then
        CMD="$CMD $SERVE_PORT"
    fi
    exec $CMD
fi

# Validate format
if [[ ! "$FORMAT" =~ ^(text|markdown|json|html)$ ]]; then
    echo "Error: Invalid format '$FORMAT'. Must be: text, markdown, json, or html" >&2
    exit 1
fi

# Auto-discover files if not specified
if [[ -z "$PRE_FILE" ]]; then
    PRE_FILE=$(find_latest_audit "_pre_scan_")
    if [[ -z "$PRE_FILE" ]]; then
        echo "Error: No pre-remediation audit files found in $AUDIT_DIR" >&2
        echo "Run with -l to list available files or specify with -p" >&2
        exit 1
    fi
    echo "Auto-detected pre-audit:  $PRE_FILE" >&2
fi

if [[ -z "$POST_FILE" ]]; then
    POST_FILE=$(find_latest_audit "_post_scan_")
    if [[ -z "$POST_FILE" ]]; then
        echo "Error: No post-remediation audit files found in $AUDIT_DIR" >&2
        echo "Run with -l to list available files or specify with -o" >&2
        exit 1
    fi
    echo "Auto-detected post-audit: $POST_FILE" >&2
fi

# Validate files exist
if [[ ! -f "$PRE_FILE" ]]; then
    echo "Error: Pre-audit file not found: $PRE_FILE" >&2
    exit 1
fi

if [[ ! -f "$POST_FILE" ]]; then
    echo "Error: Post-audit file not found: $POST_FILE" >&2
    exit 1
fi

# Build command
CMD="python3 ${SCRIPT_DIR}/audit_compare.py"
CMD="$CMD --format $FORMAT"
if [[ -n "$OUTPUT" ]]; then
    CMD="$CMD --output $OUTPUT"
fi
if [[ -n "$TITLE" ]]; then
    CMD="$CMD --title '$TITLE'"
fi
if [[ -n "$STRICT" ]]; then
    CMD="$CMD --strict"
fi
if [[ -n "$NO_REPORT" ]]; then
    CMD="$CMD --no-report"
fi
if [[ -n "$SUMMARY_ONLY" ]]; then
    CMD="$CMD --summary-only"
fi
CMD="$CMD $PRE_FILE $POST_FILE"

# Execute
echo "" >&2
exec $CMD
