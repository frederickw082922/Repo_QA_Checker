# Audit Compare Tool

Compares pre and post remediation [Goss](https://github.com/goss-org/goss) audit results to measure compliance improvement after running an Ansible-Lockdown hardening role.

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Components](#components)
- [CLI Reference](#cli-reference)
  - [Shell Wrapper (audit_compare.sh)](#shell-wrapper-audit_comparesh)
  - [Python Engine (audit_compare.py)](#python-engine-audit_comparepy)
- [Report Formats](#report-formats)
- [Interactive HTML Features](#interactive-html-features)
- [Web UI (--serve)](#web-ui---serve)
- [Report Sections](#report-sections)
- [Control ID Grouping](#control-id-grouping)
- [Exit Codes](#exit-codes)
- [Examples](#examples)

---

## Overview

After applying a CIS/STIG remediation role, a typical workflow runs a Goss audit **before** (pre-scan) and **after** (post-scan) remediation. Each audit produces a JSON file containing per-test pass/fail results.

This tool ingests those two JSON files and produces a comparison report showing:

- **Fixed controls** -- tests that moved from failed to passed
- **Regressed controls** -- tests that moved from passed to failed
- **Still-failed controls** -- tests that remain failed after remediation
- **Still-passed controls** -- tests that remained passing
- **New/removed tests** -- tests present in only one audit
- **Skipped tests** -- tests skipped in either audit
- **Overall compliance rate change** -- percentage improvement or decline

Results are grouped by control ID (extracted from the Goss test title) for easy mapping back to benchmark sections. Both **CIS** control IDs (e.g., `1.1.1.1`) and **STIG** rule IDs (e.g., `RHEL-09-123456`) are recognized automatically.

Key features:

- **Zero external Python dependencies** -- uses only the Python standard library
- **CIS and STIG support** -- auto-extracts control IDs from both CIS (`1.1.1.1`) and STIG (`RHEL-09-123456`) title formats for grouping
- **Auto-detects benchmark name and version** from audit filenames (e.g., `rhel10cis`, `ubuntu2204stig`, `v1_0_0`)
- **Expected vs found detail** -- still-failed and regressed controls show expected and actual values to aid remediation
- **Scan duration tracking** -- displays pre vs post scan duration in all report formats
- **CI-friendly exit codes** -- non-zero on regressions, with a `--strict` mode for gating on still-failed controls
- **Multiple output formats** -- text, Markdown, JSON, and interactive HTML
- **Interactive HTML reports** -- filter, search, sort, expand/collapse, and print directly from the browser
- **Web UI mode** -- launch a local web server with `--serve` for a browser-based comparison workflow
- **Summary-only mode** -- `--summary-only` shows just the summary and changes breakdown, skipping detailed control listings

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| Python 3.8+ | Standard library only, no `pip install` needed |
| Bash | Required only for the shell wrapper (`audit_compare.sh`) |
| Goss audit JSON files | Pre and post remediation scan output |

---

## Quick Start

### Using the shell wrapper (recommended)

The shell wrapper auto-discovers the most recent pre/post audit files in `/var/tmp`:

```bash
./audit_compare.sh
```

### Using the Python script directly

```bash
python3 audit_compare.py /var/tmp/rhel10cis_pre_scan_2026-02-28.json \
                         /var/tmp/rhel10cis_post_scan_2026-02-28.json
```

### Generate an interactive HTML report

```bash
./audit_compare.sh -f html
```

### Launch the web UI

```bash
./audit_compare.sh -S
# Open http://127.0.0.1:9090 in your browser
```

---

## Components

The tool consists of two files:

| File | Purpose |
|------|---------|
| `audit_compare.sh` | Bash wrapper that auto-discovers audit files and invokes the Python engine |
| `audit_compare.py` | Python engine that parses Goss JSON, compares results, and generates reports |

You can use either file directly. The shell wrapper adds convenience features (auto-discovery, file listing) on top of the Python engine.

---

## CLI Reference

### Shell Wrapper (audit_compare.sh)

```
./audit_compare.sh [OPTIONS]
```

#### Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--dir DIR` | `-d` | Directory containing audit files | `/var/tmp` |
| `--pre FILE` | `-p` | Pre-remediation audit JSON file | Auto-detected (latest `*_pre_scan_*.json`) |
| `--post FILE` | `-o` | Post-remediation audit JSON file | Auto-detected (latest `*_post_scan_*.json`) |
| `--format FMT` | `-f` | Output format: `text`, `markdown`, `json`, `html` | `text` |
| `--report FILE` | `-r` | Write report to specific file | Auto-named |
| `--no-report` | `-n` | Print to stdout only, skip writing a report file | Off |
| `--title NAME` | `-t` | Benchmark name for report title | Auto-detected from filename |
| `--strict` | `-s` | Exit 1 on regressions or still-failed controls | Off |
| `--summary-only` | `-u` | Show only summary and changes breakdown, skip control details | Off |
| `--serve [PORT]` | `-S` | Launch web UI on PORT (skips file comparison) | `9090` |
| `--list` | `-l` | List available audit files and exit | |
| `--help` | `-h` | Show help message | |

#### Auto-Discovery

When `--pre` and `--post` are not specified, the wrapper searches the audit directory (default `/var/tmp`) for files matching:

- `*_pre_scan_*.json` -- selects the most recent by filename sort
- `*_post_scan_*.json` -- selects the most recent by filename sort

The auto-detected file paths are printed to stderr for confirmation.

#### Benchmark Auto-Detection

The report title is automatically derived from audit filenames. The tool recognizes patterns like `rhel10cis`, `ubuntu2204stig`, `amazon2023stig`, etc., and formats them as `RHEL10 CIS`, `UBUNTU2204 STIG`, etc. Use `--title` to override.

The benchmark version is also auto-detected from patterns like `v1_0_0`, `v1.2.0`, or `v1r2` in filenames and included in the default report filename.

---

### Python Engine (audit_compare.py)

```
python3 audit_compare.py [OPTIONS] [pre_audit.json] [post_audit.json]
```

Positional arguments are required unless `--serve` is used.

#### Positional Arguments

| Argument | Description |
|----------|-------------|
| `pre_audit` | Pre-remediation Goss audit JSON file |
| `post_audit` | Post-remediation Goss audit JSON file |

#### Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--format {text,markdown,json,html}` | `-f` | Output format | `text` |
| `--output FILE` | `-o` | Write report to specific file | Auto-named |
| `--no-report` | | Print to stdout only, skip writing a report file | Off |
| `--title NAME` | `-t` | Benchmark name for report title | Auto-detected from filename |
| `--strict` | | Exit 1 on regressions or still-failed controls | Off |
| `--summary-only` | | Show only summary and changes breakdown, skip control details | Off |
| `--serve [PORT]` | | Launch web UI on PORT (no audit files required) | `9090` |

---

## Report Formats

### Default Output Naming

By default, the tool writes a report file with an auto-generated name:

```
audit_compare_report_{benchmark}_{version}_{datetime}.{ext}
```

For example: `audit_compare_report_RHEL10_CIS_v1_0_0_2026-02-28_143012.txt`

The benchmark name and version are auto-detected from the audit filenames. Use `--output` to specify an explicit path, or `--no-report` to print to stdout only (no file written).

### Text (default)

Plain-text report with fixed-width formatting, suitable for terminal output and log files.

```bash
python3 audit_compare.py pre.json post.json
# or
./audit_compare.sh -f text
```

### Markdown

Markdown report with tables and headings, suitable for documentation, pull requests, and wikis.

```bash
python3 audit_compare.py pre.json post.json --format markdown --output report.md
# or
./audit_compare.sh -f markdown -r report.md
```

### HTML

Styled, interactive HTML page with color-coded badges, collapsible control groups, a summary table, and a JavaScript-powered toolbar. Opens directly in a browser -- no external CSS or JavaScript files required. Visual styling matches the main QA tool's HTML reports.

```bash
python3 audit_compare.py pre.json post.json --format html
# or
./audit_compare.sh -f html
```

Key visual elements:

- Color-coded badges for each change category (green for fixed, red for regressed, yellow for still-failed)
- Collapsible `<details>` sections per control ID -- regressed controls default to open
- Expected vs found values shown inline for regressed and still-failed tests
- Positive/negative change values highlighted in the summary table
- Interactive toolbar with filter, search, expand/collapse, and print controls (see [Interactive HTML Features](#interactive-html-features))

### JSON

Structured JSON output with metadata, summary statistics, and per-control detail. Suitable for programmatic consumption and CI pipelines.

Key JSON fields:

- `metadata.benchmark` -- auto-detected or user-specified benchmark name
- `summary.duration` -- scan duration in both raw nanoseconds and formatted strings
- `summary.compliance_change` -- pre/post compliance percentages
- `fixed` / `regressed` -- flattened to clean `control_id` / `title` pairs
- `still_failed_by_control` -- grouped by control ID with `title`, `summary_line`, `expected`, and `found` per test

```bash
python3 audit_compare.py pre.json post.json --format json > comparison.json
# or
./audit_compare.sh -f json -r comparison.json
```

---

## Interactive HTML Features

HTML reports include a JavaScript-powered toolbar that adds interactive capabilities on top of the static report. All JavaScript is embedded inline -- no external files or CDN required. Reports degrade gracefully when JavaScript is disabled (the toolbar is hidden and native `<details>` expand/collapse still works).

### Toolbar Controls

| Control | Description |
|---------|-------------|
| **Filter buttons** | Toggle visibility of Fixed, Regressed, and Still Failed sections. Click a badge to dim and hide its section; click again to restore it. |
| **Search** | Type a control ID or test name to filter the detail sections. Only matching control groups are shown. A match counter displays alongside the search box. |
| **Expand All / Collapse All** | Toggle all `<details>` elements open or closed at once. |
| **Print Report** | Expands all sections, opens the browser print dialog, then restores the previous expand/collapse state. Print CSS hides the toolbar and removes shadows for clean output. |

### Click-to-Navigate

Clicking a row in the Changes Breakdown table (for categories with results) scrolls smoothly to the corresponding section. A brief highlight outline confirms the target section.

### Sortable Tables

Click any column header in the Summary or Changes Breakdown tables to sort ascending/descending. An arrow indicator shows the current sort direction.

### Graceful Degradation

When JavaScript is disabled, the toolbar is automatically hidden via `<noscript>`. The report remains fully readable -- native `<details>/<summary>` elements still provide expand/collapse functionality.

---

## Web UI (--serve)

The `--serve` flag launches a local web server that provides a browser-based interface for comparing audit files interactively. No audit file arguments are required.

```bash
# Launch on default port 9090
python3 audit_compare.py --serve

# Launch on a custom port
python3 audit_compare.py --serve 3000

# Via shell wrapper
./audit_compare.sh -S
./audit_compare.sh -S 3000
```

### Features

- **File browser** -- browse `.json` files in the working directory, navigate to parent directories
- **Auto-classification** -- files are tagged as PRE or POST based on filename patterns (`_pre_scan_`, `_post_scan_`, `pre*`, `post*`)
- **One-click comparison** -- select a pre and post file, click Compare, and the interactive HTML report renders inline
- **Full interactivity** -- the rendered report includes all interactive features (filter, search, sort, expand/collapse, print)
- **Optional title** -- set a custom benchmark title or let it auto-detect from filenames

### Security

- Binds to `127.0.0.1` only (localhost) -- not accessible from the network
- Directory traversal prevention via path validation (`os.path.realpath()` resolution)
- Only `.json` files are listed and accessible through the API

### API Endpoints

The web server exposes a simple REST API used by the single-page application:

| Endpoint | Description |
|----------|-------------|
| `GET /` | Serves the single-page application HTML |
| `GET /api/files?dir=<path>` | Lists `.json` files in the specified directory |
| `GET /api/compare?pre=<path>&post=<path>&title=<name>` | Runs comparison and returns JSON |
| `GET /api/report?pre=<path>&post=<path>&format=html` | Returns a rendered HTML report |

---

## Report Sections

All report formats include the following sections. Use `--summary-only` to output only the Summary and Changes Breakdown, skipping the detailed control listings below.

### Summary

A comparison table showing pre vs post audit totals:

| Metric | Description |
|--------|-------------|
| Total Tests | Number of Goss tests in each audit |
| Passed | Tests with a successful result |
| Failed | Tests with a failed result |
| Skipped | Tests that were skipped |
| Scan Duration | Time taken for each audit scan (formatted from Goss nanoseconds) |
| Compliance Rate | Percentage of passed tests (passed / total) |

### Changes Breakdown

Counts of tests in each transition category:

| Category | Meaning |
|----------|---------|
| Fixed | Failed in pre-audit, passed in post-audit |
| Regressed | Passed in pre-audit, failed in post-audit |
| Still Failed | Failed in both audits |
| Still Passed | Passed in both audits |
| Skipped | Skipped in either audit |
| New Tests | Present only in the post-audit |
| Removed Tests | Present only in the pre-audit |

### Fixed Controls

Lists controls that were successfully remediated, grouped by control ID.

### Regressed Controls

Lists controls that were previously passing but now fail. Includes the expected and actual values for each failing test to aid debugging.

### Still Failed Controls

Lists controls that remain failed after remediation, with expected vs found values for each test. These require manual remediation or configuration changes.

---

## Control ID Grouping

Controls are grouped by their ID, which is auto-extracted from the Goss test title. The tool recognizes:

| Format | Pattern | Example |
|--------|---------|---------|
| CIS | Dotted numeric (`X.X.X.X`) | `1.1.1.1`, `5.2.3` |
| STIG | Alphanumeric rule ID (`XXXX-XX-XXXXXX`) | `RHEL-09-123456`, `UBTU-22-654321` |
| Other | First token before `|` delimiter | Anything else |

This means reports work correctly across all Ansible-Lockdown repos without any configuration.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No regressions detected |
| `1` | Regressions detected (or still-failed controls in strict mode) |
| `2` | Input or parsing error (file not found, invalid JSON) |

### Default behavior

- Exit `0` when no controls have regressed (even if some remain failed)
- Exit `1` when any control has regressed (passed -> failed)
- Exit `2` on file or JSON parsing errors

### Strict mode

```bash
./audit_compare.sh -s
# or
python3 audit_compare.py pre.json post.json --strict
```

In strict mode, the tool also exits `1` when controls remain in a still-failed state. This is useful for CI pipelines that require full compliance before merging.

---

## Examples

### Auto-discover and compare latest audit files

```bash
./audit_compare.sh
```

### Use a custom audit directory

```bash
./audit_compare.sh -d /opt/audit_results
```

### List available audit files

```bash
./audit_compare.sh -l
```

Output:

```
Available audit files in /var/tmp:

Pre-remediation audits:
/var/tmp/rhel10cis_pre_scan_2026-02-28.json
/var/tmp/rhel10cis_pre_scan_2026-02-27.json

Post-remediation audits:
/var/tmp/rhel10cis_post_scan_2026-02-28.json
```

### Specify files directly

```bash
./audit_compare.sh -p /var/tmp/rhel10cis_pre_scan_2026-02-28.json \
                   -o /var/tmp/rhel10cis_post_scan_2026-02-28.json
```

### Override the benchmark title

```bash
./audit_compare.sh -t "RHEL9 CIS"
```

### Generate an interactive HTML report

```bash
./audit_compare.sh -f html
# Opens as audit_compare_report_RHEL10_CIS_v1_0_0_2026-02-28_143012.html
```

### Generate a JSON report for CI consumption

```bash
./audit_compare.sh -s -f json -r /tmp/audit_comparison.json
```

### Print to stdout without writing a file

```bash
python3 audit_compare.py pre.json post.json --no-report
python3 audit_compare.py pre.json post.json --no-report --format json | jq .
```

### Pipe Markdown output to a file

```bash
python3 audit_compare.py pre.json post.json --no-report --format markdown > report.md
```

### Quick summary only (no control details)

```bash
./audit_compare.sh -u -n
# or
python3 audit_compare.py pre.json post.json --summary-only --no-report
```

### Launch the web UI

```bash
./audit_compare.sh -S
# or on a custom port
python3 audit_compare.py --serve 3000
```

Then open `http://127.0.0.1:9090` (or your specified port) in a browser to browse, select, and compare audit files interactively.
