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
- [Report Sections](#report-sections)
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
- **Auto-detects benchmark name** from audit filenames (e.g., `rhel10cis`, `ubuntu2204stig`)
- **Expected vs found detail** -- still-failed and regressed controls show expected and actual values to aid remediation
- **Scan duration tracking** -- displays pre vs post scan duration in all report formats
- **CI-friendly exit codes** -- non-zero on regressions, with a `--strict` mode for gating on still-failed controls
- **Multiple output formats** -- text, Markdown, and JSON

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| Python 3.6+ | Standard library only, no `pip install` needed |
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

### Generate a Markdown report

```bash
./audit_compare.sh -f markdown -r remediation_report.md
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
| `--list` | `-l` | List available audit files and exit | |
| `--help` | `-h` | Show help message | |

#### Auto-Discovery

When `--pre` and `--post` are not specified, the wrapper searches the audit directory (default `/var/tmp`) for files matching:

- `*_pre_scan_*.json` -- selects the most recent by filename sort
- `*_post_scan_*.json` -- selects the most recent by filename sort

The auto-detected file paths are printed to stderr for confirmation.

#### Benchmark Auto-Detection

The report title is automatically derived from audit filenames. The tool recognizes patterns like `rhel10cis`, `ubuntu2204stig`, `amazon2023stig`, etc., and formats them as `RHEL10 CIS`, `UBUNTU2204 STIG`, etc. Use `--title` to override.

---

### Python Engine (audit_compare.py)

```
python3 audit_compare.py [OPTIONS] <pre_audit.json> <post_audit.json>
```

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

Styled HTML page with color-coded badges, collapsible control groups, and a summary table. Opens directly in a browser -- no external CSS or JavaScript required. Visual styling matches the main QA tool's HTML reports.

```bash
python3 audit_compare.py pre.json post.json --format html --output report.html
# or
./audit_compare.sh -f html -r report.html
```

Key visual elements:

- Color-coded badges for each change category (green for fixed, red for regressed, yellow for still-failed)
- Collapsible `<details>` sections per control ID -- regressed controls default to open
- Expected vs found values shown inline for regressed and still-failed tests
- Positive/negative change values highlighted in the summary table

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

## Report Sections

All report formats include the following sections:

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

### Control ID Grouping

Controls are grouped by their ID, which is auto-extracted from the Goss test title. The tool recognizes:

| Format | Pattern | Example |
|--------|---------|---------|
| CIS | Dotted numeric (`X.X.X.X`) | `1.1.1.1`, `5.2.3` |
| STIG | Alphanumeric rule ID (`XXXX-XX-XXXXXX`) | `RHEL-09-123456`, `UBTU-22-654321` |
| Other | First token before `\|` delimiter | Anything else |

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

### Strict mode for CI gating

```bash
./audit_compare.sh -s -f json -r /tmp/audit_comparison.json
```

### Generate a JSON report for CI consumption

```bash
./audit_compare.sh -f json -r /tmp/audit_comparison.json
```

### Pipe Python script output to a file

```bash
python3 audit_compare.py pre.json post.json --format markdown > report.md
```
