# Ansible-Lockdown QA Repository Check Tool

Comprehensive quality assurance tool for [Ansible-Lockdown](https://github.com/ansible-lockdown) CIS/STIG hardening roles.

**Version:** 2.6.0

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Checks](#checks)
- [Report Formats](#report-formats)
- [Auto-Fix Mode](#auto-fix-mode)
- [Baseline / Delta Mode](#baseline--delta-mode)
- [Configuration File](#configuration-file)
- [Exit Codes](#exit-codes)
- [pre-commit Integration](#pre-commit-integration)
- [CI/CD Integration](#cicd-integration)
- [Examples](#examples)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

---

## Overview

`Ansible_Lockdown_QA_Repo_Check.py` is a single-file Python tool that runs 11 quality checks against any Ansible-Lockdown role repository. It validates YAML syntax, Ansible best practices, spelling, grammar, variable usage, naming conventions, FQCN compliance, rule coverage, and more.

Key features:

- **Zero external Python dependencies** -- uses only the Python standard library
- **Auto-detects** the benchmark variable prefix (e.g., `rhel9cis`, `ubuntu2204cis`) and benchmark type (CIS vs STIG)
- **Full CIS and STIG support** -- rule coverage checks work for both `{prefix}_rule_X_X_X` (CIS) and `{prefix}_XXXXXX` (STIG) toggle patterns
- **Generates reports** in Markdown, HTML, or JSON with repo name, benchmark version, and timestamp in filenames
- **Auto-fix mode** for common issues (spelling, file mode quoting, FQCN)
- **Baseline/delta mode** for incremental QA in CI pipelines
- **Per-repo configuration** via `.qa_config.yml`
- **Portable** across all Ansible-Lockdown repos (RHEL, Ubuntu, Amazon, etc.)

---

## Requirements

| Requirement | Required | Notes |
|-------------|----------|-------|
| Python 3.8+ | Yes | Standard library only, no `pip install` needed |
| `yamllint` | Optional | Install via `pip install yamllint` -- check is skipped if not found |
| `ansible-lint` | Optional | Install via `pip install ansible-lint` -- check is skipped if not found |
| `git` | Optional | Used to detect the current branch for report metadata |
| `PyYAML` | Optional | If installed, used for config parsing; otherwise falls back to built-in parser |

---

## Quick Start

### Run from inside the role directory

```bash
cd /path/to/RHEL9-CIS
python3 Ansible_Lockdown_QA_Repo_Check.py --console --no-report
```

### Run from anywhere (point to the role)

```bash
python3 /path/to/Ansible_Lockdown_QA_Repo_Check.py -d /path/to/RHEL9-CIS --console
```

### Generate an HTML report

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py -f html
```

This creates `qa_report_{repo}_{version}_{timestamp}.html` in the role directory (e.g., `qa_report_RHEL9-CIS_v1_0_0_2026-02-27_143012.html`).

---

## CLI Reference

```
python3 Ansible_Lockdown_QA_Repo_Check.py [OPTIONS]
```

### Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--benchmark PREFIX` | `-b` | Benchmark variable prefix | Auto-detected |
| `--format {md,html,json}` | `-f` | Report output format | `md` |
| `--output PATH` | `-o` | Report output file path | `qa_report_{repo}_{version}_{timestamp}.{format}` |
| `--directory PATH` | `-d` | Repository directory | Script location or cwd |
| `--skip CHECKS` | | Comma-separated checks to skip | None |
| `--only CHECKS` | | Comma-separated checks to run (skip all others) | None |
| `--min-severity {info,warning,error}` | | Minimum severity to include in reports | `info` |
| `--fix` | | Auto-fix spelling, file mode quoting, and FQCN issues | Off |
| `--dry-run` | | Preview auto-fix changes without modifying files | Off |
| `--save-baseline FILE` | | Save current findings as a baseline JSON file | None |
| `--baseline FILE` | | Compare against baseline, show only new findings | None |
| `--no-report` | | Skip writing a report file (console-only mode) | Off |
| `--strict` | | Exit 1 on warnings, exit 2 on errors | Off |
| `--verbose` | | Show per-check timing and progress on stderr | Off |
| `--progress` | | Show inline progress status during checks | Auto (TTY) |
| `--no-progress` | | Disable progress status even on TTY | Off |
| `--console` | | Print colored results to terminal | Off |
| `--version` | | Show tool version and exit | |
| `--help` | `-h` | Show help message with all options, examples, and exit codes | |

### Built-in Help

Run `--help` to see the full usage summary directly in your terminal:

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --help
```

This displays all available flags, usage examples, valid check names for `--skip` / `--only`, and exit code definitions.

### Directory Resolution

When `-d` is not specified, the tool resolves the role directory in this order:

1. The directory containing the script itself (useful when the script lives inside the role)
2. The current working directory

---

## Checks

The tool runs 11 independent checks. Each produces a status of **PASS**, **FAIL**, **WARN**, or **SKIP**.

| # | Check Name | `--skip` Key | What It Does |
|---|-----------|--------------|--------------|
| 1 | **YAML Lint** | `yamllint` | Runs `yamllint -f parsable` against all YAML files. Skipped if `yamllint` is not installed. |
| 2 | **Ansible Lint** | `ansiblelint` | Runs `ansible-lint -f pep8`. Skipped if `ansible-lint` is not installed. |
| 3 | **Spell Check** | `spelling` | Scans comments and task `name:` fields for ~130 common misspellings. Jinja2 expressions are stripped before checking. |
| 4 | **Grammar Check** | `grammar` | Detects repeated words, double spaces, missing apostrophes, and subject-verb disagreement in comments and task names. Jinja2 expressions are stripped before checking. |
| 5 | **Unused Variables** | `unused_vars` | **Forward:** Variables defined in `defaults/main.yml` or `vars/` but never referenced. **Reverse:** Variables with the benchmark prefix referenced in tasks but never defined. |
| 6 | **Variable Naming** | `var_naming` | Validates `register:` variable prefixes, detects duplicate register names (with mutually exclusive `when:` suppression), and duplicate defaults. |
| 7 | **File Mode Quoting** | `file_mode` | Flags unquoted numeric `mode:` values (e.g., `mode: 0644` should be `mode: '0644'`). |
| 8 | **Company Naming** | `company_naming` | Detects outdated company name references (configurable). |
| 9 | **Audit Template** | `audit_template` | Checks `templates/ansible_vars_goss.yml.j2` for duplicate keys. |
| 10 | **FQCN Usage** | `fqcn` | Detects bare (non-FQCN) Ansible built-in module names (e.g., `command:` should be `ansible.builtin.command:`). |
| 11 | **Rule Coverage** | `rule_coverage` | Cross-references rule toggle variables in `defaults/main.yml` against task `when:` conditions to find orphaned or missing rules. Auto-detects CIS (`{prefix}_rule_X_X_X`) vs STIG (`{prefix}_XXXXXX`) toggle patterns. |

### Skipping Checks

Use `--skip` with a comma-separated list of check keys:

```bash
# Skip spell and grammar checks
python3 Ansible_Lockdown_QA_Repo_Check.py --skip spelling,grammar --console --no-report

# Skip external linters (useful when yamllint/ansible-lint are not installed)
python3 Ansible_Lockdown_QA_Repo_Check.py --skip yamllint,ansiblelint --console --no-report
```

### Running Specific Checks

Use `--only` to run only the named checks (all others are skipped):

```bash
# Run only FQCN and spelling checks
python3 Ansible_Lockdown_QA_Repo_Check.py --only fqcn,spelling --console --no-report

# Run only rule coverage
python3 Ansible_Lockdown_QA_Repo_Check.py --only rule_coverage --console --no-report
```

### Severity Levels

Each finding has a severity level:

| Severity | Description | Examples |
|----------|-------------|---------|
| `info` | Style suggestions, low priority | Double spaces, misspellings |
| `warning` | Potential issues that should be reviewed | Subject-verb disagreement, duplicate registers, unused variables |
| `error` | Definite problems that must be fixed | Rule referenced in tasks but not defined |

Filter findings with `--min-severity`:

```bash
# Only show warnings and errors
python3 Ansible_Lockdown_QA_Repo_Check.py --min-severity warning --console --no-report
```

---

## Report Formats

### Default Output Naming

Report filenames include the repo name, benchmark version, and timestamp:

```
qa_report_{repo}_{version}_{timestamp}.{ext}
```

For example: `qa_report_RHEL9-CIS_v1_0_0_2026-02-27_143012.md`

The benchmark version is read from `benchmark_version:` in `defaults/main.yml`. If not found, `unknown` is used.

### Markdown (default)

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py -f md
# Creates: qa_report_RHEL9-CIS_v1_0_0_2026-02-27_143012.md
```

Generates a Markdown file with a summary table and per-check sections containing findings tables.

### HTML

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py -f html
# Creates: qa_report_RHEL9-CIS_v1_0_0_2026-02-27_143012.html
```

Generates a styled HTML page with color-coded severity badges, suitable for viewing in a browser.

### JSON

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py -f json
# Creates: qa_report_RHEL9-CIS_v1_0_0_2026-02-27_143012.json
```

Generates structured JSON output including metadata, summary counts, per-check elapsed times, and all findings. Useful for programmatic consumption and CI pipelines.

### Custom Output Path

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py -f html -o /tmp/my_report.html
```

### Console Only (no file)

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --console --no-report
```

---

## Auto-Fix Mode

The `--fix` flag automatically corrects certain findings in place:

| Check | What Gets Fixed |
|-------|----------------|
| Spelling | Misspelled words in comments are replaced (case-preserving) |
| File Mode Quoting | Bare `mode: 0644` becomes `mode: '0644'` |
| FQCN | Bare `command:` becomes `ansible.builtin.command:` |

### Dry-run preview

Use `--dry-run` to see what would be changed without modifying any files:

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --dry-run --console --no-report
```

Output shows each proposed change on stderr:

```
  tasks/main.yml:23:     mode: 0600 ->     mode: '0600'
  tasks/main.yml:12:   debug: ->   ansible.builtin.debug:
Dry-run: 2 issue(s) would be fixed.
```

### Apply fixes

```bash
# Apply fixes
python3 Ansible_Lockdown_QA_Repo_Check.py --fix --console --no-report

# Re-run to verify
python3 Ansible_Lockdown_QA_Repo_Check.py --console --no-report
```

> **Note:** Always review the changes with `git diff` after running `--fix`. The tool modifies files in place.

---

## Baseline / Delta Mode

Baseline mode lets you track only **new** findings relative to a known state. This is useful for CI pipelines where you want to prevent regressions without fixing all legacy issues immediately.

### Save a baseline

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --save-baseline baseline.json --no-report
```

This creates `baseline.json` containing all current findings.

### Compare against a baseline

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --baseline baseline.json --console --no-report
```

Only findings **not present** in the baseline are shown. Existing findings are filtered out.

### Typical workflow

```bash
# On the main branch, save a baseline
git checkout main
python3 Ansible_Lockdown_QA_Repo_Check.py --save-baseline baseline.json --no-report

# On a feature branch, check for new issues only
git checkout feature-branch
python3 Ansible_Lockdown_QA_Repo_Check.py --baseline baseline.json --strict --console --no-report
```

---

## Configuration File

Create a `.qa_config.yml` file in the role root to customize check behavior. The tool also accepts `.qa_config.yaml` or `.qa_config.json`.

### Example `.qa_config.yml`

```yaml
# Checks to skip by default
skip_checks:
  - yamllint
  - ansiblelint

# Words to exclude from spell check findings
spelling_exceptions:
  - nftables
  - tmpfiles
  - logrotate

# Accepted register variable prefixes
register_prefixes:
  - discovered_
  - prelim_
  - pre_audit_
  - post_audit_
  - set_

# Paths to exclude from FQCN check
fqcn_exclude_paths:
  - molecule/

# Outdated company names to flag
company_old_names:
  - mindpoint

# Line patterns that suppress company name findings
company_exclude_patterns:
  - tyto
  - project
  - author
  - "company:"
  - namespace
  - company_title

# Minimum severity for reports
min_severity: info
```

### Inline list syntax

The config parser also supports inline lists:

```yaml
skip_checks: [yamllint, ansiblelint]
spelling_exceptions: [nftables, tmpfiles, logrotate]
```

### Config defaults

If no config file is present, these defaults are used:

| Key | Default Value |
|-----|---------------|
| `skip_checks` | `[]` |
| `spelling_exceptions` | `[]` |
| `register_prefixes` | `discovered_`, `prelim_`, `pre_audit_`, `post_audit_`, `set_` |
| `fqcn_exclude_paths` | `molecule/` |
| `company_old_names` | `mindpoint` |
| `company_exclude_patterns` | `tyto`, `project`, `author`, `company:`, `namespace`, `company_title` |
| `min_severity` | `info` |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed (or only warnings without `--strict`) |
| `1` | Warnings found (only with `--strict`) |
| `2` | Errors found (any check has FAIL status) |

### Default behavior (without `--strict`)

- Exit `0` for PASS and WARN results
- Exit `2` only when a check has FAIL status (errors)

### Strict mode

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --strict --console --no-report
```

- Exit `0` only when all checks are PASS or SKIP
- Exit `1` if any check has WARN status
- Exit `2` if any check has FAIL status

---

## pre-commit Integration

This tool can be used as a [pre-commit](https://pre-commit.com/) hook so QA checks run automatically on every commit or in CI via `pre-commit run --all-files`.

### Basic Usage

Add the following to your Ansible role's `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/ansible-lockdown/Repo_QA_Checker
  rev: v2.6.0  # pin to a release tag
  hooks:
    - id: ansible-lockdown-qa
```

The hook runs with sensible defaults: `-d . --strict --console --no-report`. It operates on the entire role directory (not individual files) and exits non-zero on warnings or errors.

### Overriding Default Arguments

You can override the default `args` in your `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/ansible-lockdown/Repo_QA_Checker
  rev: v2.6.0
  hooks:
    - id: ansible-lockdown-qa
      args: ['-d', '.', '--console', '--no-report', '--skip', 'grammar']
```

### Adding Linter Dependencies

By default, the `yamllint` and `ansible-lint` checks are skipped gracefully when those tools are not installed. To include them, add `additional_dependencies`:

```yaml
- repo: https://github.com/ansible-lockdown/Repo_QA_Checker
  rev: v2.6.0
  hooks:
    - id: ansible-lockdown-qa
      additional_dependencies: ['yamllint', 'ansible-lint']
```

### Testing Locally

```bash
# Test the hook against your role without installing it permanently
cd /path/to/your-ansible-role
pre-commit try-repo /path/to/Repo_QA_Checker ansible-lockdown-qa --all-files
```

> **Note:** The `-d .` argument is required when running as a hook. pre-commit sets the working directory to the consumer's repo root, and without `-d .` the tool would look for role files in its own cached install directory.

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: QA Check
on: [push, pull_request]

jobs:
  qa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install linters
        run: pip install yamllint ansible-lint

      - name: Run QA checks
        run: |
          python3 Ansible_Lockdown_QA_Repo_Check.py \
            --strict \
            -f json \
            -o qa_report.json

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: qa-report
          path: qa_report.json
```

### GitHub Actions with Baseline

```yaml
      - name: Run QA checks (delta only)
        run: |
          python3 Ansible_Lockdown_QA_Repo_Check.py \
            --baseline baseline.json \
            --strict \
            --console \
            --no-report
```

### GitLab CI Example

```yaml
qa-check:
  stage: test
  script:
    - pip install yamllint ansible-lint
    - python3 Ansible_Lockdown_QA_Repo_Check.py --strict -f html -o qa_report.html
  artifacts:
    when: always
    paths:
      - qa_report.html
```

---

## Examples

### Basic console check (no file output)

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --console --no-report
```

### Generate all report formats

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py -f md -o reports/qa.md
python3 Ansible_Lockdown_QA_Repo_Check.py -f html -o reports/qa.html
python3 Ansible_Lockdown_QA_Repo_Check.py -f json -o reports/qa.json
```

### Progress status

When running on an interactive terminal, the tool prints progress lines showing which check is running:

```
  [1/11] YAML Lint, Ansible Lint (parallel)...
    YAML Lint done (1.03s)
    Ansible Lint done (0.51s)
  [3/11] Spell Check...
  [4/11] Grammar Check...
  [5/11] Unused Variables...
  ...
```

Progress is automatically disabled when output is piped or in CI environments. Use `--no-progress` to disable it explicitly, or `--progress` to force it on.

### Verbose mode with timing

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --verbose --console --no-report
```

Output includes per-check elapsed time:

```
  Running yamllint (parallel) ...
  Running ansiblelint (parallel) ...
    ansiblelint completed in 0.51s
    yamllint completed in 1.03s
  Running spelling ...
    spelling completed in 0.04s
  ...
```

### Only warnings and errors

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --min-severity warning --console --no-report
```

### Run against a different repository

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py -d /path/to/Ubuntu2204-CIS --console --no-report
```

### Override auto-detected prefix

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py -b ubuntu2204cis --console --no-report
```

### Run only specific checks

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --only fqcn,spelling --console --no-report
```

### Dry-run auto-fix (preview only)

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --dry-run --console --no-report
```

### Auto-fix then verify

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --fix --no-report
python3 Ansible_Lockdown_QA_Repo_Check.py --console --no-report
git diff  # review changes
```

### Save and compare baselines

```bash
# Save current state
python3 Ansible_Lockdown_QA_Repo_Check.py --save-baseline baseline.json --no-report

# After making changes, check for new issues
python3 Ansible_Lockdown_QA_Repo_Check.py --baseline baseline.json --console --no-report
```

---

## Development

### Linting

The project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting. Configuration is in `pyproject.toml`.

```bash
pip install ruff

# Check for issues
ruff check .

# Auto-fix lint issues
ruff check --fix .

# Format code
ruff format .
```

### Installing as a Package

```bash
pip install .

# Or with optional linter dependencies
pip install ".[lint]"

# Or with dev dependencies (pytest, ruff)
pip install ".[dev]"

# Then run from anywhere
ansible-lockdown-qa -d /path/to/role --console --no-report
```

---

## Troubleshooting

### "Error: defaults/main.yml not found. Are you in an Ansible role directory?"

The tool could not locate `defaults/main.yml`. This happens when:

- You are running from outside the role directory without `-d`
- The path provided with `-d` is not an Ansible role

**Fix:** Use `-d /path/to/role` to specify the role directory explicitly.

### yamllint or ansible-lint checks show SKIP

The external tool is not installed. Install with:

```bash
pip install yamllint ansible-lint
```

The checks will be skipped gracefully if the tools are not available -- this is not an error.

### False positives in variable checks

If valid variables are being flagged:

- **Unused variables:** The variable may be used in a Jinja2 expression the tool doesn't parse. Add it to the spelling_exceptions in `.qa_config.yml` or review manually.
- **Duplicate registers:** The tool suppresses duplicates when tasks have different `when:` conditions (mutually exclusive). If a duplicate is valid for other reasons, it will still be reported.

### Grammar check reports too many double-space findings

Double-space findings are `info` severity. Use `--min-severity warning` to suppress them, or skip the grammar check entirely:

```bash
python3 Ansible_Lockdown_QA_Repo_Check.py --skip grammar --console --no-report
```

### Console colors not displaying

Colors are automatically disabled when output is piped or redirected. They only display on interactive terminals (TTY).
