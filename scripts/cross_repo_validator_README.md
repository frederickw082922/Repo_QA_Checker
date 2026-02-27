# Cross-Repo Validator

Validates consistency between an Ansible-Lockdown **remediation role** and its paired **Goss audit repo** — supports both **STIG** and **CIS** benchmarks, with or without a `Private-` prefix.

**Version:** 2.5.0

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Benchmark Types](#benchmark-types)
- [Checks](#checks)
- [Report Formats](#report-formats)
- [Auto-Detection](#auto-detection)
- [Exit Codes](#exit-codes)
- [Examples](#examples)
- [How It Works](#how-it-works)
- [Relationship to QA Repo Check Tool](#relationship-to-qa-repo-check-tool)

---

## Overview

Ansible-Lockdown maintains paired repositories for each security benchmark:

| Repo Type | STIG Example | CIS Example | Contains |
|-----------|-------------|-------------|----------|
| **Remediation** | `Private-AMAZON2023-STIG` | `RHEL9-CIS` | Ansible role with tasks, defaults, handlers, templates |
| **Audit** | `AMAZON2023-STIG-Audit` | `RHEL9-CIS-Audit` | Goss test definitions, variables, audit script |

Rule toggle variables, Rule_IDs (STIG), version metadata, and category/section assignments must stay synchronized across **both** repos. `cross_repo_validator.py` automates this cross-validation with 14 independent checks.

Key features:

- **Zero external Python dependencies** — uses only the Python 3 standard library
- **Supports both STIG and CIS** benchmark types with auto-detection
- **Handles public and private repos** — works with or without `Private-` prefix
- **Auto-detects** the benchmark prefix, rule ID prefix, audit vars file, and sibling audit repo
- **Generates reports** in Markdown, JSON, or HTML
- **Reports include** git branch and benchmark version metadata
- **`--version` flag** for CI pipeline identification
- **Selective execution** via `--skip` and `--only` filters
- **Generic** across all Ansible-Lockdown benchmark pairs (RHEL, Ubuntu, Amazon, Windows, etc.)

---

## Requirements

| Requirement | Required | Notes |
|-------------|----------|-------|
| Python 3.8+ | Yes | Standard library only, no `pip install` needed |

---

## Quick Start

### STIG repo (private prefix)

```bash
# Auto-discovers the audit repo sibling
python3 scripts/cross_repo_validator.py -r Private-AMAZON2023-STIG
```

### CIS repo (public, no prefix)

```bash
python3 scripts/cross_repo_validator.py -r RHEL9-CIS
```

### Explicit paths

```bash
python3 scripts/cross_repo_validator.py \
  -r /path/to/Private-AMAZON2023-STIG \
  -a /path/to/AMAZON2023-STIG-Audit
```

### Console output (no file)

```bash
python3 scripts/cross_repo_validator.py -r RHEL9-CIS --console --no-report
```

---

## CLI Reference

```
python3 cross_repo_validator.py [OPTIONS]
```

### Help

```bash
python3 scripts/cross_repo_validator.py -h
```

```
usage: cross_repo_validator.py [-h] [-V] -r REMEDIATION [-a AUDIT]
                               [-t {stig,cis,auto}] [--format {md,json,html}]
                               [-o OUTPUT] [--skip SKIP] [--only ONLY]
                               [--strict] [--verbose] [--console]
                               [--no-report]

Cross-repo validator for Ansible-Lockdown remediation + audit pairs.

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -r REMEDIATION, --remediation REMEDIATION
                        Path to remediation repo (e.g. Private-AMAZON2023-STIG
                        or RHEL9-CIS)
  -a AUDIT, --audit AUDIT
                        Path to audit repo (auto-discovered if omitted)
  -t {stig,cis,auto}, --type {stig,cis,auto}
                        Benchmark type (default: auto-detect)
  --format {md,json,html}
                        Report format (default: md)
  -o OUTPUT, --output OUTPUT
                        Output file path (default: cross_repo_report.{fmt})
  --skip SKIP           Comma-separated check names to skip
  --only ONLY           Comma-separated check names to run exclusively
  --strict              Exit with code 1 on warnings
  --verbose             Print verbose progress to stderr
  --console             Print report to stdout
  --no-report           Skip writing report file

Supports both STIG and CIS benchmark types.  The benchmark type is
auto-detected from defaults/main.yml variable naming patterns.

Works with public repos (RHEL9-CIS) and private repos (Private-AMAZON2023-STIG).

Check keys for --skip / --only:
  rule_toggle_sync, audit_coverage, rule_id_match, rule_key_match,
  category_alignment, version_consistency, goss_include_coverage,
  config_variable_parity, goss_template_var_sync, audit_vars_completeness,
  toggle_value_sync, severity_directory, goss_block_pairing,
  when_toggle_alignment
```

### Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--version` | `-V` | Show version number and exit | — |
| `--remediation PATH` | `-r` | Path to remediation repo | **Required** |
| `--audit PATH` | `-a` | Path to audit repo | Auto-discovered |
| `--type {stig,cis,auto}` | `-t` | Benchmark type | `auto` |
| `--format {md,json,html}` | | Report output format | `md` |
| `--output PATH` | `-o` | Report output file path | `cross_repo_report.{format}` |
| `--skip CHECKS` | | Comma-separated checks to skip | None |
| `--only CHECKS` | | Comma-separated checks to run exclusively | None |
| `--strict` | | Exit with code 1 on warnings | Off |
| `--verbose` | | Print progress detail to stderr | Off |
| `--console` | | Print report to stdout | Off |
| `--no-report` | | Skip writing a report file | Off |

---

## Benchmark Types

The tool handles two benchmark families with different naming conventions:

### STIG Benchmarks

| Aspect | Pattern | Example |
|--------|---------|---------|
| Toggle variable | `{prefix}_{6digits}` | `az2023stig_000100` |
| Audit file name | `{STIG_PREFIX}-{6digits}.yml` | `AZLX-23-000100.yml` |
| Audit vars file | `vars/STIG.yml` | — |
| Conditional | `{{ if .Vars.az2023stig_000100 }}` | — |
| Task name | `SEVERITY \| STIG_ID \| ACTION` | `CAT2 \| AZLX-23-000135 \| ...` |
| Rule_ID tag | `SV-######r#######_rule` | `SV-273996r1119976_rule` |
| Category dirs | `cat_1/`, `cat_2/`, `cat_3/` | — |

### CIS Benchmarks

| Aspect | Pattern | Example |
|--------|---------|---------|
| Toggle variable | `{prefix}_rule_{section}` | `rhel9cis_rule_1_1_1_1` |
| Audit file name | `{section}.yml` | `1.1.1.1.yml` |
| Audit vars file | `vars/CIS.yml` | — |
| Conditional | `{{ if .Vars.rhel9cis_rule_1_1_1_1 }}` | — |
| Task name | `SECTION \| ACTION` | `1.1.1.1 \| Ensure...` |
| Rule_ID tag | N/A (CIS doesn't use Rule_IDs) | — |
| Category dirs | `section_*/` or `cat_*/` | — |

### Type Detection

When `--type auto` (the default), the tool examines `defaults/main.yml` for toggle patterns:
- If `_rule_` patterns are found → **CIS**
- If `_NNNNNN` (6-digit) patterns are found → **STIG**

Override with `-t stig` or `-t cis` if auto-detection guesses wrong.

---

## Checks

The tool runs 14 independent checks. Each produces a status of **PASS**, **FAIL**, **WARN**, or **SKIP**.

### Check 1: Rule Toggle Sync

**Key:** `rule_toggle_sync`

Compares rule toggle variables across 4 locations:

| Location | Repo | STIG Example | CIS Example |
|----------|------|-------------|-------------|
| `defaults/main.yml` | Remediation | `az2023stig_000100: true` | `rhel9cis_rule_1_1_1_1: true` |
| `templates/ansible_vars_goss.yml.j2` | Remediation | `az2023stig_000100: {{ ... }}` | `rhel9cis_rule_1_1_1_1: {{ ... }}` |
| `vars/STIG.yml` or `vars/CIS.yml` | Audit | `az2023stig_000100: true` | `rhel9cis_rule_1_1_1_1: true` |
| Audit test files | Audit | `{{ if .Vars.az2023stig_000100 }}` | `{{ if .Vars.rhel9cis_rule_1_1_1_1 }}` |

`defaults/main.yml` is treated as the source of truth. Any rule present there but missing from the other 3 locations (or vice-versa) is flagged.

**Severity:** warning

---

### Check 2: Audit File Coverage

**Key:** `audit_coverage`

Verifies that every rule toggle in `defaults/main.yml` has a corresponding Goss audit file, and that every audit file on disk maps back to a defined rule toggle.

For STIG, maps toggle `az2023stig_000100` to file `AZLX-23-000100.yml`. For CIS, maps toggle `rhel9cis_rule_1_1_1_1` to file `1.1.1.1.yml`.

**Severity:** warning

---

### Check 3: Rule_ID Consistency

**Key:** `rule_id_match`

Extracts `SV-*_rule` strings from remediation task tags and from audit file `Rule_ID:` metadata. For each rule present in both repos, verifies the Rule_ID values match.

**Note:** This check is most relevant for STIG benchmarks. CIS benchmarks typically don't use Rule_IDs, so this check will report fewer findings.

**Severity:** error (mismatch), warning (missing from one side)

---

### Check 4: Rule Key Consistency

**Key:** `rule_key_match`

Three-way validation:

1. **Audit filename** vs **audit metadata** — catches copy-paste errors where a file was duplicated but metadata not updated.
   - STIG: `AZLX-23-000100.yml` vs `STIG_ID: AZLX-23-000100`
   - CIS: `1.1.1.1.yml` vs section metadata
2. Rule keys present in tasks but missing from audit (informational).
3. Rule keys present in audit but missing from tasks (informational).

**Severity:** error (filename/metadata mismatch), info (coverage gaps)

---

### Check 5: Category Alignment

**Key:** `category_alignment`

Maps each rule to its category from the remediation side (`tasks/cat_1/`, `cat_2/`, `cat_3/` or `section_*/`) and verifies the corresponding audit file lives in the matching directory.

**Severity:** error

---

### Check 6: Version Consistency

**Key:** `version_consistency`

Extracts the benchmark version from up to 3 locations and normalizes for comparison:

| Location | Format Example | Normalized |
|----------|---------------|------------|
| `defaults/main.yml` | `v1.2.0` | `(1, 2)` |
| `vars/STIG.yml` or `vars/CIS.yml` | `v1r2` | `(1, 2)` |
| `run_audit.sh` | `1.2.0` | `(1, 2)` |

Compares the `(major, minor)` tuple across all locations. The different format conventions (dotted vs STIG `vXrY`) are handled transparently.

**Severity:** error

---

### Check 7: Goss Include Coverage

**Key:** `goss_include_coverage`

Parses the glob patterns from `goss.yml` and verifies that every audit file on disk would be matched by at least one pattern. Catches files that exist but would be silently excluded at runtime.

**Severity:** error

---

### Check 8: Config Variable Parity

**Key:** `config_variable_parity`

Compares non-toggle configuration variables (e.g., syslog paths, cipher lists, password policies) that appear in both `defaults/main.yml` and the audit vars file. These are variables like `az2023stig_syslog_trustedcertificatefile` or `rhel9cis_ssh_ciphers` that control runtime behavior and must match for audit tests to produce valid results.

Only simple scalar values are compared; multi-line blocks and list values are skipped.

**Severity:** warning

---

### Check 9: Template Variable Sync

**Key:** `goss_template_var_sync`

Scans `templates/ansible_vars_goss.yml.j2` for variables that use **hardcoded literal values** instead of Jinja2 templating (`{{ }}`). When a hardcoded value is found, verifies it matches `defaults/main.yml`. Catches cases where a developer hardcoded a value in the template that has since changed in defaults.

**Severity:** warning (mismatch), info (hardcoded but not in defaults)

---

### Check 10: Audit Vars Completeness

**Key:** `audit_vars_completeness`

Scans all goss test files for `{{ .Vars.xxx }}` references and verifies each non-toggle variable is defined in the audit vars file (`vars/STIG.yml` or `vars/CIS.yml`). Catches variables that goss tests rely on but that aren't available when running the audit standalone (without the Ansible-generated vars file).

Known runtime variables injected by the audit script (e.g., `machine_uuid`, `os_release`, `system_type`) are excluded from this check.

**Severity:** warning

---

### Check 11: Toggle Value Sync

**Key:** `toggle_value_sync`

Compares the boolean values (`true`/`false`) of rule toggles that exist in both `defaults/main.yml` and the audit vars file. A toggle set to `true` in defaults but `false` in audit vars means the audit will skip a test that remediation actively runs (and vice-versa).

Only toggles present in both files are compared; missing toggles are already covered by Check 1.

**Severity:** warning

---

### Check 12: Severity-Directory Alignment

**Key:** `severity_directory`

For STIG benchmarks, extracts the severity label (`HIGH`, `MEDIUM`, `LOW`) from task names and verifies it matches the `cat_X/` directory the task file lives in:

| Severity | Expected Directory |
|----------|--------------------|
| HIGH | `tasks/cat_1/` |
| MEDIUM | `tasks/cat_2/` |
| LOW | `tasks/cat_3/` |

Catches tasks that were moved to a different category directory without updating the task name, or severity reclassifications that weren't reflected in the directory structure.

**Note:** Skipped for CIS benchmarks (they don't use severity labels in task names).

**Severity:** error

---

### Check 13: Goss Block Pairing

**Key:** `goss_block_pairing`

Validates that opening template blocks (`{{ if ... }}`, `{{ range ... }}`) are properly paired with closing blocks (`{{ end }}`) in each audit file. Mismatched blocks can cause silent test failures at runtime.

Properly accounts for nested constructs (e.g., a `{{ range }}` inside an `{{ if }}`).

**Severity:** warning

---

### Check 14: When-Toggle Alignment

**Key:** `when_toggle_alignment`

For STIG benchmarks, verifies that each task's `when:` condition references the correct toggle variable for its STIG_ID. For example, a task named `MEDIUM | AZLX-23-000100 | ...` should use `when: az2023stig_000100`, not a different toggle.

Catches copy-paste errors where a task was duplicated but the `when:` condition wasn't updated.

**Note:** Skipped for CIS benchmarks.

**Severity:** error

---

### Skipping Checks

```bash
# Skip rule toggle and version checks
python3 cross_repo_validator.py -r repo --skip rule_toggle_sync,version_consistency
```

### Running Specific Checks

```bash
# Run only Rule_ID and rule key checks
python3 cross_repo_validator.py -r repo --only rule_id_match,rule_key_match
```

### Check Key Reference

| Key | Check Name |
|-----|-----------|
| `rule_toggle_sync` | Rule Toggle Sync |
| `audit_coverage` | Audit File Coverage |
| `rule_id_match` | Rule_ID Consistency |
| `rule_key_match` | Rule Key Consistency |
| `category_alignment` | Category Alignment |
| `version_consistency` | Version Consistency |
| `goss_include_coverage` | Goss Include Coverage |
| `config_variable_parity` | Config Variable Parity |
| `goss_template_var_sync` | Template Variable Sync |
| `audit_vars_completeness` | Audit Vars Completeness |
| `toggle_value_sync` | Toggle Value Sync |
| `severity_directory` | Severity-Directory Alignment |
| `goss_block_pairing` | Goss Block Pairing |
| `when_toggle_alignment` | When-Toggle Alignment |

---

## Report Formats

### Markdown (default)

```bash
python3 cross_repo_validator.py -r repo
# Creates: cross_repo_report.md
```

Generates a Markdown report with:

- Header metadata (repos, date, detected prefixes, benchmark type, benchmark version, git branches)
- Summary table (total/passed/failed/warnings/skipped)
- Per-check status table
- Per-check findings tables (up to 200 findings per check)

### HTML

```bash
python3 cross_repo_validator.py -r repo --format html
# Creates: cross_repo_report.html
```

Self-contained HTML report with embedded CSS. Features:

- Summary cards with colour-coded counts (pass/fail/warn/skip)
- Overview table with status badges
- Collapsible per-check detail sections (PASS checks start collapsed)
- Colour-coded severity labels (error=red, warning=amber, info=teal)
- Monospace file paths, sticky table headers, responsive layout
- No external dependencies — opens in any browser

### JSON

```bash
python3 cross_repo_validator.py -r repo --format json
# Creates: cross_repo_report.json
```

Structured JSON with metadata, summary counts, and per-check findings arrays. Suitable for programmatic consumption and CI pipelines.

### Custom Output Path

```bash
python3 cross_repo_validator.py -r repo -o /tmp/validation.md
```

### Console Only (no file)

```bash
python3 cross_repo_validator.py -r repo --console --no-report
```

---

## Auto-Detection

The tool auto-detects five things so you rarely need to configure anything manually.

### 1. Benchmark Type

Detected from `defaults/main.yml` by examining toggle variable patterns:

| Pattern Found | Detected Type |
|--------------|---------------|
| `{prefix}_rule_{section}` (e.g., `rhel9cis_rule_1_1_1_1`) | CIS |
| `{prefix}_{6digits}` (e.g., `az2023stig_000100`) | STIG |

### 2. Benchmark Prefix

Detected from `defaults/main.yml` by voting on underscore-delimited variable name segments. Works across all Ansible-Lockdown repos:

| Repo | Detected Prefix |
|------|----------------|
| Private-AMAZON2023-STIG | `az2023stig` |
| RHEL9-CIS | `rhel9cis` |
| Ubuntu2204-CIS | `ubuntu2204cis` |

### 3. Rule ID Prefix (STIG only)

Detected from the first audit file name found under `cat_*/`:

| Audit File | Detected Prefix |
|-----------|----------------|
| `AZLX-23-000100.yml` | `AZLX-23` |
| `RHEL-09-000001.yml` | `RHEL-09` |

CIS repos return an empty prefix (they use section-based naming like `1.1.1.1.yml`).

### 4. Audit Vars File

The tool scans the audit repo's `vars/` directory:

| Benchmark Type | Expected File | Fallback |
|---------------|--------------|----------|
| STIG | `vars/STIG.yml` | Any `.yml` in `vars/` |
| CIS | `vars/CIS.yml` | Any `.yml` in `vars/` |

### 5. Audit Repo Discovery

When `-a` is omitted, the tool searches for a sibling directory:

**STIG with Private prefix:**
```
parent_directory/
  Private-AMAZON2023-STIG/    <-- you pass this with -r
  AMAZON2023-STIG-Audit/      <-- auto-discovered (strips Private-)
```

**CIS (public repo):**
```
parent_directory/
  RHEL9-CIS/                  <-- you pass this with -r
  RHEL9-CIS-Audit/            <-- auto-discovered
```

Logic:
1. Try `{repo_name}-Audit` directly
2. Strip `Private-` prefix and try `{base}-Audit`
3. Fall back to any `*-Audit` directory containing the benchmark name

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed (or only warnings without `--strict`) |
| `1` | Warnings found (only with `--strict`) |
| `2` | Errors found (any check has FAIL status) |

### Default behavior

- Exit `0` for PASS and WARN results
- Exit `2` only when a check has FAIL status

### Strict mode

```bash
python3 cross_repo_validator.py -r repo --strict
```

- Exit `0` only when all checks are PASS or SKIP
- Exit `1` if any check has WARN status
- Exit `2` if any check has FAIL status

---

## Examples

### STIG: Full validation with verbose progress

```bash
python3 scripts/cross_repo_validator.py \
  -r Private-AMAZON2023-STIG \
  --verbose \
  --console
```

Output:

```
  [*] Detected benchmark prefix: az2023stig
  [*] Benchmark type: STIG
  [*] Detected rule ID prefix: AZLX-23
  [*] Extracting rule toggles from defaults/main.yml...
  [*]   Found 195 toggles
  [*] Extracting rule toggles from vars/STIG.yml...
  [*]   Found 191 toggles
  ...
  [*] Running: Rule Toggle Sync...
  [*] Running: Audit File Coverage...
  ...
```

### CIS: Validate a public RHEL 9 repo

```bash
python3 scripts/cross_repo_validator.py \
  -r RHEL9-CIS \
  --verbose \
  --console
```

### Force benchmark type

```bash
# Override auto-detection
python3 scripts/cross_repo_validator.py -r MyRepo -t cis
```

### JSON output for CI pipelines

```bash
python3 scripts/cross_repo_validator.py \
  -r Private-AMAZON2023-STIG \
  --format json \
  -o validation.json \
  --strict
```

### Quick check of just version and goss coverage

```bash
python3 scripts/cross_repo_validator.py \
  -r Private-AMAZON2023-STIG \
  --only version_consistency,goss_include_coverage \
  --console --no-report
```

### Repos in different locations

```bash
python3 scripts/cross_repo_validator.py \
  -r /home/user/repos/RHEL9-CIS \
  -a /home/user/audit/RHEL9-CIS-Audit \
  -o rhel9_cross_validation.md
```

### Sample STIG findings output

```
## [WARN] Rule Toggle Sync

| Severity | File | Line | Description |
|----------|------|------|-------------|
| warning | `vars/STIG.yml` | - | In defaults but missing from vars/STIG.yml: 'az2023stig_001295' |
| warning | `(audit files)` | - | In defaults but no audit conditional found: 'az2023stig_001295' |

## [FAIL] Rule_ID Consistency

| Severity | File | Line | Description |
|----------|------|------|-------------|
| error | `cat_2/AZLX-23-000xxx/AZLX-23-000135.yml` | - | Rule_ID mismatch for AZLX-23-000135: task='SV-273996r1119976_rule' vs audit='SV-274000r1119991_rule' |

## [FAIL] Rule Key Consistency

| Severity | File | Line | Description |
|----------|------|------|-------------|
| error | `cat_2/AZLX-23-002xxx/AZLX-23-002450.yml` | - | Audit filename/metadata STIG_ID mismatch: file='AZLX-23-002450' vs metadata='AZLX-23-002445' |

## [WARN] Config Variable Parity

| Severity | File | Line | Description |
|----------|------|------|-------------|
| warning | `vars/STIG.yml` | 228 | Config value mismatch for 'az2023stig_syslog_remote_log_server': defaults='192.168.2.100' vs vars/STIG.yml='syslog+tcp://127.0.0.1:514' |
| warning | `vars/STIG.yml` | 225 | Config value mismatch for 'az2023stig_syslog_trustedcertificatefile': defaults='/etc/ssl/ca/trusted.pem' vs vars/STIG.yml='/etc/pki/tls/certs/ca-bundle.crt' |
```

---

## How It Works

### Data Flow

```
  Remediation Repo                         Audit Repo
  ================                         ==========

  defaults/main.yml ----+              +-- vars/STIG.yml or CIS.yml
    (rule toggles)      |              |     (rule toggles)
                        |              |
  templates/            |  cross_repo  |   cat_1/*.yml  (STIG)
    ansible_vars_       +--validator---+   cat_2/**/*.yml
    goss.yml.j2         |  14 checks |   cat_3/**/*.yml
    (rule toggles)      |              |   section_*/*.yml (CIS)
                        |              |     (conditionals,
  tasks/cat_{1,2,3}/  --+              +--    Rule_IDs,
    (rule keys,                        |      rule keys,
     Rule_IDs,                         |      categories)
     categories)                       |
                                       +-- goss.yml
                                       |     (include globs)
                                       |
                                       +-- run_audit.sh
                                             (version)
```

### Detection Phase

Before extraction, the tool detects:

| What | How |
|------|-----|
| Benchmark type | Count `_rule_` vs 6-digit patterns in `defaults/main.yml` |
| Benchmark prefix | Counter-voting on underscore-delimited variable segments |
| Rule ID prefix | First STIG-pattern filename in `cat_*/` (empty for CIS) |
| Audit vars file | Scan `vars/` for `STIG.yml`, `CIS.yml`, or any `.yml` |
| Audit repo | Sibling directory search with `Private-` prefix stripping |

### Extraction Phase

Before running checks, the tool extracts data from both repos into normalized dictionaries:

| Data Source | What Gets Extracted |
|------------|-------------------|
| `defaults/main.yml` | Rule toggles with line numbers |
| `defaults/main.yml` | Non-toggle config variables (`{prefix}_*`) with values |
| `templates/ansible_vars_goss.yml.j2` | Toggle pattern + hardcoded vs templated config variables |
| `vars/STIG.yml` or `vars/CIS.yml` | Toggle pattern + config variables + all defined variable names |
| Audit `cat_*/**/*.yml` or `section_*/**/*.yml` | Goss conditionals, Rule_IDs, rule keys, categories, `.Vars.*` references |
| Task `cat_*/*.yml` or `section_*/*.yml` | Rule keys from task names, Rule_IDs from tags, categories from directory |
| `goss.yml` | Glob patterns for audit file inclusion |
| 3 version locations | Raw version strings normalized to `(major, minor)` tuples |

### Check Phase

Each check receives the pre-extracted data and produces a `CheckResult` containing `Finding` objects. Checks are independent and can run in any order or subset.

### Report Phase

Results are formatted into Markdown or JSON. Findings are capped at 200 per check in Markdown to keep reports readable.

---

## Relationship to QA Repo Check Tool

| Aspect | QA Repo Check Tool | Cross-Repo Validator |
|--------|--------------------|---------------------|
| **Scope** | Single repo (remediation OR audit) | Two repos (remediation AND audit) |
| **Location** | `Repo_QA_Checker/` | `scripts/` |
| **Checks** | 11 (lint, spelling, grammar, FQCN, etc.) | 14 (toggle sync, Rule_ID, config parity, block pairing, etc.) |
| **Benchmark Types** | STIG and CIS | STIG and CIS |
| **Data Models** | `Finding`, `CheckResult` dataclasses | Same dataclass pattern (compatible) |
| **Dependencies** | Python 3.8+ (optional: yamllint, ansible-lint) | Python 3.8+ only |
| **Auto-Detection** | Benchmark prefix | Benchmark prefix + type + rule ID prefix + audit repo |

The two tools are complementary:

1. Run **QA Repo Check** against each repo individually for internal consistency
2. Run **Cross-Repo Validator** against the pair for cross-repo consistency

Both use the same `Finding`/`CheckResult` data models, enabling future integration into a unified tool.
