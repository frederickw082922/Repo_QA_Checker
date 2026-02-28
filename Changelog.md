# Changelog

All notable changes to the Ansible-Lockdown QA Repository Check Tool are documented in this file.

---

## 2.6.0 - 2026-02-28

### Added

- **Audit Compare Tool** (`scripts/audit_compare.py`, `scripts/audit_compare.sh`) -- new tool for comparing pre and post remediation Goss audit results
  - Shell wrapper with auto-discovery of latest pre/post audit files in `/var/tmp`
  - CIS and STIG control ID extraction -- auto-groups by `1.1.1.1` (CIS) or `RHEL-09-123456` (STIG) patterns
  - Benchmark name auto-detection from filenames (e.g., `rhel10cis` -> `RHEL10 CIS`)
  - Benchmark version auto-detection from filenames (e.g., `v1_0_0`, `v1.2.0`)
  - Four output formats: `text`, `markdown`, `json`, `html`
  - HTML reports with color-coded badges, collapsible control groups, and styled summary tables matching main QA tool
  - Auto-generated report filenames: `audit_compare_report_{benchmark}_{version}_{datetime}.{ext}`
  - Expected vs found detail on regressed and still-failed controls
  - Scan duration comparison in summary section
  - CI-friendly exit codes: `0` (no regressions), `1` (regressions), `2` (input error)
  - `--strict` mode: also exits `1` on still-failed controls
  - `--title` flag to override auto-detected benchmark name
  - `--no-report` flag for stdout-only output
  - README at `scripts/audit_compare_README.md`

---

## 2.5.0

### Added

- **STIG support:** Benchmark type auto-detection (CIS vs STIG) via `_detect_benchmark_type()`. Rule Coverage check now correctly handles STIG toggle patterns (`{prefix}_XXXXXX`) in addition to CIS patterns (`{prefix}_rule_X_X_X`). Previously all STIG repos silently received a false PASS on rule coverage.
- **Report filenames:** Default output filenames now include repo name, benchmark version, and timestamp (e.g., `qa_report_RHEL8-STIG_v2r4_2026-02-27_143012.md`). Benchmark version is extracted from `benchmark_version:` in `defaults/main.yml`.
- **Report metadata:** `benchmark_version` field added to `ReportMetadata`. Benchmark version now displayed in Markdown, HTML, and JSON report headers.
- **Jinja2 stripping:** Spell check and grammar check now strip `{{ ... }}` expressions before analysis, reducing false positives from template variable names in task names and comments.

### Fixed

- **Rule Coverage (STIG):** Check no longer silently returns 0 issues on STIG repos — uses `{prefix}_\d{6}` pattern instead of hardcoded `{prefix}_rule_\w+`
- **Grammar check descriptions:** Subject-verb disagreement findings now show the matched word (e.g., `'variables' + 'is'` instead of generic `plural noun + 'is'`)
- **Unused variable check:** Replaced overly broad substring suppression (`vname in dv`) with proper prefix matching (`dv.startswith(vname + "_")`) to prevent hiding genuinely undefined variables
- **File mode check:** Comment lines (`# mode: 0644`) are now skipped, preventing false positives
- **Auto-fix file mode:** Fixed silent failure when `mode:` values had non-standard whitespace (e.g., `mode:  0644`). Uses regex replacement to handle variable spacing.
- **Task name extraction:** Jinja2 expressions are now stripped from task names rather than skipping the entire name, so surrounding text is still spell/grammar checked

---

## 2.4.2

### Added

- **Progress status:** Real-time progress reporting on stderr during check execution
  - Check-level: `[3/11] Spell Check...` printed before each check starts
  - Parallel lint checks show each tool as it completes with elapsed time
  - Auto-enabled on interactive terminals (TTY), automatically disabled in CI/piped output
  - Thread-safe `StatusLine` class for use during parallel lint checks
- `--progress` flag: force progress status display on (even in non-TTY environments)
- `--no-progress` flag: disable progress status (even on TTY)

---

## 2.4.1

### Fixed

- **Grammar check:** Skip "Multiple consecutive spaces" detection in comment text (after `#`) — double spacing in comments is intentional formatting
- **Grammar check:** Skip "Multiple consecutive spaces" detection in AIDE-related content where double spacing is expected
- **Grammar check:** Skip `aide.conf.j2` entirely from grammar checking — AIDE config syntax triggers false positives (e.g. repeated words like `selinux selinux`)

---

## 2.4.0

### Fixed

- **Module naming:** Renamed `Ansible-Lockdown_QA_Repo_Check.py` to `Ansible_Lockdown_QA_Repo_Check.py` (hyphen to underscore) to fix `ModuleNotFoundError` when installed as a package via pip or pre-commit
- **Baseline delta display:** `BaselineManager.delta()` now recalculates check status (PASS/FAIL/WARN) from remaining findings instead of preserving the original status, fixing misleading `FAIL (0 new issue(s))` output in console and reports
- **README:** Updated pre-commit integration `rev:` references from `v2.3.0` to `v2.4.1`

### Changed

- Simplified exit code logic in `main()` — removed baseline-specific workaround now that `delta()` returns correct statuses
- Removed stale `[tool.pytest.ini_options]` section from `pyproject.toml` (referenced non-existent `tests/` directory)

---

## 2.3.0

### Added

- **pre-commit hook support:** Added `.pre-commit-hooks.yaml` with an `ansible-lockdown-qa` hook entry, allowing consumers to run QA checks automatically on every commit via [pre-commit](https://pre-commit.com/)
- README: new "pre-commit Integration" section with consumer usage snippets, argument overrides, `additional_dependencies` for linters, and local testing instructions

### Fixed

- **pyproject.toml:** Changed `license = "MIT"` (PEP 639 string) to `license = {text = "MIT"}` (PEP 621 table) and removed `License :: OSI Approved :: MIT License` classifier to fix build failures with newer setuptools

---

## 2.2.1

### Fixed

- **Ansible Lint integration:** Changed `-f parsable` to `-f pep8` (parsable is not a valid ansible-lint format option)
- **Ansible Lint parser:** Rewrote output regex to match modern ansible-lint pep8 format (`file:line:col: rule: message`) instead of legacy `[rule]` bracket format
- **Ansible Lint parser:** Added `--nocolor` flag and ANSI escape code stripping to prevent color codes from breaking output parsing
- **FQCN auto-fixer:** Fixed regex to handle both `module:` and `- module:` list-item syntax (previously silently failed on unnamed tasks)
- **Unused variables reverse check:** Added guard for empty benchmark prefix to prevent false positives matching all underscore-prefixed identifiers

### Changed

- Consolidated `import collections` and `from collections import defaultdict` into a single `from collections import Counter, defaultdict` import
- Added missing Ansible task keywords (`action`, `local_action`, `debugger`) to `TASK_KEYWORDS` set to prevent false positives in FQCN checking
- Updated README to reflect `ansible-lint -f pep8` format flag

---

## 2.2.0

### Added

- `--only` flag: run only the specified checks, skipping all others (inverse of `--skip`)
- `--dry-run` flag: preview auto-fix changes without modifying any files
- `--help` / `-h` flag documented in README (built in via argparse)
- PyYAML fallback: config parser uses `yaml.safe_load` when PyYAML is installed, falls back to built-in parser otherwise
- Thread-safe file cache: `read_lines()` and `collect_files()` now use `threading.Lock` to prevent race conditions during parallel checks
- `SPELL_EXCEPTIONS` populated with common Ansible domain terms (nftables, tmpfiles, logrotate, systemctl, chrony, sshd, grub, auditd, rsyslog, journald, coredump, sudo, polkit, fstab, sysctl, modprobe)
- Directory validation: `-d` flag now exits with a clear error if the path is not a valid directory
- `pyproject.toml`: packaging metadata, `[project.scripts]` entry point (`ansible-lockdown-qa`), optional `[lint]` and `[dev]` dependency groups, ruff and pytest configuration
- README: new "Development" section with project structure, running tests, linting, and package installation instructions
- README: new "Running Specific Checks" and "Dry-run preview" subsections
- README: `--help` documented in CLI Reference table and "Built-in Help" subsection

### Changed

- `concurrent.futures` and `threading` imports moved to top-level (were deferred inside method)
- Renamed `esc()` to `_html_escape()` to avoid generic global name collision
- `CompanyNamingCheck` exclude list now uses `os.path.basename(__file__)` instead of hardcoded script filename
- Baseline mode exit codes now recalculate status from remaining findings rather than using original check status (fixes false exit code 2 when all FAIL findings were in the baseline)
- `.gitignore` trimmed from 208 lines (GitHub default Python template) to 39 project-relevant entries

### Removed

- Duplicate documentation file `Ansible-Lockdown_QA_Repo_Check.md` (was identical to `README.md`)

---

## 2.1.0 - Initial public release

### Features

- 11 independent QA checks: YAML Lint, Ansible Lint, Spell Check, Grammar Check, Unused Variables, Variable Naming, File Mode Quoting, Company Naming, Audit Template, FQCN Usage, Rule Coverage
- Report generation in Markdown, HTML, and JSON formats
- Auto-fix mode for spelling, file mode quoting, and FQCN issues
- Baseline/delta mode for incremental QA in CI pipelines
- Per-repo configuration via `.qa_config.yml` / `.qa_config.yaml` / `.qa_config.json`
- Auto-detection of benchmark variable prefix
- Parallel execution of subprocess-based checks (yamllint, ansible-lint)
- Colored console output with per-check timing
- `--strict` mode for CI gate enforcement
- Zero external Python dependencies
