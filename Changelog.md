# Changelog

All notable changes to the Ansible-Lockdown QA Repository Check Tool are documented in this file.

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
