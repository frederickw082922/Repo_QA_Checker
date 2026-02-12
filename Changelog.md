# Changelog

All notable changes to the Ansible-Lockdown QA Repository Check Tool are documented in this file.

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
