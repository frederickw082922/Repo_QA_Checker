# QA Tool 3.0.0 Roadmap

Planned improvements for the Ansible-Lockdown QA Repository Check Tool, based on
analysis of companion scripts, real-world QA reports, and recurring patterns across
Ansible-Lockdown repos.

---

## High Priority — New Checks & Capabilities

### 1. Template Header Check (New Check #12)

**Status:** Not in tool — currently handled by standalone `check_template_headers.py`

Add a new `TemplateHeaderCheck` that verifies all `.j2` template files start with
the `{{ file_managed_by_ansible }}` header.

- Detect missing headers on all `.j2` files in `templates/`
- Smart exclusion list for files that should NOT have headers:
  - Banner files: `issue.j2`, `issue.net.j2`, `motd.j2`
  - YAML audit templates: `*_goss_*.yml.j2`, `*_audit_*.yml.j2` (require `---` on line 1)
  - System config files: `sshd_config.j2`
- Configurable exclusion patterns via `.qa_config.yml`:

  ```yaml
  template_header_excludes:
    - "issue.j2"
    - "issue.net.j2"
    - "motd.j2"
    - "*_goss_*.yml.j2"
  ```

- Auto-fix with `--fix`: prepend `{{ file_managed_by_ansible }}` + blank line
- Severity: `warning`

**Goal:** Eliminate the need to run `check_template_headers.py` separately.

---

### 2. Grammar Auto-Fix

**Status:** Detection exists (`GrammarCheck`), but `AutoFixer` does not fix grammar
issues — currently handled by standalone `fix_grammar.py`

Extend the `AutoFixer` class to support grammar corrections:

- Add `"grammar"` to `FIXABLE_CHECKS`
- Fix repeated words: `of of` -> `of`
- Fix missing apostrophes: `wont` -> `won't`, `cant` -> `can't`, etc.
- Fix subject-verb disagreement: `variables is` -> `variables are`
- Case-preserving replacements (same approach as spelling fixes)
- Dry-run preview support (already built into AutoFixer infrastructure)

**Goal:** Eliminate the need to run `fix_grammar.py` separately.

---

### 3. Lint Config Validation (New Check #13)

**Status:** Not in tool — called out in `prompt.md` as a common manual fix

Add a `LintConfigCheck` that validates `.ansible-lint` and `.yamllint` configuration files:

- **`.ansible-lint`:**
  - Flag deprecated options: `verbosity`, `parseable`
  - Warn if `use_default_rules` is missing
  - Validate `skip_list` entries are recognized rule names
- **`.yamllint`:**
  - Verify `comments-indentation: disable` is set (ansible-lint compatibility)
  - Verify `octal-values.forbid-implicit-octal: true` (Ansible best practice)
  - Warn if `line-length` is not disabled (common false positive source)
- Auto-fix deprecated options with `--fix`
- Severity: `warning` for deprecated options, `info` for recommendations
- Configurable via `.qa_config.yml`:

  ```yaml
  lint_config_check: true  # enable/disable
  ```

---

## Medium Priority — Improvements to Existing Checks

### 4. Flexible Audit Template Patterns

**Status:** Hardcoded to `templates/ansible_vars_goss.yml.j2`

Make the `AuditTemplateCheck` support multiple template patterns:

- Configurable via `.qa_config.yml`:

  ```yaml
  audit_template_patterns:
    - "*_goss_*.yml.j2"
    - "*_audit_*.yml.j2"
  ```

- Default: current behavior (`ansible_vars_goss.yml.j2`)
- Scan all matching files in `templates/` for duplicate keys

---

### 5. Smarter Reverse Variable Check (Reduce False Positives)

**Status:** RHEL8-STIG report shows 19 "referenced but not defined" warnings, most
from audit templates where vars are set by the audit role, not the hardening role

Reduce noise from the `UnusedVarCheck` reverse check:

- Add config option to exclude paths from the reverse check:

  ```yaml
  reverse_check_exclude_paths:
    - "templates/"
  ```

- Auto-detect variables that ONLY appear in audit templates and downgrade from `warning` to `info`
- Recognize common audit-role-provided variables (e.g., `*_os_distribution`, `*_bootloader_path`)
- Consider checking `vars/audit.yml` as a secondary definition source for template variables

---

### 6. Configurable Subprocess Timeouts

**Status:** Hardcoded — `yamllint` at 120s, `ansible-lint` at 300s

Add config support:

```yaml
yamllint_timeout: 120
ansible_lint_timeout: 300
```

Large repos or slow CI environments may need higher values.

---

### 7. Configurable Report Limits

**Status:** Hardcoded — 200 findings per check in reports, 20 in console

Add config support:

```yaml
max_findings_report: 200
max_findings_console: 20
```

---

## Lower Priority — Polish & Completeness

### 8. Broader File Type Coverage for Grammar/Spell

**Status:** Currently checks `.yml`, `.yaml`, `.j2`, `.md` — the standalone
`fix_grammar.py` also covers `.conf`, `.cfg`, `.rst`

Extend `SpellCheck` and `GrammarCheck` to also scan:

- `.rst` — catches `CONTRIBUTING.rst` (present in every repo)
- `.cfg` — catches configuration templates
- Configurable via `.qa_config.yml`:

  ```yaml
  grammar_file_extensions:
    - ".yml"
    - ".yaml"
    - ".j2"
    - ".md"
    - ".rst"
  ```

---

### 9. Register Naming Auto-Fix

**Status:** Detection exists (`VarNamingCheck`), no auto-fix

Add auto-fix for non-standard register variable names:

- Suggest the correct prefix based on task context (e.g., `rhel8_efi_boot` -> `discovered_rhel8_efi_boot`)
- Apply with `--fix` flag
- Requires updating all references to the renamed variable in the same file
- Higher risk than other auto-fixes — may need `--dry-run` review

---

### 10. Duplicate Register Wider Search Window

**Status:** When-condition deduplication searches 40 lines backward, 20 lines
forward — may miss conditions in larger task blocks

- Make the search window configurable or adaptive based on task block size
- Consider parsing full task blocks instead of fixed-line windows
- Handle the case of 3+ duplicates in the same file (e.g., `discovered_audit_log_dir`
  appearing 3 times in RHEL8-STIG)

---

### 11. Pre-commit Auto-Fix Hook

**Status:** Planned in `plan.md` Phase 7 but not implemented

Add a second entry in `.pre-commit-hooks.yaml`:

```yaml
- id: ansible-lockdown-qa-fix
  name: Ansible Lockdown QA Auto-Fix
  entry: ansible-lockdown-qa
  args: ['-d', '.', '--fix', '--no-report']
  language: python
  pass_filenames: false
  always_run: true
```

---

## Modular File Structure

### Why

The script is currently a single ~2000-line file (`Ansible_Lockdown_QA_Repo_Check.py`).
Adding 2-3 new checks, grammar auto-fix, and template header fixes will push it past
2500+ lines. A modular layout makes each check independently readable, testable, and
maintainable.

### Proposed Package Layout

```text
ansible_lockdown_qa/
├── __init__.py              # Package version, public API
├── __main__.py              # Entry point: python -m ansible_lockdown_qa
├── cli.py                   # Argument parsing, main() function
├── config.py                # ConfigLoader, defaults, .qa_config.yml parsing
├── constants.py             # MISSPELLING_DICT, GRAMMAR_PATTERNS, ANSIBLE_BUILTIN_MODULES,
│                            #   TASK_KEYWORDS, SPELL_EXCEPTIONS, SEVERITY_LEVELS, ANSI codes
├── models.py                # Finding, CheckResult, ReportMetadata dataclasses
├── scanner.py               # RepoScanner class (file cache, collect_files, read_lines,
│                            #   run_all_checks, _run_parallel_checks, StatusLine)
├── checks/
│   ├── __init__.py          # Exports all check classes for discovery
│   ├── yamllint.py          # YamlLintCheck
│   ├── ansiblelint.py       # AnsibleLintCheck
│   ├── spelling.py          # SpellCheck
│   ├── grammar.py           # GrammarCheck
│   ├── unused_vars.py       # UnusedVarCheck
│   ├── var_naming.py        # VarNamingCheck
│   ├── file_mode.py         # FileModeCheck
│   ├── company_naming.py    # CompanyNamingCheck
│   ├── audit_template.py    # AuditTemplateCheck
│   ├── fqcn.py              # FQCNCheck
│   ├── rule_coverage.py     # RuleCoverageCheck
│   ├── template_header.py   # TemplateHeaderCheck (NEW - item #1)
│   └── lint_config.py       # LintConfigCheck (NEW - item #3)
├── fixers/
│   ├── __init__.py          # AutoFixer base, fix dispatch
│   ├── spelling.py          # _fix_spelling
│   ├── grammar.py           # _fix_grammar (NEW - item #2)
│   ├── file_mode.py         # _fix_file_mode
│   ├── fqcn.py              # _fix_fqcn
│   └── template_header.py   # _fix_template_header (NEW - item #1)
├── reports/
│   ├── __init__.py          # ReportGenerator dispatch
│   ├── markdown.py          # Markdown report generation
│   ├── html.py              # HTML report generation
│   ├── json_report.py       # JSON report generation
│   └── console.py           # ConsoleOutput (colored terminal output)
└── baseline.py              # BaselineManager (save/load/delta)
```

### Migration Strategy

1. **Keep the single-file version working** throughout the migration. Do not break
   existing users or pre-commit hooks.
2. **Move one module at a time**, starting with the easiest extractions:
   - `constants.py` — pure data, no dependencies
   - `models.py` — dataclasses only
   - `config.py` — self-contained loader
   - `reports/` — output-only, no check logic
   - `baseline.py` — self-contained save/load
3. **Extract checks into `checks/`** one at a time. Each check class already has a
   clean boundary (`__init__(self, scanner)` + `run() -> CheckResult`).
4. **Extract fixers into `fixers/`** — each fix method becomes its own file.
5. **Update `scanner.py`** to import checks from the `checks/` package. The check
   registry in `run_all_checks()` becomes a simple import list.
6. **Update `pyproject.toml`** entry point:

   ```toml
   [project.scripts]
   ansible-lockdown-qa = "ansible_lockdown_qa.cli:main"
   ```

7. **Update `.pre-commit-hooks.yaml`** entry to match the new package name.

### What Each File Contains (Line Count Estimates)

| File | Current Source Lines | Contents |
| ---- | ---- | ---- |
| `constants.py` | ~200 | All dicts, sets, compiled regexes |
| `models.py` | ~30 | 3 dataclasses |
| `config.py` | ~80 | ConfigLoader class |
| `scanner.py` | ~150 | RepoScanner + StatusLine |
| `cli.py` | ~120 | argparse + main() |
| `checks/*.py` | ~50-150 each | One class per file |
| `fixers/*.py` | ~20-40 each | One fix method per file |
| `reports/*.py` | ~50-100 each | One format per file |
| `baseline.py` | ~60 | BaselineManager |

No single file exceeds ~200 lines. Each can be read, understood, and tested in isolation.

### Backward Compatibility

- The old single-file script can remain as a thin wrapper that imports from the package,
  or be removed once all consumers migrate to `pip install` / pre-commit hook usage.
- The CLI interface (`--flags`, exit codes, report formats) stays identical.
- The `.qa_config.yml` format stays identical.

---

## Summary

| # | Feature | Type | Priority | Eliminates Script |
| --- | --- | --- | --- | --- |
| 1 | Template Header Check | New check + auto-fix | High | `check_template_headers.py` |
| 2 | Grammar Auto-Fix | Extend AutoFixer | High | `fix_grammar.py` |
| 3 | Lint Config Validation | New check | High | Manual `.ansible-lint` fixes |
| 4 | Flexible Audit Templates | Enhance existing | Medium | `check_audit_keys.py` patterns |
| 5 | Smarter Reverse Var Check | Reduce false positives | Medium | -- |
| 6 | Configurable Timeouts | Config option | Medium | -- |
| 7 | Configurable Report Limits | Config option | Medium | -- |
| 8 | Broader File Extensions | Enhance existing | Low | -- |
| 9 | Register Naming Auto-Fix | Extend AutoFixer | Low | -- |
| 10 | Wider Duplicate Search | Enhance existing | Low | -- |
| 11 | Pre-commit Fix Hook | New hook entry | Low | -- |
| 12 | Modular File Structure | Refactor | High | -- |

**Target:** Completing items 1-3 and 12 would consolidate all standalone scripts
into one tool, break the single file into manageable modules, and justify a 3.0.0
version bump.
