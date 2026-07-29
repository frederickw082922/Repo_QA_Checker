# Changelog

All notable changes to the Ansible-Lockdown QA Repository Check Tool are documented in this file.

---

## 2.8.1 - 2026-07-01

### Added

- **`check_audit_vars.py`:** Standalone check script (stdlib only) that validates audit variable placement across Lockdown remediation roles. Enforces the canonical split from Private-RHEL10-CIS: user-overridable toggles (`setup_audit`, `run_audit`, `audit_only`, `fetch_audit_output`, `audit_output_collection_method`, `audit_output_destination`, `audit_run_heavy_tests`) belong in `defaults/main.yml`; role-internal constants (`audit_cmd_timeout`, `audit_bin_*`, `pre_audit_outfile`, etc.) belong in `vars/audit.yml`. Reports misplaced vars, duplicate definitions (vars wins over defaults), molecule override collisions, missing canonical keys, and legacy bridge templates. Supports single-role scans and `--all` / `--compact` batch mode under CIS/ or STIG/ roots. Added to `run_all_checks.sh`.
- **QA Repo Check: Audit Variable Placement (`audit_vars`):** New check in `Ansible_Lockdown_QA_Repo_Check.py` that delegates to `check_audit_vars.py` and surfaces findings in the main QA report (Markdown/HTML/JSON/console). Skip with `--skip audit_vars`; run alone with `--only audit_vars`.
- **`check_shell_pipefail.py`:** Read-only checker (stdlib only) for `ansible.builtin.shell` layout: `set -o pipefail` as first block line plus `args: executable: "{{ <prefix>_shell_executable }}"`. Reuses `fix_shell_pipefail.scan_file` so rules match the fix script. Auto-detects `*_shell_executable` from role vars. Supports `--all` / `--compact` batch mode. Wired in `run_all_checks.sh` and `Ansible_Lockdown_QA_Repo_Check.py` (`--skip shell_pipefail` / `--only shell_pipefail`).
- **QA Repo Check: Shell Pipefail Layout (`shell_pipefail`):** New check in `Ansible_Lockdown_QA_Repo_Check.py` that delegates to `check_shell_pipefail.py` and surfaces findings in the main QA report (Markdown/HTML/JSON/console).

### Changed

- **Audit Variable Placement is now advisory (warnings only):** every finding from this check is reported as a warning, so it can only ever be PASS or WARN, never FAIL. Variable placement (user-overridable toggles in `defaults/main.yml` vs role-internal constants in `vars/audit.yml`) is guidance rather than a hard gate. In `check_audit_vars.py` the four `error`-severity findings (CHECK A overridable-var-in-`vars/audit.yml`, CHECK C molecule-override-ignored, duplicate-definition, and the `defaults/main.yml` not-found structural check) are downgraded to `warning`, so the standalone CLI and `--all` batch mode now exit 0 on placement findings. In the main report, `AuditVarsCheck` surfaces every finding as a warning and derives WARN/PASS directly, so the check stays advisory even if source severities drift.

### Fixed

- **`fix_shell_pipefail.py` folded-scalar pipefail bug:** A folded (`>`) block scalar was treated as a valid host for `set -o pipefail`. Under `>` the newline after pipefail folds to a space, so the inserted `set -o pipefail` ran with the following command as positional arguments to the `set` builtin and never applied, silently emptying the task's `stdout` (this regressed a RHEL8 prelim interactive-user detector). A `>` indicator no longer counts as a valid block indicator: the shell line is rewritten to literal `|` when the task needs pipefail, gated to single-physical-line bodies (safe, since `|` preserves the line as-is). A multi-line folded body is left untouched with a new `folded_multiline` WARN, because auto-converting it to `|` would reinterpret space-joined continuation lines as separate commands. Verified on synthetic cases and via dry-run across the CIS fleet (23 folded scalars: single-line ones convert cleanly, the one genuine multi-line folded scalar warns instead of breaking).
- **QA report artifact exclusion:** Spell, grammar, and company-naming checks no longer scan prior `qa_report_*` or `AL_QA_Report_*` files left in role directories. All existing report artifacts in the role root are auto-added to `exclude_paths` at scan start (not only the current run's output file). `fix_grammar.py` and `fix_spelling.py` apply the same skip pattern.
- **`fix_shell_pipefail.py` Case D:** Shell tasks that put the command under `args.cmd` (with `ansible.builtin.shell:` and no block body) are migrated into the shell block after `set -o pipefail` instead of leaving an empty block. Fixes the broken layout produced when pipefail was inserted ahead of an `args:`/`cmd:` task.
- **`fix_shell_pipefail.py` Case D `--dry-run` crash:** Preview no longer raises `KeyError: 'inline_cmd'` on a Case D task. The dry-run summary keyed the inline-command preview off `type != "A"`, which caught Case D (a `type == "D"` fix that has no `inline_cmd`); it now keys off `type == "B"` so Case D reports "insert pipefail".
- **`fix_shell_pipefail.py` Case D apply corruption:** Applying a Case D fix no longer leaves the original `cmd:`/`executable:` lines stranded inside the shell block or duplicates the command. The migration used scan-time line indices that went stale once `set -o pipefail` was inserted, so `del` removed the wrong line. Case D is now rebuilt atomically (`_apply_case_d`): the shell block, `set -o pipefail`, the migrated command, and a preserved/added `args: executable:` are spliced in one pass. Verified idempotent and yamllint-clean.
- **`check_shell_pipefail.py` double report:** A Case D task no longer emits two findings on the same line (one from `scan_file`, one from the args.cmd sweep). The args.cmd sweep now skips shell lines already reported by `scan_file`.
- **Audit Template check:** `AuditTemplateCheck` now scans both `templates/lockdown_audit.yml.j2` (canonical) and `templates/ansible_vars_goss.yml.j2` (legacy). Previously only looked for the legacy filename, so migrated roles were incorrectly reported as SKIP.
- **`check_audit_vars.py` CHECK E severity:** Presence of the legacy `ansible_vars_goss.yml.j2` bridge template is now a warning, not an error. The `lockdown_audit.yml.j2` rename is not yet a fleet-wide convention, so an error failed nearly every role in the shared QA suite.
- **`check_audit_vars.py` CHECK C `set_fact` awareness:** Molecule audit-var overrides written via `set_fact` are no longer flagged as ineffective. `set_fact` (precedence 19) does override the `include_vars` (precedence 18) that loads `vars/audit.yml`; only lower-precedence play/host `vars:` assignments are now reported.
- **Cross-Repo Validator: bridge-template resolution:** `template_path` now resolves from a candidate list (prefers `templates/lockdown_audit.yml.j2`, falls back to `templates/ansible_vars_goss.yml.j2`) instead of hardcoding the legacy name. Roles that adopted the New Alignment Strategy rename previously read zero template keys (`tmpl_keys:0`) and produced false `Template-Goss Var Cross-Ref` FAILs and `Rule Toggle Sync` WARNs. Verified: Private-UBUNTU24-STIG (renamed) reads `tmpl_keys:254`, Private-UBUNTU22-STIG (legacy) still resolves via fallback at `tmpl_keys:218`.
- **QA Repo Check: report descriptions:** Added `CHECK_DESCRIPTIONS` entries for `Meta Validate`, `Audit Variable Placement`, and `Shell Pipefail Layout`, which previously rendered a blank description column and blank "Why these findings?" text in the generated report.
- **README check table:** Now lists all 15 registered checks (previously stated 11 and omitted `meta_validate`, `manual_warn`, `audit_vars`, and `shell_pipefail`).
- **Version alignment:** Bumped the bundled sub-tool versions (`scripts/audit_compare/audit_compare.py`, `scripts/cross_repo_validator/cross_repo_validator.py`, and the cross-repo validator README) and the `pyproject.toml` package version to 2.8.1 so the whole repository moves in lockstep.
- **QA Repo Check: `--only` check name list:** Added missing keys `meta_validate`, `manual_warn`, and `audit_vars` so `--only` / `--skip` behave consistently with the full check suite.
- **QA Repo Check: dynamic import of `check_audit_vars.py`:** Register the loaded module in `sys.modules` before `exec_module()` so dataclass processing works on Python 3.14+ when the checker is imported from the main QA script.
- **Audit Template check: YAML list-item false positives:** `AuditTemplateCheck._scan_template` and `scripts/check_audit_keys.py` now track YAML sequence-item boundaries, so the same key in two sibling list elements is no longer reported as a duplicate. Each `- ` marker opens an item scope keyed by its indentation and is folded into the duplicate-lookup alongside the existing conditional scope. Previously a `gpg_key:` list of `- name:/fingerprint:` entries (e.g. RHEL9-STIG `lockdown_audit.yml.j2`, two release keys per distro) produced spurious `Duplicate audit key 'fingerprint'` findings. Genuine duplicate keys within the same mapping and scope are still caught.
- **Audit Variable Placement CHECK C: canonical-var false positive:** CHECK C (molecule cannot override `vars/audit.yml` entries) no longer flags variables in the canonical `VARS_AUDIT_VARS` set (e.g. `audit_git_version`). Those role-internal constants are supposed to live in `vars/audit.yml` - the fleet-wide CIS/STIG convention (verified: 18/18 sibling roles declare `audit_git_version` there, none in `defaults/main.yml`) - so a molecule host/play-var reference to them is not a placement defect, and the correct override is `--extra-vars` or `set_fact` (both outrank `include_vars`). Only non-canonical keys parked in `vars/audit.yml` and referenced by molecule are still reported. This clears the last standing finding on convention-following roles.
- **Manual Warn Count check: cache-aliasing false positive:** `RepoScanner.collect_files` now returns a fresh list copy on every call (both cache-hit and cache-miss paths). The Unused Variables check appended `handlers/main.yml` to the list `collect_files` returned, which mutated the shared cache entry for `tasks/` in place; the later Manual Warn Count check then read the poisoned list, scanned `handlers/main.yml`, and mis-flagged a correctly-scoped `vars: warn_control_id` (e.g. the RHEL9-STIG AIDE handler) as misplaced. The result now depends only on the check's own inputs, not on check ordering.

---

## 2.8.0 - 2026-05-26

### Added

- **`fix_shell_pipefail.py`:** New fix script that finds and auto-remediates `ansible.builtin.shell` tasks missing `set -o pipefail` or `args: executable:`. Handles three cases: (A) block format missing pipefail, (B) inline format converted to block with pipefail and args inserted, (C) block format with pipefail but missing args. Preserves trailing `# noqa` comments on inline-to-block conversions. Supports `--dry-run`, `--exec-var` (default: `default_shell_executable`), and `--no-ansible-check` flags. Added to `run_all_checks.sh`.
- **Cross-Repo Validator:** New helper `extract_runtime_defined_vars(tasks_dir)` walks every `*.yml` under `tasks/` to harvest `register:` targets and `set_fact:` block keys. Used by Check 15 (and available to other checks).

### Fixed

- **`check_var_naming.py`: Orphaned template false positives:** Forward and reverse variable coverage checks now skip templates not referenced by any `src:` in task files. The new `collect_deployed_templates()` function walks `tasks/` for `src: *.j2` references and builds a deployed set; templates absent from that set are excluded from both forward (defined-but-unused) and reverse (used-but-undefined) scanning. Eliminates false positives caused by stale draft templates or templates replaced by inline `copy: content:`.
- **Cross-Repo Validator: Config Variable Parity (Check 8):** Eliminated false positives caused by static comparison of values where one side is a Jinja2 expression (e.g. `{{ list | join(",") }}` in defaults vs the resolved literal in audit vars). The check now skips equality when either side contains `{{ ... }}` markers. Also relaxed inline-comment stripping in `_strip_yaml_value` to require only single whitespace before `#` (per the YAML spec), so values like `sha512 # pragma: allowlist secret` compare equal to plain `sha512`.
- **Cross-Repo Validator: Template-Goss Var Cross-Ref (Check 15):** Added support for runtime-set variables. The check now treats variables defined via `register:` or inside `set_fact:` blocks anywhere under `tasks/` as valid Jinja2 reference sources, alongside `defaults/main.yml`, `vars/audit.yml`, and Ansible builtins. The well-known runtime set (`system_is_container`, `os_release`, etc.) injected by `run_audit.sh` is also merged into the valid-sources set. Closes false positives on roles whose templates reference vars set during play execution.
- **`run_all_checks.sh`:** Per-script pass/warn scoring now uses the script's actual exit code instead of regex-grepping the captured output. The previous regex (`: 0$`) misfired on tails like `Missing from all code: 0`, marking scripts with real warnings as PASS. Each `check_*.py` already exits `0` clean / `1` on issues, so this is a clean swap.
- **`check_tags_completeness.py`:** Added a file-basename allowlist (`ORCHESTRATION_FILES`) covering Lockdown-convention play-wiring files — `main.yml`, `LE_audit_setup.yml`, `audit_only.yml`, `auditd.yml`, `check_prereqs.yml`, `fetch_audit_output.yml`, `parse_etc_password.yml`, `pre_remediation_audit.yml`, `post_remediation_audit.yml`, `prelim.yml`, `warning_facts.yml`. Tasks in these files skip the `no_tags` and `missing_rule_id` checks since they use `include_tasks`/`import_tasks` and inherit tags from the imported files. The existing name-pattern heuristics (`is_section_include` / `is_infra_task`) only caught a subset of phrasings; the file allowlist closes the gap so phrasings like "Run Cat 2 STIG 21xxxx tasks" or "Audit_Only | Create local Directories" no longer false-positive.
- **Manual Warn Count check (`Ansible_Lockdown_QA_Repo_Check.py` `ManualWarnCountCheck`):** Made the `block_level_warn_vars` detection context-aware. Previously fired on any `vars: warn_control_id` at task scope regardless of surrounding structure, false-positiving on the legit Lockdown DRY pattern (one `vars:` declaration at parent task scope paired with a `block:` whose children import `warning_facts.yml`). Now suppresses when the parent task contains both a sibling `block:` AND a `warning_facts.yml` reference within that block scope. On UB22 V2R7 this dropped 28 findings to 1 — and the surviving finding (`tasks/Cat2/UBTU-22-291xxx.yml:33`, `UBTU-22-291015`) is a real bug previously hidden in the FP catalogue: `warn_control_id` declared but no `warning_facts.yml` import anywhere in the file.
- **`fix_warn_count.py`:** Mirrored the context-aware check into the standalone fix script. `scan_block_level_vars` now skips the legit parent-vars+block pattern. Additionally hardened `fix_block_level_vars` with a safety guard: when no `warning_facts.yml` target exists in scope (i.e. the genuine "missing Warn Count" case), the function refuses to delete the orphan `vars:` block — previously it would silently delete with no replacement insert, hiding the missing-Warn-Count signal. Returns `(fixed_count, skipped_list)` so the caller can report `SKIPPED:` items with a "needs human decision" message instead of treating them as fixed.
- **`dependency_graph.py`:** Reference scanner skipped any line whose stripped content started with `#`, treating it as a YAML comment. This misclassified literal `#`-prefixed lines inside YAML block scalars (e.g. `file_managed_by_ansible: |-` whose body contains `# Provided by {{ company_title }}`) as comments, causing variables referenced only in such block-scalar bodies to be reported as orphans. Now keeps the line when it contains a Jinja2 expression (`{{ ... }}`) — template content overrides the comment heuristic. On UB22 V2R7 this cleared the lone remaining `company_title` orphan FP, bringing dep-graph orphans to zero.

---

## 2.7.0 - 2026-03-31

### Added

- **FIX Scripts:** Added suite of standalone fix scripts for common QA findings — `fix_changed_when.py`, `fix_company_naming.py`, `fix_file_modes.py`, `fix_fqcn.py`, `fix_handler_refs.py`, `fix_ignore_errors.py`, `fix_loop_control.py`, `fix_no_log.py`, `fix_spelling.py`, `fix_when_inline.py`, `check_rule_coverage.py`, `check_tags_completeness.py`, `check_var_naming.py` — with dedicated FIX Scripts README
- **`check_file_modes.py`:** Comprehensive file mode notation checker that detects octal, absolute symbolic (`=`), and mixed notation patterns. Converts all to relative symbolic (`-`/`+`) notation per Lockdown conventions. Supports `--fix` for auto-remediation and `--tasks-only` to limit scan scope. Includes Jinja2 conditional mode handling.
- **`run_all_checks.sh`:** Bash runner that executes all check and fix scripts in one pass against any Ansible Lockdown role (CIS or STIG). Flags: `--fix` (apply all fixes), `--checks` (read-only analysis only), `--dry-run` (fix preview only). Includes repo structure validation, per-script pass/warn tracking, timing, and meaningful exit codes (0=clean, 1=warnings, 2=bad args).
- **QA Repo Check: Manual Warn Count check (`manual_warn`):** New check validates that every task containing `msg: "This control requires manual remediation"` is followed by a Warn Count block that imports `warning_facts.yml` with the correct `warn_control_id`. Without this block, manual-only controls are not tracked in the Ansible run warning summary.
- **Fix Script: `fix_warn_count.py`:** Standalone script to detect and auto-fix manual remediation tasks missing the Warn Count `warning_facts.yml` import block. Supports `--fix` for automatic remediation.
- **Cross-Repo Validator: Check 16 — Handler Notify Validation (`handler_notify`):** Parses `handlers/main.yml` for handler names (including `listen:` aliases) and scans all task files for `notify:` references. Detects undefined handlers (runtime errors), case mismatches (silently skipped handlers), and orphaned handlers (dead code).
- **Cross-Repo Validator: Check 17 — Prelim Variable Dependencies (`prelim_dependencies`):** Extracts all variables registered or set via `set_fact` in `tasks/prelim.yml` and validates that every `prelim_*` reference in section task files points to a defined variable. Catches refactoring misses where prelim tasks were renamed or removed but downstream references remain.
- **Cross-Repo Validator: Check 18 — Automation Status Tracking (`automation_status`):** Classifies each control as automated, manual, or partial by examining the Ansible modules used, then validates that automated controls have corresponding audit test files with at least one goss assertion. Reports automated vs manual counts for tracking automation progress.
- **Cross-Repo Validator: Check 19 — File Path Alignment (`file_path_alignment`):** Extracts literal file paths from remediation task modules (`path:`, `dest:`, shell/command strings) and goss audit test blocks (`file: path:`, `mount: mountpoint:`, `command:`/`exec:` strings), then compares per control. Detects remediation paths not tested by audit (silent false pass) and audit paths not in remediation (stale tests). Includes parent/child tolerance, same-directory tolerance, glob normalization, and Jinja2 path exclusion to minimize false positives. Works for both CIS and STIG benchmarks.

### Changed

- **Report consistency across tools:** Standardized report formatting and descriptions across QA Repo Check, Cross-Repo Validator, and Audit Compare for consistent look and feel

### Fixed

- **`fix_loop_control.py`: Block-level placement bug.** `loop_control:` was placed at the outer block indent instead of the inner task indent when loops were inside blocks, causing Ansible error `'loop_control' is not a valid attribute for a Block`. Now uses the loop keyword's own indent level. Also added duplicate guard (won't insert `loop_control:` if it already exists), blank line cleanup (removes consecutive blank lines after fix), and idempotency (re-running `--fix` is a no-op).
- **`fix_loop_control.py`: Blank line before loop_control.** The insert_idx scanner skipped blank lines between loop items and the next key, then inserted `loop_control:` after the blank line. Changed to track `last_content_idx` and insert immediately after the last loop item. Found 53 instances on UB24.
- **`fix_no_log.py`: Duplicate insertion bug.** Running `--fix` twice would insert duplicate `no_log: true` lines. Added guard that checks if `no_log:` already exists in the task block before inserting. Also added blank line cleanup and idempotency.
- **`fix_grammar.py`: False positives on changelogs.** Changelog files (`Changelog.md`, `CHANGELOG.md`) are now skipped entirely. Changelogs describe previous grammar fixes (e.g., "fixed repeated words: 'is is', 'of of'") which were falsely flagged as new grammar issues.
- **`fix_when_inline.py`: False positive on multi-line boolean expressions.** Single-item `when:` lists where the value ends with `or` or `and` (continuation of a multi-line condition) are now skipped. Previously flagged as convertible to inline format, which would break the expression.
- **`fix_handler_refs.py`: False positive on handler-to-handler notify chains.** Now scans both task files AND handler files for `notify:` references. Previously only checked tasks, so handlers notified by other handlers (e.g., `Grub update` notifying `Change requires reboot`) were incorrectly reported as unused.
- **`fix_ignore_errors.py`: False positive on `# noqa` suppressed lines.** Lines with `# noqa: ignore-errors` or any `# noqa` comment are now skipped. These are intentional ansible-lint suppressions, not violations.
- **`fix_no_log.py`: False positive on permission-only modules.** `ansible.builtin.file` and `ansible.builtin.stat` tasks touching sensitive paths (e.g., `/etc/shadow`) are no longer flagged. These modules set ownership/permissions only and do not read or expose file content.
- **`fix_grammar.py`: False positives on repeated words.** Improved detection to skip matches inside URLs, file paths, backtick-quoted content, and `=` assignments. Added verification that the repeated word actually exists in the original line.
- **`fix_no_log.py`: False positive on `/etc/passwd` tasks.** Tasks parsing `/etc/passwd` (world-readable, no password hashes) are no longer flagged. Also skips `set_fact` tasks that reformat data. Only tasks accessing actual shadow files are flagged.
- **QA Repo Check: Unused Variables false positives on `src:`/`dest:` paths.** The main `Ansible_Lockdown_QA_Repo_Check.py` now skips `src:`, `dest:`, `path:`, `creates:`, `removes:` lines during reverse variable scanning. Template filenames (e.g., `audit/ubtu20cis_6_3_3_1_scope.rules.j2`) were tokenized into prefix-matching strings and falsely flagged as undefined variables (~17 false positives on UBUNTU20-CIS).
- **QA Repo Check: Ansible Lint false positive on Python ResourceWarning.** Python `ResourceWarning` messages captured from stderr are no longer reported as ansible-lint findings.
- **Grammar Check: "Multiple consecutive spaces" false positives in task names:** Task names containing Jinja2 expressions (e.g. `"Check for {{ ansible_env.SUDO_USER }} | state"`) are stripped of `{{ ... }}` before grammar analysis. That often leaves two consecutive spaces (e.g. `for  |`), which was incorrectly reported as "Multiple consecutive spaces." The Grammar check now skips the "Multiple consecutive spaces" rule when the text is a task name, so these Jinja2-stripping artifacts are no longer flagged. Comments and Markdown continue to skip this rule as before.
- **Grammar Check: Changelog excluded:** The Grammar check no longer scans `Changelog.md` or `CHANGELOG.md`, so changelog formatting and historical wording are not reported as grammar findings.
- **Grammar Check: QA report output excluded:** The Grammar check no longer scans Markdown files whose basename matches `qa_report*.md`, avoiding self-report findings when the tool writes its report into the repo directory.
- **Grammar Check: Subject-verb disagreement ignored in task section files:** "Subject-verb disagreement" findings are no longer reported for files under `tasks/section*` or `tasks/cat*`, where CIS/STIG task names and comments often use shorthand that triggers false positives.
- **Audit Compare: Web UI filter issue:** Fixed filtering functionality in the Audit Compare HTML report web interface
- **Audit Compare: CodeQL polynomial regex fix:** Refactored regular expressions to eliminate polynomial backtracking flagged by CodeQL security scanning
- **Audit Compare: Bounded regex quantifiers:** Bounded all `\d+` to `\d{1,10}` and changed `([a-zA-Z]+)` to `([a-zA-Z]+?)` across every regex to prevent catastrophic backtracking
- **Cross-Repo Validator: Rule Key Consistency false positives for CIS bare `when:` list items:** Fixed `extract_task_data()` to correctly detect bare toggle lines in Ansible `when:` lists for CIS repos, eliminating false "Rule found in audit but no task" info findings
- **check_var_naming.py: Bridge template false positives:** Script now extracts output key names (left-hand side of `key: {{ value }}` lines) from `ansible_vars_goss.yml.j2` and excludes them from "referenced but not defined" errors. Previously all bridge template output vars were falsely flagged (29 false positives on UBUNTU20-CIS).
- **check_var_naming.py: set_fact false positives:** Variables created by `ansible.builtin.set_fact` tasks are now collected and excluded from "referenced but not defined" errors (e.g. `ubtu20cis_passwd` in `parse_etc_password.yml`).
- **check_var_naming.py: Handler register false positives:** Register variables in `handlers/` files are now collected alongside task registers, preventing false "referenced but not defined" errors for handler-specific vars.
- **check_var_naming.py: Template src/dest path false positives:** Lines matching `src:`, `dest:`, `path:`, `creates:`, or `removes:` in task files are now skipped during reverse variable scanning. Template filenames (e.g. `audit/ubtu20cis_6_3_3_1_scope.rules.j2`) were tokenized into prefix-matching strings and falsely flagged as undefined variables (17 false positives on UBUNTU20-CIS).
- **check_tags_completeness.py: Section include false positives:** Tasks matching section include patterns (`SECTION | X.Y`), infrastructure task patterns (`Import preliminary`, `flush handlers`, `Include section`, `Run post`, etc.), and audit setup/teardown patterns are no longer flagged for missing tags. These are `import_tasks` calls that inherit tags from imported files — tagging them is unnecessary and was generating noise.
- **check_tags_completeness.py: Block-format tags not detected:** Fixed a parsing bug where `tags:` on its own line (block format) was never detected because `tline.lstrip()` preserves trailing newlines — so `"tags:\n" == "tags:"` always failed. Only inline `tags: always` format was working. Added `.strip()` for exact string comparisons. This was causing ~300 false "no_tags" warnings on every repo.
- **check_tags_completeness.py: Block tag inheritance:** Sub-tasks inside a `block:` that has tags now inherit the parent block's tags and are no longer flagged for missing tags. The parser tracks block nesting via indent levels and marks child tasks as `in_tagged_block`. Combined with the block-format fix, this reduced UBUNTU20-CIS warnings from 349 to 43.
- **check_audit_keys.py: Jinja2 conditional branch false positives:** Keys inside `{% if %}` / `{% elif %}` / `{% else %}` / `{% endif %}` branches are no longer flagged as duplicates. Each branch gets a unique scope ID so the same key in different branches (e.g. `ubtu20cis_mailserver` in if/else) is correctly recognized as mutually exclusive. Previously caused 2 false positives on UBUNTU20-CIS.
- **check_tags_completeness.py: Infrastructure task rule ID false positives:** Tasks with `tags: always`, section include patterns (`Include section N`), and infrastructure orchestration patterns are no longer checked for missing rule ID tags. These are not tied to benchmark controls. Reduced UBUNTU20-CIS `missing_rule_id` from 20 to 1.
- **QA Repo Check: Audit Template conditional branch false positives:** Ported the Jinja2 `{% if %}`/`{% else %}`/`{% endif %}` conditional scope tracking from `check_audit_keys.py` into the main QA script's `AuditTemplateCheck`. Keys in mutually exclusive branches are no longer flagged as duplicates. Also added `{% for %}`/`{% endfor %}` loop tracking to skip expected repeats. Fixed 2 false positives on UBUNTU20-CIS.

---

## 2.6.0 - 2026-03-06

### Added

- **Cross-Repo Validator: Per-check section descriptions and criteria in reports:** Each check section in Markdown, HTML, and JSON reports now includes a short **description subtitle** summarizing what the check asks (e.g. *"Does every rule toggle have an audit test file?"*) and a detailed **"Why these findings?"** criteria block explaining the check logic and why findings appear.
  - Markdown: italic subtitle under each heading + `> **Why these findings?** ...` blockquote
  - HTML: italic subtitle in collapsible header + styled callout box with blue left border
  - JSON: `"description"` (short) and `"criteria"` (detailed) string fields per check object
- **QA Repo Check: Per-check section descriptions and criteria in reports:** Same description + criteria feature added to the main QA tool. All 11 checks now include an italic subtitle and detailed criteria text in Markdown, HTML, and JSON reports.
  - Markdown: italic subtitle under each heading + `> **Why these findings?** ...` blockquote
  - HTML: italic subtitle in collapsible header + styled callout box with blue left border
  - JSON: `"description"` and `"criteria"` string fields added to each check object
- **QA Repo Check: Collapsible HTML sections:** HTML report check sections are now collapsible (click-to-toggle), matching the cross-repo validator. PASS checks with no findings start collapsed, toggle arrows rotate on collapse, and hover highlights the header row.
- **Overview tables with description column:** Both the QA Repo Check and Cross-Repo Validator summary/overview tables now include a Description column showing the short one-liner for each check.
- **Audit Compare: Section descriptions in reports:** Each report section (Summary, Changes Breakdown, Fixed Controls, Regressed Controls, Still Failed Controls) now includes an italic description explaining the section's purpose.
  - Markdown: italic description under section headings + `>` blockquote for detail sections
  - HTML: color-coded callout boxes (green for Fixed, red for Regressed, amber for Still Failed)
  - JSON: `"section_descriptions"` dictionary added to the report object
- **Report footers across all tools:** All three tools (QA Repo Check, Cross-Repo Validator, Audit Compare) now include a `*Generated by <tool> v<version> for <name> on <date>*` footer in both Markdown and HTML reports. Audit Compare JSON metadata now includes `"tool_version"`.
- **Print-friendly CSS across all tools:** All three HTML report templates now include `@media print` rules that remove shadows, expand collapsed sections, and use a white background for clean printing.
- **Standardized badge color scheme:** Cross-Repo Validator HTML badges updated from solid-color (white text on colored background) to pastel style (dark text on light background) matching the QA tool and Audit Compare. Severity text colors also aligned across all tools.
- **QA Repo Check: CSS variables:** HTML template migrated from hardcoded hex colors to CSS custom properties (`:root` block with `--bg`, `--card`, `--border`, `--text`, `--text-light`, `--primary`), matching the Cross-Repo Validator's CSS architecture.

### Fixed

- **Audit Compare: Bounded regular expressions:** All regex patterns in `audit_compare.py` now use bounded quantifiers (`\d{1,10}`, `{1,10}`) instead of unbounded `\d+` / `+` to eliminate polynomial backtracking warnings from security scanners. Alternation patterns also refactored to avoid shared prefixes across branches.
- **Cross-Repo Validator: Rule Key Consistency false positives (CIS):** `extract_task_data()` used hardcoded `cat_1/cat_2/cat_3` directory names, causing zero tasks to be found for CIS repos that use `section_*` directories. All audit rules were falsely flagged as "Rule found in audit but no task." Task subdirectory discovery now dynamically finds both `cat_*` and `section_*` directories, matching the audit extraction logic.
- **Cross-Repo Validator: Template Variable Sync false positives:** Reduced false positives from three sources:
  - Jinja2 control blocks (`{% if %}`, `{% for %}`) on value lines were incorrectly classified as hardcoded — now skipped during extraction
  - Empty/bare values (multiline YAML structure parent keys) were flagged — now skipped
  - Variables intentionally hardcoded in the template but absent from `defaults/main.yml` (audit-only structural vars like bootloader paths, `sshd_limited`) were reported as info findings — now silently accepted as intentional
- **Cross-Repo Validator: Audit directory category extraction:** `cat_(\d)` regex only matched `cat_*` directories — updated to `(?:cat|section)_(\d+)` so section numbers are extracted correctly for CIS repos
- **Cross-Repo Validator: Rule ID prefix detection:** `auto_detect_rule_id_prefix()` used hardcoded `cat_*` directories — now uses `_find_audit_subdirs()` for consistent directory discovery
- **Cross-Repo Validator: Multi-rule audit file extraction:** `extract_audit_files()` only captured the first toggle conditional, STIG_ID, and Rule_ID per file. Audit files containing multiple rules (e.g., CIS `cis_3.5.3.3.x.yml` with 6 rules, or STIG files with multiple STIG_IDs) only registered the first rule — remaining rules were falsely flagged in Rule Key Consistency and Audit File Coverage. Now collects all toggle conditionals, STIG_IDs, and Rule_IDs per file and registers each as a separate audit map entry (applies to both CIS and STIG)
- **Cross-Repo Validator: Dotted toggle names in task `when:` conditions (CIS):** Some repos use dotted notation in `when:` conditions (e.g., `amazon2cis_rule_3.4.3.5` instead of `amazon2cis_rule_3_4_3_5`). The task extraction regex only matched underscores, stopping at the first dot and producing truncated keys like `amazon2cis_rule_3`. Now matches dots in toggle names and normalizes them to underscores
- **Cross-Repo Validator: Rule Key Consistency false positives for CIS bare `when:` list items:** `extract_task_data()` used `fullmatch()` to detect bare toggle lines in Ansible `when:` lists (e.g. `- amazon2cis_rule_1_1_2_1_1`), but `fullmatch()` requires the entire string to match and the YAML list prefix `- ` caused it to fail. Every toggle in a multi-line `when:` block was missed, producing false "Rule found in audit but no task" info findings (127 false findings on AMAZON2-CIS). Replaced `fullmatch()` with `finditer()` in an `else` branch, which correctly finds toggle references regardless of `- ` prefix. Also handles compound `or`/`and` conditions on a single line (e.g. `- toggle_a or toggle_b`) and uses the match group instead of the raw line for the key value

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
  - `--summary-only` flag to show only summary and changes breakdown, skipping detailed control listings
  - **Interactive HTML reports** -- JavaScript-powered toolbar with:
    - Filter buttons to toggle visibility of Fixed, Regressed, and Still Failed sections
    - Search box to filter controls by ID or test name with match counter
    - Sortable table columns (click headers to sort ascending/descending)
    - Expand All / Collapse All toggle for `<details>` sections
    - Click-to-navigate from Changes Breakdown rows to corresponding sections
    - Print Report button with print-friendly CSS (hides toolbar, removes shadows)
    - Graceful degradation when JavaScript is disabled (toolbar hidden via `<noscript>`)
  - **Web UI** (`--serve [PORT]`) -- local web server for browser-based comparison workflow
    - Single-page application with file browser, pre/post file selection, and inline report rendering
    - Auto-classification of JSON files as PRE/POST based on filename patterns
    - REST API endpoints: `/api/files`, `/api/compare`, `/api/report`
    - Binds to `127.0.0.1` only with directory traversal prevention
    - Default port: `9090`
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
