# Ansible-Lockdown Fix & Check Scripts

Standalone Python scripts for detecting and auto-fixing common issues in [Ansible Lockdown](https://github.com/ansible-lockdown) hardening roles. Every script works with both **CIS** and **STIG** benchmark types across all supported operating systems.

---

## At a Glance

| Script | What It Fixes / Checks | Auto-Fix |
|--------|----------------------|----------|
| [`fix_fqcn.py`](#fix_fqcnpy) | Bare module names → `ansible.builtin.*` | `--fix` |
| [`fix_file_modes.py`](#fix_file_modespy) | Unquoted file modes (`0644` → `'0644'`) | `--fix` |
| [`fix_when_inline.py`](#fix_when_inlinepy) | Single-item `when:`/`tags:` lists → inline | `--fix` |
| [`fix_changed_when.py`](#fix_changed_whenpy) | Missing `changed_when` on shell/command tasks | `--fix` |
| [`fix_handler_refs.py`](#fix_handler_refspy) | Missing, unused, duplicate handlers; FQCN | `--fix-case` `--fix-fqcn` |
| [`fix_no_log.py`](#fix_no_logpy) | Missing `no_log: true` on sensitive tasks | `--fix` |
| [`fix_spelling.py`](#fix_spellingpy) | Common misspellings (English + Ansible terms) | `--fix` |
| [`fix_grammar.py`](#fix_grammarpy) | Repeated words, apostrophes, subject-verb | `--fix` |
| [`fix_company_naming.py`](#fix_company_namingpy) | Outdated company/org names | `--fix --new-name` |
| [`check_rule_coverage.py`](#check_rule_coveragepy) | Rule toggle ↔ task coverage gaps | Report only |
| [`check_var_naming.py`](#check_var_namingpy) | Register prefixes, duplicates, fwd/reverse | Report only |
| [`fix_ignore_errors.py`](#fix_ignore_errorspy) | `ignore_errors: true` → `failed_when: false` | `--fix` |
| [`fix_loop_control.py`](#fix_loop_controlpy) | Loops missing `loop_control.label` | `--fix` |
| [`check_rule_coverage.py`](#check_rule_coveragepy) | Rule toggle ↔ task coverage gaps | Report only |
| [`check_var_naming.py`](#check_var_namingpy) | Register prefixes, duplicates, fwd/reverse | Report only |
| [`check_tags_completeness.py`](#check_tags_completenesspy) | Tasks missing required tags (rule ID, level) | Report only |
| [`check_audit_keys.py`](#check_audit_keyspy) | Duplicate keys in Goss audit templates | Report only |
| [`check_template_headers.py`](#check_template_headerspy) | Missing `{{ file_managed_by_ansible }}` header | `--fix` |

---

## Requirements

- **Python 3.8+** (standard library only — zero external dependencies)
- An Ansible Lockdown role directory with `defaults/main.yml` and `tasks/`

---

## Common Conventions

All scripts follow the same patterns:

```bash
# Dry run (default) — report issues without changing files
python fix_fqcn.py /path/to/role

# Apply fixes
python fix_fqcn.py /path/to/role --fix

# Review changes after fixing
cd /path/to/role && git diff
```

- **Dry run by default** — no files are modified unless `--fix` is passed
- **Exit code 0** = clean, **exit code 1** = issues found (or errors)
- **Auto-detection** — benchmark type (CIS/STIG) and variable prefix are detected automatically from `defaults/main.yml`
- **`.qa_config.yml`** — some scripts load per-repo configuration when present

### CIS vs STIG Detection

Scripts that need the benchmark prefix auto-detect it from `defaults/main.yml`:

| Type | Config Prefix | Rule Toggle Pattern | Example |
|------|--------------|-------------------|---------|
| CIS | `ubtu20cis` | `{prefix}_rule_1_1_1_1` | `ubtu20cis_rule_1_1_1_1: true` |
| STIG Type A | `rhel8stig` | `{rule_prefix}_010000` | `rhel_08_010000: true` |
| STIG Type B | `az2023stig` | `{prefix}_000100` | `az2023stig_000100: true` |

**STIG Type A** (split prefix): Config and rule toggles use different prefixes (e.g. `rhel8stig_gui` vs `rhel_08_010000`). Found in RHEL, Ubuntu STIG roles.

**STIG Type B** (unified prefix): Same prefix for everything. Prefix ends in `stig` directly followed by `_6digits` (e.g. `az2023stig_000100`). Found in Amazon Linux 2023 and newer roles.

All scripts detect both patterns automatically.

---

## Fix Scripts

### `fix_fqcn.py`

Converts bare (non-fully-qualified) Ansible module names to their `ansible.builtin.*` equivalents. Ansible 2.10+ requires FQCN for reliable module resolution.

```bash
python fix_fqcn.py /path/to/role                          # Scan only
python fix_fqcn.py /path/to/role --fix                     # Apply fixes
python fix_fqcn.py /path/to/role --exclude-path molecule/  # Skip molecule/
```

**What it converts:**
```yaml
# Before                          # After
- name: Copy config               - name: Copy config
  template:                          ansible.builtin.template:
    src: foo.j2                        src: foo.j2

- name: Set permissions            - name: Set permissions
  file:                               ansible.builtin.file:
    path: /etc/foo                       path: /etc/foo
```

**Scans:** `tasks/` and `handlers/` directories. Recognizes 60+ `ansible.builtin` modules. Skips task-level keywords (`when`, `register`, `tags`, etc.) to avoid false positives.

---

### `fix_file_modes.py`

Finds unquoted file permission modes and wraps them in quotes. Unquoted octal modes like `mode: 0644` are parsed by YAML as the decimal integer 644, causing Ansible to set completely wrong permissions (decimal 644 = octal 01204).

```bash
python fix_file_modes.py /path/to/role          # Scan only
python fix_file_modes.py /path/to/role --fix     # Apply fixes
```

**What it converts:**
```yaml
# Before                   # After
mode: 0644                 mode: '0644'
mode: 0755                 mode: '0755'
mode: 0600                 mode: '0600'
```

**Skips:** Already-quoted values, Jinja2 expressions (`{{ item.mode }}`), `preserve`, and variable references.

---

### `fix_when_inline.py`

Converts single-item `when:`, `tags:`, and `notify:` lists to the more concise inline format. Multi-item lists are left unchanged.

```bash
python fix_when_inline.py /path/to/role                 # Scan only
python fix_when_inline.py /path/to/role --fix            # Apply fixes
python fix_when_inline.py /path/to/role --dry-run-stats  # Summary counts only
```

**What it converts:**
```yaml
# Before (2 lines)                # After (1 line)
when:                              when: ubtu20cis_rule_1_1_1_1
  - ubtu20cis_rule_1_1_1_1

tags:                              tags: always
  - always
```

**Scans:** `tasks/` and `handlers/`. Handles `when:`, `tags:`, and `notify:` keywords.

---

### `fix_changed_when.py`

Finds `shell` and `command` tasks that are missing `changed_when` and adds `changed_when: false`. Targets AUDIT and PRELIM tasks by default (read-only commands that never change system state).

```bash
python fix_changed_when.py /path/to/role            # Scan AUDIT/PRELIM only
python fix_changed_when.py /path/to/role --fix       # Apply fixes
python fix_changed_when.py /path/to/role --strict    # Flag ALL shell/command tasks
```

**Detection heuristics:**
- Task name contains `AUDIT`, `PRELIM`, `gather`, `discover`, `check`, `verify`, or `validate`
- Module is `shell`, `command`, or `raw` (bare or FQCN)

**What it adds:**
```yaml
# Before                          # After
- name: "1.1.1 | AUDIT | ..."     - name: "1.1.1 | AUDIT | ..."
  ansible.builtin.shell: ...        ansible.builtin.shell: ...
  register: result                   changed_when: false
                                     register: result
```

---

### `fix_handler_refs.py`

Comprehensive handler integrity check. Finds missing, unused, and duplicate handlers plus case mismatches and bare module names.

```bash
python fix_handler_refs.py /path/to/role             # Full report
python fix_handler_refs.py /path/to/role --fix-case   # Fix case mismatches
python fix_handler_refs.py /path/to/role --fix-fqcn   # Fix bare modules in handlers
```

**Checks:**

| Check | Severity | Example |
|-------|----------|---------|
| Missing handler | Error | `notify: Update dconf` but no handler with that name |
| Duplicate handler | Warning | Two handlers named `Restart sshd` |
| Case mismatch | Warning | `notify: Restart Sshd` vs handler `Restart sshd` |
| Unused handler | Info | Handler defined but never notified |
| Bare FQCN | Warning | `service:` instead of `ansible.builtin.service:` in handlers |

**Output includes:**
- Handler count and notify reference count
- Breakdown by issue type

---

### `fix_no_log.py`

Finds tasks that read or manipulate sensitive data (passwords, shadow files, keys) without `no_log: true`, which would expose secrets in Ansible logs.

```bash
python fix_no_log.py /path/to/role            # Scan only
python fix_no_log.py /path/to/role --fix       # Add no_log: true
python fix_no_log.py /path/to/role --strict    # Also flag password-named tasks
```

**Detects tasks that:**
- Read `/etc/shadow`, `/etc/gshadow`, or `/etc/security/opasswd`
- Have `password:` parameters or `password_hash` references
- Use the `user` module with a password argument

**What it adds:**
```yaml
# Before                          # After
- name: "7.1.8 | PATCH | ..."     - name: "7.1.8 | PATCH | ..."
  ansible.builtin.shell:            no_log: true
    cmd: cat /etc/gshadow            ansible.builtin.shell:
                                       cmd: cat /etc/gshadow
```

---

### `fix_spelling.py`

Scans task names, comments, and documentation for common misspellings using a built-in dictionary of 120+ English and Ansible-specific terms. Strips Jinja2 `{{ expressions }}` before analysis to avoid false positives.

```bash
python fix_spelling.py /path/to/role                           # Scan only
python fix_spelling.py /path/to/role --fix                      # Apply fixes
python fix_spelling.py /path/to/role --exception chrony fstab   # Allow specific words
python fix_spelling.py /path/to/role --skip-dir molecule        # Skip directories
```

**Sample dictionary entries:**

| Misspelling | Correction | Category |
|------------|-----------|----------|
| `benmarks` | `benchmarks` | Ansible |
| `configuartion` | `configuration` | Ansible |
| `priviledge` | `privilege` | English |
| `remdiation` | `remediation` | Ansible |
| `seperately` | `separately` | English |
| `tempalte` | `template` | Ansible |
| `vulnerabilty` | `vulnerability` | Ansible |

**Configuration:** Loads `spelling_exceptions` from `.qa_config.yml` if present.

---

### `fix_grammar.py`

Checks task names and comments for grammatical issues.

```bash
python fix_grammar.py /path/to/role          # Scan only
python fix_grammar.py /path/to/role --fix     # Apply fixes
```

**Checks for:**

| Pattern | Example | Fix |
|---------|---------|-----|
| Repeated words | `the the`, `of of` | Remove duplicate |
| Missing apostrophes | `doesnt`, `wont`, `cant` | `doesn't`, `won't`, `can't` |
| Subject-verb disagreement | `This variables is` | `This variable is` |

**Skips:** YAML values (`true true`), short words, backtick-quoted content in markdown.

---

### `fix_company_naming.py`

Detects outdated company or organization names that should be updated after a rebrand.

```bash
python fix_company_naming.py /path/to/role                            # Scan only
python fix_company_naming.py /path/to/role --fix --new-name "Tyto"    # Replace
python fix_company_naming.py /path/to/role --old-name "acme" "oldco"  # Custom names
```

**Default old names:** `mindpoint` (configurable via `company_old_names` in `.qa_config.yml`)

**Excludes:**
- `meta/` directory (Galaxy metadata)
- `README.md`, `CONTRIBUTING.rst`, `LICENSE`
- Lines containing context patterns (`author`, `namespace`, `company:`, etc.)

---

### `fix_ignore_errors.py`

Replaces `ignore_errors: true` with the safer `failed_when: false`. Using `ignore_errors` suppresses ALL errors including connection failures and module bugs. `failed_when: false` still reports the failure in verbose output but doesn't stop the play.

```bash
python fix_ignore_errors.py /path/to/role          # Scan only
python fix_ignore_errors.py /path/to/role --fix     # Apply fixes
```

**What it converts:**
```yaml
# Before                          # After
- name: Check for package         - name: Check for package
  ansible.builtin.shell: dpkg -l    ansible.builtin.shell: dpkg -l
  ignore_errors: true                failed_when: false
```

**Scans:** `tasks/` and `handlers/`. Skips comment-only lines and preserves trailing comments.

---

### `fix_loop_control.py`

Finds loop tasks (`loop:`, `with_items:`, `with_dict:`, etc.) missing `loop_control.label`. Without a label, Ansible dumps the entire loop item to stdout on each iteration — potentially leaking passwords, hashes, and other sensitive data.

```bash
python fix_loop_control.py /path/to/role                       # Scan only
python fix_loop_control.py /path/to/role --fix                  # Apply fixes (default label)
python fix_loop_control.py /path/to/role --fix --label '"{{ item.name }}"'  # Custom label
```

**What it adds:**
```yaml
# Before                          # After
- name: Set password policy        - name: Set password policy
  ansible.builtin.lineinfile:        ansible.builtin.lineinfile:
    path: "{{ item.file }}"            path: "{{ item.file }}"
    regexp: "{{ item.regexp }}"        regexp: "{{ item.regexp }}"
  loop: "{{ password_rules }}"       loop: "{{ password_rules }}"
                                     loop_control:
                                         label: "{{ item }}"
```

**Default labels:** `"{{ item }}"` for most loops, `"{{ item.key }}"` for `with_dict:`.

**Scans:** `tasks/` and `handlers/`. Detects both `loop:` and all `with_*:` variants. Handles the case where `loop_control:` exists but has no `label:` key.

---

## Check Scripts (Report Only)

### `check_rule_coverage.py`

Cross-references rule toggle variables in `defaults/main.yml` against their usage in `tasks/`, `templates/`, and `handlers/` to find orphaned toggles and missing implementations.

```bash
python check_rule_coverage.py /path/to/role                  # Auto-detect
python check_rule_coverage.py /path/to/role --prefix rhel_08  # Explicit prefix
python check_rule_coverage.py /path/to/role --type stig       # Explicit type
```

**Detects both patterns:**
- CIS: `{prefix}_rule_{section}` (e.g. `ubtu20cis_rule_1_1_1_1`)
- STIG: `{prefix}_{6digits}` (e.g. `rhel_08_010000`)

**Output:**
```
Benchmark prefix: ubtu20cis
Benchmark type:   cis
Rules defined in defaults: 313
Rules used in tasks:      313
Rules used in templates:  313
Rules used in handlers:   0

All rules have corresponding tasks.
```

---

### `check_var_naming.py`

Comprehensive variable hygiene check: register naming conventions, duplicate detection, and forward/reverse coverage analysis.

```bash
python check_var_naming.py /path/to/role                  # Auto-detect
python check_var_naming.py /path/to/role --prefix rhel8stig --type stig
```

**Four checks:**

| Check | What It Finds |
|-------|--------------|
| Register prefix | Variables not using `discovered_`, `prelim_`, `pre_audit_`, `post_audit_`, or `set_` |
| Duplicate registers | Same register name used in multiple tasks |
| Duplicate defaults | Same top-level key defined twice in `defaults/main.yml` |
| Forward/reverse | Defined but unused vars; referenced but undefined vars |

**STIG dual-prefix support:** Correctly tracks both config prefix (`rhel8stig_*`) and rule prefix (`rhel_08_*`) for STIG repos.

---

### `check_tags_completeness.py`

Verifies that all tasks have the required tags for their benchmark type. Auto-detects CIS vs STIG and checks for rule ID tags, level/severity tags, and `always` on prelim tasks.

```bash
python check_tags_completeness.py /path/to/role                    # Auto-detect
python check_tags_completeness.py /path/to/role --summary-only     # Counts only
python check_tags_completeness.py /path/to/role --require-level    # CIS: require level tags
python check_tags_completeness.py /path/to/role --require-severity # STIG: require CAT tags
```

**Checks by benchmark type:**

| Check | CIS | STIG |
|-------|-----|------|
| Has any tags | Yes | Yes |
| Rule ID tag | `rule_1_1_1_1` | `RHEL-08-010000` |
| Level/severity tag | `level1-server`, etc. | `CAT1`, `CAT2`, `CAT3` |
| Prelim tasks have `always` | Yes | Yes |

**Output:**
```
Benchmark prefix: ubtu20cis
Benchmark type:   cis

============================================================
Total tasks:          387
Tasks without tags:   12
Tasks with issues:    15

Issue breakdown:
  missing_always: 1
  missing_rule_id: 2
  no_tags: 12
```

---

### `check_audit_keys.py`

Scans Goss audit variable templates (`ansible_vars_goss.yml.j2`) for duplicate YAML keys at the same indentation level, which cause one value to silently override another.

```bash
python check_audit_keys.py /path/to/role
python check_audit_keys.py /path/to/role --pattern ".*custom_audit.*"
```

**Handles:** Jinja2 `{% for %}` loops (keys inside loops are expected to repeat and are not flagged).

---

### `check_template_headers.py`

Verifies that all `.j2` template files have `{{ file_managed_by_ansible }}` on line 1.

```bash
python check_template_headers.py /path/to/role                # Scan only
python check_template_headers.py /path/to/role --fix           # Add missing headers
python check_template_headers.py /path/to/role --list-excluded # Show skipped files
python check_template_headers.py /path/to/role --exclude custom.j2
```

**Excluded by default:**
- Banner files: `issue.j2`, `issue.net.j2`, `motd.j2` (content renders to system output)
- Audit YAML templates: `*goss*.yml.j2`, `*audit*.yml.j2` (require `---` on line 1)
- `sshd_config.j2` (system config file)

---

## Recommended Workflow

### Quick Scan (no changes)

```bash
cd /path/to/role

# Run all checks
for script in fix_fqcn fix_file_modes fix_when_inline fix_changed_when \
              fix_handler_refs fix_no_log fix_ignore_errors fix_loop_control \
              fix_spelling fix_grammar fix_company_naming; do
    python scripts/${script}.py .
done

python scripts/check_rule_coverage.py .
python scripts/check_var_naming.py .
python scripts/check_tags_completeness.py .
python scripts/check_audit_keys.py .
python scripts/check_template_headers.py .
```

### Auto-Fix (safe order)

Apply fixes in this order to avoid conflicts:

```bash
cd /path/to/role

# 1. Structural fixes first
python scripts/fix_fqcn.py . --fix
python scripts/fix_file_modes.py . --fix

# 2. Format fixes
python scripts/fix_when_inline.py . --fix

# 3. Missing attributes
python scripts/fix_changed_when.py . --fix
python scripts/fix_no_log.py . --fix
python scripts/fix_ignore_errors.py . --fix
python scripts/fix_loop_control.py . --fix

# 4. Text fixes
python scripts/fix_spelling.py . --fix
python scripts/fix_grammar.py . --fix
python scripts/fix_company_naming.py . --fix --new-name "YourCompany"

# 5. Template fixes
python scripts/check_template_headers.py . --fix

# 6. Review all changes
git diff
```

### CI Integration

```bash
# Exit code 1 if any issues found — use in CI pipelines
python scripts/fix_fqcn.py /path/to/role || exit 1
python scripts/fix_file_modes.py /path/to/role || exit 1
python scripts/check_rule_coverage.py /path/to/role || exit 1
```

---

## Tested Against

All scripts are validated against multiple Ansible Lockdown repos:

| Repo | Type | Prefix | Rules | Result |
|------|------|--------|-------|--------|
| UBUNTU20-CIS | CIS | `ubtu20cis` | 313 | Pass |
| RHEL8-STIG | STIG (Type A) | `rhel8stig` / `rhel_08` | 371 | Pass |
| RHEL9-STIG | STIG (Type A) | `rhel9stig` / `rhel_09` | 447 | Pass |
| Private-AMAZON2023-STIG | STIG (Type B) | `az2023stig` | 195 | Pass |
| AMAZON2023-CIS | CIS | `amzn2023cis` | 244 | Pass |

---

## Related Tools

| Tool | Location | Description |
|------|----------|-------------|
| `Ansible_Lockdown_QA_Repo_Check.py` | `../` | Main QA tool — runs all checks with HTML/MD/JSON reports |
| `cross_repo_validator.py` | `./` | Validates remediation + audit repo pairs (14 checks) |
| `audit_compare.py` | `./` | Compares pre/post audit scan results |

---

## Configuration (`.qa_config.yml`)

Some scripts load per-repo configuration from `.qa_config.yml` at the role root:

```yaml
# Spelling exceptions (words to allow)
spelling_exceptions:
  - chrony
  - timesyncd
  - nftables

# Outdated company names to flag
company_old_names:
  - mindpoint

# Paths to exclude from FQCN checks
fqcn_exclude_paths:
  - molecule/

# Register variable prefixes (override defaults)
register_prefixes:
  - discovered_
  - prelim_
  - pre_audit_
  - post_audit_
  - set_

# Minimum severity to report
min_severity: info

# Checks to skip entirely
skip_checks:
  - meta-validate
```
