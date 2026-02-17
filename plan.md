# Roadmap: Expose `ansible-lockdown-qa-check` as a pre-commit Hook

## Goal

Allow consumers (Ansible-Lockdown role repositories) to add this tool as a
[pre-commit](https://pre-commit.com/) hook so that QA checks run automatically
on every commit (or on CI via `pre-commit run --all-files`).

---

## Current State

| Item | Status |
|------|--------|
| Installable via `pip install .` | Yes (`pyproject.toml` with `[project.scripts]`) |
| CLI entry point `ansible-lockdown-qa` | Yes (maps to `Ansible_Lockdown_QA_Repo_Check:main`) |
| Exit codes (0 / 1 / 2) | Yes -- compatible with pre-commit expectations |
| `.pre-commit-hooks.yaml` | **Missing** |
| pre-commit-friendly defaults | **Needs review** (report file, console output, directory resolution) |

---

## Phase 1 -- Hook Definition File

**Deliverable:** `.pre-commit-hooks.yaml` in the repo root.

### Steps

1. **Create `.pre-commit-hooks.yaml`** with a single hook entry:
   - `id: ansible-lockdown-qa`
   - `name: Ansible Lockdown QA Check`
   - `entry: ansible-lockdown-qa`
   - `language: python`
   - `pass_filenames: false` -- the tool operates on an entire role directory,
     not individual files
   - `always_run: true` -- ensures the hook fires even when only non-YAML files
     change (variable usage spans Python/Jinja2/YAML)
   - `stages: [pre-commit]` (default, but explicit for clarity)

2. **Choose sensible default args** for the hook:
   - `args: ['-d', '.', '--strict', '--console', '--no-report']`
   - Rationale: run in the repo root, treat warnings as failures in a commit
     gate, print to terminal, and skip writing a report file that would dirty
     the working tree.
   - Consumers can override `args` in their own `.pre-commit-config.yaml`.

---

## Phase 2 -- Verify Directory Resolution in Hook Context

pre-commit clones hook repos into an isolated cache and runs the entry point
with `cwd` set to the **consumer's repo root**. The tool must resolve the
target directory correctly.

### Steps

1. **Audit `_resolve_directory()`** (line ~1750):
   - When `-d .` is passed, `os.path.abspath('.')` resolves to cwd -- correct.
   - When `-d` is omitted, the fallback is `os.path.dirname(__file__)` (the
     cached hook repo, **not** the consumer's repo). This would fail silently.
   - Decision: require `-d .` in the hook's default `args` (Phase 1 already
     covers this). Document this clearly.

2. **Validate `defaults/main.yml` detection** -- confirm the error message and
   exit code 1 surface cleanly through pre-commit when the hook runs in a
   non-role directory.

---

## Phase 3 -- Output / Side-Effect Hygiene

pre-commit hooks should not create or modify files in the working tree (unless
the hook is a "fixer"). Validate the tool behaves cleanly.

### Steps

1. **`--no-report` must be in default args** -- prevents `qa_report.*` from
   being written. Already planned in Phase 1 `args`.

2. **`--fix` mode as a separate hook (optional):**
   - Consider exposing a second hook entry (`id: ansible-lockdown-qa-fix`) that
     runs with `--fix` and is marked as a fixer.
   - This is optional for the initial release; document it as a future
     enhancement if not implemented now.

3. **stderr vs stdout** -- pre-commit captures stdout. Confirm:
   - `--console` output goes to stdout (visible to the user).
   - `--verbose` timing goes to stderr (also visible, does not interfere).

---

## Phase 4 -- Additional Dependencies

The hook's `language: python` means pre-commit will `pip install` the package.
Optional linter tools (`yamllint`, `ansible-lint`) will not be installed
automatically.

### Steps

1. **Decide on `additional_dependencies`:**
   - Option A: Do nothing -- `yamllint` and `ansiblelint` checks auto-skip if
     the tools are missing. This is the current graceful behavior. **(Recommended
     for initial release.)**
   - Option B: Add a second hook entry (`id: ansible-lockdown-qa-full`) that
     includes `additional_dependencies: [yamllint, ansible-lint]`.

2. **Document** how consumers can add `additional_dependencies` in their own
   config to opt in to the full check suite:
   ```yaml
   - repo: https://github.com/ansible-lockdown/Repo_QA_Checker
     rev: v2.2.0
     hooks:
       - id: ansible-lockdown-qa
         additional_dependencies: ['yamllint', 'ansible-lint']
   ```

---

## Phase 5 -- Testing the Hook End-to-End

### Steps

1. **Local test with `try-repo`:**
   ```bash
   cd /path/to/an-ansible-role
   pre-commit try-repo /path/to/Repo_QA_Checker ansible-lockdown-qa --all-files
   ```
   - Verify exit codes: 0 on clean role, non-zero on role with issues.
   - Verify no files are created/modified in the role directory.

2. **Remote test** (after pushing):
   ```bash
   # In an Ansible role repo with .pre-commit-config.yaml pointing to the
   # pushed branch/tag
   pre-commit run ansible-lockdown-qa --all-files
   ```

3. **Test edge cases:**
   - Hook runs in a non-role directory (should exit 1 with a clear message).
   - Hook runs with consumer-overridden `args`.
   - Hook runs with `additional_dependencies: [yamllint, ansible-lint]`.

---

## Phase 6 -- Documentation Updates

### Steps

1. **Add a "pre-commit Integration" section to `README.md`** with:
   - Consumer usage snippet (`.pre-commit-config.yaml` example).
   - How to override args and add linter dependencies.
   - Note about `--fix` mode (manual or future fixer hook).

2. **Tag a release** (e.g., `v2.3.0`) so consumers can pin `rev:` to a stable
   version. pre-commit requires a git tag or commit SHA for `rev`.

---

## Phase 7 (Optional / Future) -- Auto-Fix Hook

### Steps

1. Add a second entry in `.pre-commit-hooks.yaml`:
   ```yaml
   - id: ansible-lockdown-qa-fix
     name: Ansible Lockdown QA Auto-Fix
     entry: ansible-lockdown-qa
     args: ['-d', '.', '--fix', '--no-report']
     language: python
     pass_filenames: false
     always_run: true
   ```
2. Test that the fixer modifies files and pre-commit re-stages them.

---

## Summary / Checklist

| # | Task | Phase | Priority |
|---|------|-------|----------|
| 1 | Create `.pre-commit-hooks.yaml` | 1 | Must |
| 2 | Set sensible default `args` | 1 | Must |
| 3 | Verify `_resolve_directory()` with `-d .` | 2 | Must |
| 4 | Confirm `--no-report` suppresses file output | 3 | Must |
| 5 | Validate stdout/stderr behavior | 3 | Should |
| 6 | Document `additional_dependencies` for linters | 4 | Should |
| 7 | Test with `pre-commit try-repo` locally | 5 | Must |
| 8 | Test remotely after push | 5 | Must |
| 9 | Update README with pre-commit section | 6 | Must |
| 10 | Tag release for `rev:` pinning | 6 | Must |
| 11 | Add `ansible-lockdown-qa-fix` hook | 7 | Nice to have |
