#!/usr/bin/env python3
"""Find and optionally fix manual remediation tasks missing the Warn Count block.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Tasks that use `msg: "This control requires manual remediation"` must be
followed by a Warn Count task that imports warning_facts.yml so the control
is tracked in the warning summary at the end of the Ansible run.

Also detects block-level `vars: warn_control_id` placement — vars must be at
task-level (same indentation as `ansible.builtin.import_tasks:`), NOT at
block-level (same indentation as `block:`).

Expected pattern:
    - name: "X.X.X | AUDIT | Description | check status"
      ansible.builtin.debug:
        msg: "This control requires manual remediation"

    - name: "X.X.X | AUDIT | Description | Warn Count"
      ansible.builtin.import_tasks:
        file: warning_facts.yml
      vars:
        warn_control_id: 'X.X.X'

Usage:
    python fix_warn_count.py <repo_path> [--fix]
"""

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}

# Pattern to match the "check status" name line with a manual remediation debug
MANUAL_RE = re.compile(
    r'^(\s*)- name: "([0-9.]+) \| AUDIT \| (.+?) \| check status"\s*$'
)
DEBUG_MSG = 'msg: "This control requires manual remediation"'

# Pattern to detect block-level vars with warn_control_id (wrong placement)
BLOCK_LEVEL_VARS_RE = re.compile(r'^(\s{2})vars:\s*$')
BLOCK_LEVEL_WARN_ID_RE = re.compile(r'^(\s{4})warn_control_id:\s*')
# Pattern to detect import_tasks for warning_facts.yml missing task-level vars
IMPORT_WARN_FACTS_RE = re.compile(r'^\s+file:\s*warning_facts\.yml\s*$')


def find_task_files(repo_path):
    """Find task YAML files."""
    files = []
    tasks_dir = os.path.join(repo_path, "tasks")
    if not os.path.isdir(tasks_dir):
        return files
    for root, dirs, filenames in os.walk(tasks_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith((".yml", ".yaml")):
                files.append(os.path.join(root, fname))
    return sorted(files)


def scan_file(filepath, repo_path):
    """Scan a file for manual remediation tasks missing Warn Count."""
    issues = []
    rel = os.path.relpath(filepath, repo_path)

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i]

        # Look for the manual remediation debug message
        if DEBUG_MSG not in line:
            i += 1
            continue

        # Walk backwards to find the "check status" name line
        control_id = ""
        description = ""
        task_indent = ""
        for back in range(i - 1, max(i - 5, -1), -1):
            m = MANUAL_RE.match(lines[back])
            if m:
                task_indent = m.group(1)
                control_id = m.group(2)
                description = m.group(3)
                break

        if not control_id:
            i += 1
            continue

        # Check if Warn Count block already follows
        has_warn = False
        for ahead in range(i + 1, min(i + 8, len(lines))):
            if "Warn Count" in lines[ahead]:
                has_warn = True
                break
            stripped = lines[ahead].lstrip()
            if stripped.startswith("- name:"):
                break

        if not has_warn:
            issues.append({
                "file": rel,
                "line": i + 1,
                "control_id": control_id,
                "description": description,
                "task_indent": task_indent,
                "insert_after": i,
            })

        i += 1

    return issues


def _is_legit_parent_vars_for_block(lines, vars_line_idx):
    """Return True if the `vars:` at lines[vars_line_idx] belongs to a
    parent task that pairs it with a `block:` containing a `warning_facts.yml`
    import. That is the intended DRY Lockdown convention and should not be
    flagged as a misplaced declaration.

    Mirrors the helper in Ansible_Lockdown_QA_Repo_Check.py's
    ManualWarnCountCheck. Kept duplicated rather than imported to keep
    these scripts independently runnable.
    """
    task_start = None
    for back in range(vars_line_idx, -1, -1):
        if re.match(r"^- name:", lines[back]):
            task_start = back
            break
    if task_start is None:
        return False
    task_end = len(lines)
    for fwd in range(vars_line_idx + 1, len(lines)):
        if re.match(r"^- name:", lines[fwd]):
            task_end = fwd
            break
    has_block = False
    has_warning_facts = False
    for k in range(task_start, task_end):
        if re.match(r"^  block:\s*$", lines[k].rstrip()):
            has_block = True
        if "warning_facts.yml" in lines[k]:
            has_warning_facts = True
    return has_block and has_warning_facts


def scan_block_level_vars(filepath, repo_path):
    """Scan a file for misplaced vars with warn_control_id.

    The legit Lockdown DRY pattern is `vars: warn_control_id` at parent
    task scope paired with a `block:` whose children import
    `warning_facts.yml`. Flag only when that pairing is absent — those
    declarations are genuinely misplaced.
    """
    issues = []
    rel = os.path.relpath(filepath, repo_path)

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i]

        # Look for vars: (2-space indent) followed by warn_control_id
        if BLOCK_LEVEL_VARS_RE.match(line):
            if i + 1 < len(lines) and BLOCK_LEVEL_WARN_ID_RE.match(lines[i + 1]):
                # Skip the legit parent-vars-for-block DRY pattern
                if _is_legit_parent_vars_for_block(lines, i):
                    i += 1
                    continue

                # Extract the control ID
                cid_match = re.search(r"warn_control_id:\s*['\"]?([^'\"]+)",
                                      lines[i + 1])
                cid = cid_match.group(1).strip() if cid_match else "unknown"

                # Find the import_tasks: warning_facts.yml in this block
                import_line = None
                for ahead in range(i + 2, min(i + 60, len(lines))):
                    if IMPORT_WARN_FACTS_RE.match(lines[ahead]):
                        import_line = ahead
                        break

                issues.append({
                    "file": rel,
                    "line": i + 1,
                    "control_id": cid,
                    "vars_line": i,
                    "warn_id_line": i + 1,
                    "import_facts_line": import_line,
                })
        i += 1

    return issues


def fix_block_level_vars(filepath, issues):
    """Move misplaced vars to task-level on the import_tasks task.

    Returns (fixed_count, skipped) tuple. Issues with no warning_facts.yml
    target in scope are skipped — silently deleting the vars there would
    hide a missing-Warn-Count signal. Such issues need human attention
    to decide between (a) add the Warn Count import, or (b) remove the
    unused vars.
    """
    if not issues:
        return 0, []

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    fixed = 0
    skipped = []
    # Process in reverse to preserve line numbers
    for issue in sorted(issues, key=lambda x: x["vars_line"], reverse=True):
        vars_idx = issue["vars_line"]
        warn_id_idx = issue["warn_id_line"]
        import_idx = issue["import_facts_line"]
        cid = issue["control_id"]

        if import_idx is None:
            # No warning_facts.yml in scope — refuse to auto-move.
            # The vars: is likely a real missing-Warn-Count signal.
            skipped.append(issue)
            continue

        # Remove misplaced vars: and warn_control_id: lines
        del lines[warn_id_idx]
        del lines[vars_idx]

        # Adjust import_idx since we removed 2 lines before it
        import_idx -= 2

        # Find the indentation of import_tasks (the line before import_facts)
        import_tasks_line = import_idx - 1
        if import_tasks_line >= 0:
            indent_match = re.match(r'^(\s+)', lines[import_tasks_line])
            if indent_match:
                task_indent = indent_match.group(1)
                content_indent = task_indent + "  "

                # Check if vars: already exists after warning_facts.yml
                next_idx = import_idx + 1
                has_vars = (next_idx < len(lines) and
                            'vars:' in lines[next_idx] and
                            'warn_control_id' in lines[min(next_idx + 1,
                                                            len(lines) - 1)])

                if not has_vars:
                    # Insert task-level vars after the import_facts line
                    insert_at = import_idx + 1
                    lines.insert(insert_at,
                                 f"{task_indent}vars:\n")
                    lines.insert(insert_at + 1,
                                 f"{content_indent}warn_control_id: '{cid}'\n")
        fixed += 1

    if fixed > 0:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)

    return fixed, skipped


def apply_fixes(filepath, issues):
    """Add Warn Count blocks to tasks missing them."""
    if not issues:
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Process in reverse to preserve line numbers
    for issue in sorted(issues, key=lambda x: x["insert_after"], reverse=True):
        insert_idx = issue["insert_after"] + 1
        indent = issue["task_indent"]
        cid = issue["control_id"]
        desc = issue["description"]

        # Build the Warn Count block with correct indentation
        # task_indent is the indent of "- name:", so the task item content
        # is indented by task_indent + 2 more spaces
        item_indent = indent + "  "
        content_indent = indent + "    "
        warn_block = [
            "\n",
            f"{indent}- name: \"{cid} | AUDIT | {desc} | Warn Count\"\n",
            f"{item_indent}ansible.builtin.import_tasks:\n",
            f"{content_indent}file: warning_facts.yml\n",
            f"{item_indent}vars:\n",
            f"{content_indent}warn_control_id: '{cid}'\n",
        ]

        for j, new_line in enumerate(warn_block):
            lines.insert(insert_idx + j, new_line)

    with open(filepath, "w", encoding="utf-8") as f:
        f.writelines(lines)

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Find and fix manual remediation tasks missing Warn Count")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix", action="store_true",
                        help="Apply fixes automatically")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    files = find_task_files(args.repo_path)
    total_missing = 0
    total_misplaced = 0

    for filepath in files:
        # Check for missing Warn Count blocks
        issues = scan_file(filepath, args.repo_path)
        if issues:
            for issue in issues:
                total_missing += 1
                print(f"  [warning] {issue['file']}:{issue['line']} "
                      f"- Missing Warn Count block for control "
                      f"{issue['control_id']}")

            if args.fix:
                if apply_fixes(filepath, issues):
                    rel = os.path.relpath(filepath, args.repo_path)
                    print(f"  FIXED: {rel} ({len(issues)} missing block(s))")

        # Check for block-level vars placement (wrong indentation)
        blv_issues = scan_block_level_vars(filepath, args.repo_path)
        if blv_issues:
            for issue in blv_issues:
                total_misplaced += 1
                print(f"  [warning] {issue['file']}:{issue['line']} "
                      f"- Block-level vars for warn_control_id "
                      f"'{issue['control_id']}' (should be task-level)")

            if args.fix:
                fixed, skipped = fix_block_level_vars(filepath, blv_issues)
                rel = os.path.relpath(filepath, args.repo_path)
                if fixed:
                    print(f"  FIXED: {rel} ({fixed} vars moved to "
                          f"task-level)")
                for skip in skipped:
                    print(f"  SKIPPED: {rel}:{skip['line']} - vars for "
                          f"'{skip['control_id']}' has no warning_facts.yml "
                          f"target in scope. Needs human decision: add Warn "
                          f"Count import, or remove unused vars.")

    total_issues = total_missing + total_misplaced
    print(f"\n{'='*60}")
    if total_missing:
        print(f"Missing Warn Count blocks: {total_missing}")
    if total_misplaced:
        print(f"Block-level vars (wrong placement): {total_misplaced}")
    print(f"Total issues: {total_issues}")
    if not args.fix and total_issues > 0:
        print("Run with --fix to apply automatic fixes")

    sys.exit(1 if total_issues > 0 and not args.fix else 0)


if __name__ == "__main__":
    main()
