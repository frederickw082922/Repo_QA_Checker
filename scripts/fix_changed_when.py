#!/usr/bin/env python3
"""Find and optionally fix shell/command tasks missing changed_when.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Shell and command tasks that don't modify system state (audit checks,
prelim facts gathering) should have `changed_when: false` to prevent
false "changed" reports during Ansible runs.

Detection heuristics:
- Task name contains "AUDIT" or "PRELIM" -> likely read-only
- Shell/command tasks that register a variable but have no changed_when

Usage:
    python fix_changed_when.py <repo_path> [--fix] [--strict]
"""

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}

# Module names that execute commands
COMMAND_MODULES = {
    "shell", "command", "raw",
    "ansible.builtin.shell", "ansible.builtin.command", "ansible.builtin.raw",
}

# Task name patterns that indicate read-only operations
AUDIT_PATTERNS = re.compile(
    r"\b(AUDIT|PRELIM|prelim|audit|gather|discover|check|verify|validate)\b",
    re.IGNORECASE,
)


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


def scan_file(filepath, repo_path, strict=False):
    """Scan a file for shell/command tasks missing changed_when."""
    issues = []
    rel = os.path.relpath(filepath, repo_path)

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()

        # Look for task start: "- name:"
        name_match = re.match(r"^(\s*)- name:\s*(.+)", line)
        if not name_match:
            i += 1
            continue

        task_indent = len(name_match.group(1)) + 2
        task_name = name_match.group(2).strip().strip("'\"")
        task_start = i

        # Scan the task block for module, register, and changed_when
        has_command_module = False
        has_changed_when = False
        has_register = False
        module_line = None
        end_of_task = len(lines)

        j = i + 1
        while j < len(lines):
            tline = lines[j]
            tstripped = tline.lstrip()
            if not tstripped or tstripped.startswith("#"):
                j += 1
                continue

            tindent = len(tline) - len(tstripped)

            # Task boundary: less indented or new list item at same level
            if tindent < task_indent:
                end_of_task = j
                break
            if tstripped.startswith("- ") and tindent <= task_indent - 2:
                end_of_task = j
                break

            # Check for command module
            for mod in COMMAND_MODULES:
                if tstripped.startswith(f"{mod}:"):
                    has_command_module = True
                    module_line = j
                    break

            if re.match(r"\s*changed_when:", tline):
                has_changed_when = True
            if re.match(r"\s*register:", tline):
                has_register = True

            j += 1

        if j >= len(lines):
            end_of_task = len(lines)

        # Report if shell/command task lacks changed_when
        if has_command_module and not has_changed_when:
            is_audit = bool(AUDIT_PATTERNS.search(task_name))
            if is_audit or strict:
                severity = "warning" if is_audit else "info"
                issues.append({
                    "file": rel,
                    "line": task_start + 1,
                    "task_name": task_name,
                    "is_audit": is_audit,
                    "severity": severity,
                    "insert_after": module_line if module_line else task_start,
                    "task_indent": task_indent,
                })

        i = end_of_task if end_of_task > i else i + 1

    return issues


def apply_fixes(filepath, issues):
    """Add changed_when: false to tasks missing it."""
    if not issues:
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Process in reverse to preserve line numbers
    for issue in sorted(issues, key=lambda i: i["insert_after"], reverse=True):
        insert_idx = issue["insert_after"] + 1
        indent = " " * issue["task_indent"]
        new_line = f"{indent}changed_when: false\n"

        # Don't insert if already there (safety check)
        if insert_idx < len(lines) and "changed_when" in lines[insert_idx]:
            continue

        lines.insert(insert_idx, new_line)

    with open(filepath, "w", encoding="utf-8") as f:
        f.writelines(lines)

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Find and fix missing changed_when on shell/command tasks")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix", action="store_true", help="Apply fixes automatically")
    parser.add_argument("--strict", action="store_true",
                        help="Flag ALL shell/command tasks without changed_when, "
                             "not just AUDIT/PRELIM tasks")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    files = find_task_files(args.repo_path)
    total_issues = 0

    for filepath in files:
        issues = scan_file(filepath, args.repo_path, strict=args.strict)
        if issues:
            for issue in issues:
                total_issues += 1
                label = "AUDIT" if issue["is_audit"] else "shell/command"
                print(f"  [{issue['severity']}] {issue['file']}:{issue['line']} "
                      f"- Missing changed_when on {label} task: "
                      f"{issue['task_name'][:70]}")

            if args.fix:
                if apply_fixes(filepath, issues):
                    rel = os.path.relpath(filepath, args.repo_path)
                    print(f"  FIXED: {rel} ({len(issues)} task(s))")

    print(f"\n{'='*60}")
    print(f"Total missing changed_when: {total_issues}")
    if not args.fix and total_issues > 0:
        print("Run with --fix to apply automatic fixes")

    sys.exit(1 if total_issues > 0 and not args.fix else 0)


if __name__ == "__main__":
    main()
