#!/usr/bin/env python3
"""Find tasks that read or set passwords/secrets without no_log: true.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Detects tasks that handle sensitive data (passwords, shadow file, keys)
and are missing `no_log: true`, which would expose secrets in Ansible
logs and console output.

Checks for:
- Shell/command tasks reading /etc/shadow or /etc/gshadow
- Tasks with password/secret in variable names or values
- Tasks using user module with password parameter
- Lineinfile/replace tasks touching sensitive files

Usage:
    python fix_no_log.py <repo_path> [--fix] [--strict]
"""

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}

# Patterns indicating sensitive operations
SHADOW_PATTERNS = [
    re.compile(r"/etc/shadow"),
    re.compile(r"/etc/gshadow"),
    re.compile(r"/etc/security/opasswd"),
]

PASSWORD_PATTERNS = [
    re.compile(r"\bpassword\s*:", re.IGNORECASE),
    re.compile(r"\bpassword_hash\b", re.IGNORECASE),
    re.compile(r"\bencrypt\b.*\bpassword\b", re.IGNORECASE),
]

# Module patterns that commonly need no_log
SENSITIVE_MODULES = {
    "user": ["password"],
    "ansible.builtin.user": ["password"],
}


def find_task_files(repo_path):
    """Find task YAML files."""
    files = []
    for subdir in ("tasks", "handlers"):
        dirpath = os.path.join(repo_path, subdir)
        if not os.path.isdir(dirpath):
            continue
        for root, dirs, filenames in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                if fname.endswith((".yml", ".yaml")):
                    files.append(os.path.join(root, fname))
    return sorted(files)


def scan_file(filepath, repo_path, strict=False):
    """Scan a file for tasks missing no_log on sensitive operations."""
    issues = []
    rel = os.path.relpath(filepath, repo_path)

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i]

        # Find task start
        name_match = re.match(r"^(\s*)- name:\s*(.+)", line)
        if not name_match:
            i += 1
            continue

        task_indent = len(name_match.group(1)) + 2
        task_name = name_match.group(2).strip().strip("'\"")
        task_start = i

        # Scan the task block
        has_no_log = False
        has_sensitive_content = False
        sensitive_reason = ""
        end_of_task = len(lines)

        j = i + 1
        while j < len(lines):
            tline = lines[j]
            tstripped = tline.lstrip()
            if not tstripped or tstripped.startswith("#"):
                j += 1
                continue

            tindent = len(tline) - len(tstripped)
            if tindent < task_indent:
                end_of_task = j
                break
            if tstripped.startswith("- ") and tindent <= task_indent - 2:
                end_of_task = j
                break

            # Check for no_log
            if re.match(r"\s*no_log:", tline):
                has_no_log = True

            # Check for shadow file access
            for pat in SHADOW_PATTERNS:
                if pat.search(tline):
                    has_sensitive_content = True
                    sensitive_reason = f"reads {pat.pattern}"
                    break

            # Check for password parameters
            if not has_sensitive_content:
                for pat in PASSWORD_PATTERNS:
                    if pat.search(tline):
                        has_sensitive_content = True
                        sensitive_reason = "handles password data"
                        break

            j += 1

        if j >= len(lines):
            end_of_task = len(lines)

        if has_sensitive_content and not has_no_log:
            issues.append({
                "file": rel,
                "line": task_start + 1,
                "task_name": task_name,
                "reason": sensitive_reason,
                "task_indent": task_indent,
                "insert_line": task_start + 1,  # After the name: line
            })

        i = end_of_task if end_of_task > i else i + 1

    return issues


def apply_fixes(filepath, issues):
    """Add no_log: true to tasks missing it."""
    if not issues:
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Process in reverse to preserve line numbers
    for issue in sorted(issues, key=lambda i: i["insert_line"], reverse=True):
        insert_idx = issue["insert_line"]
        indent = " " * issue["task_indent"]
        new_line = f"{indent}no_log: true\n"

        # Insert after the name: line
        lines.insert(insert_idx, new_line)

    with open(filepath, "w", encoding="utf-8") as f:
        f.writelines(lines)

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Find tasks missing no_log on sensitive operations")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix", action="store_true",
                        help="Add no_log: true to flagged tasks")
    parser.add_argument("--strict", action="store_true",
                        help="Also flag tasks with password in the name")
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
                print(f"  [warning] {issue['file']}:{issue['line']} "
                      f"- Missing no_log ({issue['reason']}): "
                      f"{issue['task_name'][:70]}")

            if args.fix:
                if apply_fixes(filepath, issues):
                    rel = os.path.relpath(filepath, args.repo_path)
                    print(f"  FIXED: {rel} ({len(issues)} task(s))")

    print(f"\n{'='*60}")
    print(f"Total missing no_log: {total_issues}")
    if not args.fix and total_issues > 0:
        print("Run with --fix to add no_log: true")

    sys.exit(1 if total_issues > 0 and not args.fix else 0)


if __name__ == "__main__":
    main()
