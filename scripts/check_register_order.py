#!/usr/bin/env python3
"""Check that register: appears after changed_when, failed_when, check_mode in Ansible tasks.

Lockdown convention: register: must be the last logical attribute on a task,
appearing after all evaluation/safety attributes (changed_when, failed_when,
check_mode, no_log).

Usage:
    python check_register_order.py <role_path>
    python check_register_order.py <role_path> --fix      # Auto-fix ordering
    python check_register_order.py <role_path> --summary   # Summary only
"""

import argparse
import os
import re
import sys

EVAL_KEYS = {'changed_when:', 'failed_when:', 'check_mode:', 'no_log:'}


def check_file(filepath, fix=False):
    """Check a single file for register ordering issues. Returns list of issues."""
    with open(filepath) as f:
        lines = f.readlines()

    issues = []
    fixed_lines = list(lines) if fix else None
    # Track fixes in reverse to preserve line numbers
    fixes = []

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith('register:'):
            continue

        indent = len(line) - len(line.lstrip())
        # Look ahead for eval keys at the same indent level
        after_keys = []
        for j in range(i + 1, min(i + 8, len(lines))):
            next_line = lines[j]
            next_stripped = next_line.strip()
            if not next_stripped or next_stripped.startswith('#'):
                continue
            next_indent = len(next_line) - len(next_line.lstrip())
            if next_indent != indent:
                break
            for key in EVAL_KEYS:
                if next_stripped.startswith(key):
                    after_keys.append((j, key.rstrip(':')))

        if after_keys:
            for j, key_name in after_keys:
                issues.append({
                    'file': filepath,
                    'line': i + 1,
                    'register_line': stripped,
                    'after_key': key_name,
                    'after_line': j + 1,
                })

            if fix:
                # Collect the register line and all eval lines that follow it
                register_line_idx = i
                eval_line_indices = [j for j, _ in after_keys]

                # Find the last eval key line to insert register after
                last_eval_idx = max(eval_line_indices)

                # Move register line to after last eval line
                fixes.append((register_line_idx, last_eval_idx))

    if fix and fixes:
        # Process fixes in reverse order to preserve indices
        for register_idx, insert_after_idx in reversed(fixes):
            register_content = fixed_lines[register_idx]
            del fixed_lines[register_idx]
            # Adjust insert position since we removed a line above it
            if insert_after_idx > register_idx:
                insert_after_idx -= 1
            fixed_lines.insert(insert_after_idx + 1, register_content)

        with open(filepath, 'w') as f:
            f.writelines(fixed_lines)

    return issues


def main():
    parser = argparse.ArgumentParser(description='Check register: ordering in Ansible tasks')
    parser.add_argument('role_path', help='Path to the Ansible role')
    parser.add_argument('--fix', action='store_true', help='Auto-fix ordering issues')
    parser.add_argument('--summary', action='store_true', help='Summary only')
    args = parser.parse_args()

    role_path = os.path.abspath(args.role_path)
    scan_dirs = ['tasks', 'handlers']
    all_issues = []

    for scan_dir in scan_dirs:
        dir_path = os.path.join(role_path, scan_dir)
        if not os.path.isdir(dir_path):
            continue
        for root, _, files in os.walk(dir_path):
            for f in sorted(files):
                if not f.endswith('.yml') and not f.endswith('.yaml'):
                    continue
                filepath = os.path.join(root, f)
                issues = check_file(filepath, fix=args.fix)
                all_issues.extend(issues)

    if not all_issues:
        print("OK: No register ordering issues found.")
        return 0

    # Deduplicate by (file, register_line)
    seen = set()
    unique_issues = []
    for issue in all_issues:
        key = (issue['file'], issue['line'])
        if key not in seen:
            seen.add(key)
            unique_issues.append(issue)

    if args.fix:
        print(f"Fixed {len(unique_issues)} register ordering issues.")
        return 0

    if args.summary:
        files_affected = len(set(i['file'] for i in unique_issues))
        print(f"WARN: {len(unique_issues)} tasks have register: before evaluation attributes across {files_affected} files")
        return 1

    print(f"WARN: {len(unique_issues)} tasks have register: before evaluation attributes\n")
    for issue in unique_issues:
        rel_path = os.path.relpath(issue['file'], role_path)
        print(f"  {rel_path}:{issue['line']}: register before {issue['after_key']} (line {issue['after_line']})")

    print(f"\nTotal: {len(unique_issues)} issues")
    if not args.fix:
        print("Run with --fix to auto-fix.")
    return 1


if __name__ == '__main__':
    sys.exit(main())
