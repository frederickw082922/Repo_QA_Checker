#!/usr/bin/env python3
"""Find and optionally fix unquoted file mode values in Ansible task files.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Unquoted octal modes like `mode: 0644` are interpreted as decimal integers
by the YAML parser (0644 decimal = 01204 octal), causing Ansible to set
wrong file permissions. This script finds and quotes them.

    mode: 0644   ->  mode: '0644'
    mode: 0755   ->  mode: '0755'
    mode: 0600   ->  mode: '0600'

Skips modes that are already quoted, use Jinja2 expressions, use `preserve`,
or reference variables.

Usage:
    python fix_file_modes.py <repo_path> [--fix]
"""

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", "__pycache__", ".github", "collections"}

MODE_PAT = re.compile(r"^(\s*mode:\s+)(0?\d{3,4})\s*$")


def find_yaml_files(repo_path):
    """Find all YAML files in the repo."""
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith((".yml", ".yaml")):
                files.append(os.path.join(root, fname))
    return sorted(files)


def scan_file(filepath, repo_path):
    """Scan a file for unquoted file modes."""
    issues = []
    rel = os.path.relpath(filepath, repo_path)

    with open(filepath, "r", encoding="utf-8") as f:
        for num, line in enumerate(f, 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue

            m = re.match(r"^\s*mode:\s+(.+)", line)
            if not m:
                continue

            val = m.group(1).strip()

            # Skip already quoted, Jinja2, preserve, variable references
            if (val.startswith("'") or val.startswith('"')
                    or val.startswith("{") or "preserve" in val
                    or "item" in val or "ansible" in val):
                continue

            if re.match(r"^0?\d{3,4}$", val):
                issues.append({
                    "file": rel,
                    "line": num,
                    "old": val,
                    "new": f"'{val}'",
                    "raw": line.rstrip(),
                })

    return issues


def apply_fixes(filepath, issues):
    """Quote unquoted mode values in a file."""
    if not issues:
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    modified = False
    issue_lines = {i["line"] for i in issues}

    for idx, line in enumerate(lines):
        line_num = idx + 1
        if line_num not in issue_lines:
            continue

        m = MODE_PAT.match(line)
        if m:
            prefix = m.group(1)
            mode_val = m.group(2)
            new_line = f"{prefix}'{mode_val}'\n"
            if new_line != line:
                lines[idx] = new_line
                modified = True

    if modified:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)

    return modified


def main():
    parser = argparse.ArgumentParser(
        description="Find and fix unquoted file modes in Ansible-Lockdown roles")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix", action="store_true", help="Apply fixes automatically")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    files = find_yaml_files(args.repo_path)
    total_issues = 0
    total_fixed = 0

    for filepath in files:
        issues = scan_file(filepath, args.repo_path)
        if issues:
            rel = os.path.relpath(filepath, args.repo_path)
            for issue in issues:
                total_issues += 1
                print(f"  [warning] {issue['file']}:{issue['line']} "
                      f"- mode: {issue['old']} -> mode: {issue['new']}")

            if args.fix:
                if apply_fixes(filepath, issues):
                    total_fixed += len(issues)
                    print(f"  FIXED: {rel}")

    print(f"\n{'='*60}")
    print(f"Total unquoted modes: {total_issues}")
    if args.fix:
        print(f"Total fixed: {total_fixed}")
    elif total_issues > 0:
        print("Run with --fix to apply automatic fixes")

    sys.exit(1 if total_issues > 0 and not args.fix else 0)


if __name__ == "__main__":
    main()
