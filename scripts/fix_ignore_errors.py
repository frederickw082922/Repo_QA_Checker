#!/usr/bin/env python3
"""Find and optionally fix ignore_errors: true -> failed_when: false.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Using `ignore_errors: true` suppresses ALL errors including connection
failures, permission issues, and module bugs. The safer alternative is
`failed_when: false` which still reports the task as failed in verbose
output but doesn't stop the play.

Detection:
- Scans tasks/ and handlers/ for `ignore_errors: true` or `ignore_errors: yes`
- Skips lines inside comments
- Preserves indentation when fixing

Usage:
    python fix_ignore_errors.py <repo_path> [--fix]
"""

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}
SEARCH_DIRS = ("tasks", "handlers")
EXTENSIONS = {".yml", ".yaml"}

# Match ignore_errors: true/yes (not in comments)
IGNORE_ERRORS_RE = re.compile(
    r"^(\s*)ignore_errors:\s*(true|yes)\s*(#.*)?$", re.IGNORECASE
)


def find_yaml_files(repo_path):
    """Find all YAML files in tasks/ and handlers/."""
    files = []
    for subdir in SEARCH_DIRS:
        dirpath = os.path.join(repo_path, subdir)
        if not os.path.isdir(dirpath):
            continue
        for root, dirs, filenames in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                if any(fname.endswith(ext) for ext in EXTENSIONS):
                    files.append(os.path.join(root, fname))
    return sorted(files)


def scan_file(filepath, repo_path):
    """Scan a file for ignore_errors: true."""
    issues = []
    rel = os.path.relpath(filepath, repo_path)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for num, line in enumerate(f, 1):
                # Skip comment-only lines
                if line.lstrip().startswith("#"):
                    continue
                m = IGNORE_ERRORS_RE.match(line)
                if m:
                    issues.append({
                        "file": rel,
                        "line": num,
                        "indent": m.group(1),
                        "comment": m.group(3) or "",
                        "raw": line.rstrip(),
                    })
    except (IOError, OSError) as e:
        print(f"  Error reading {filepath}: {e}", file=sys.stderr)

    return issues


def apply_fixes(filepath, issues):
    """Replace ignore_errors: true with failed_when: false."""
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

        m = IGNORE_ERRORS_RE.match(line)
        if m:
            indent = m.group(1)
            comment = m.group(3) or ""
            if comment:
                new_line = f"{indent}failed_when: false  {comment}\n"
            else:
                new_line = f"{indent}failed_when: false\n"
            lines[idx] = new_line
            modified = True

    if modified:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)

    return modified


def main():
    parser = argparse.ArgumentParser(
        description="Replace ignore_errors: true with failed_when: false")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix", action="store_true",
                        help="Apply fixes automatically")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    files = find_yaml_files(args.repo_path)
    total_issues = 0

    for filepath in files:
        issues = scan_file(filepath, args.repo_path)
        if issues:
            for issue in issues:
                total_issues += 1
                print(f"  [warning] {issue['file']}:{issue['line']} "
                      f"- ignore_errors: true (use failed_when: false)")

            if args.fix:
                if apply_fixes(filepath, issues):
                    rel = os.path.relpath(filepath, args.repo_path)
                    print(f"  FIXED: {rel}")

    print(f"\n{'='*60}")
    print(f"Total ignore_errors: true found: {total_issues}")
    if not args.fix and total_issues > 0:
        print("Run with --fix to replace with failed_when: false")

    sys.exit(1 if total_issues > 0 and not args.fix else 0)


if __name__ == "__main__":
    main()
