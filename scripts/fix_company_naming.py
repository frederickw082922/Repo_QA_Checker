#!/usr/bin/env python3
"""Find and optionally fix outdated company/organization names in role files.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Detects old company names (e.g., "mindpoint") in task names, comments,
documentation, and templates. Excludes meta/ files, README.md, and lines
containing known context patterns (author fields, namespace declarations).

Usage:
    python fix_company_naming.py <repo_path> [--fix] [--old-name NAME ...]
                                 [--new-name NAME]
"""

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", "__pycache__", ".github", "collections"}

DEFAULT_OLD_NAMES = ["mindpoint"]

# Patterns that indicate the old name is used in acceptable context
EXCLUDE_PATTERNS = [
    "tyto", "project", "author", "company:", "namespace", "company_title",
]

# Files to skip entirely
EXCLUDE_FILES = {"README.md", "CONTRIBUTING.rst", "LICENSE"}

EXTENSIONS = {".yml", ".yaml", ".j2", ".md", ".py", ".sh", ".cfg", ".conf"}


def find_files(repo_path):
    """Find all eligible files."""
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if any(fname.endswith(ext) for ext in EXTENSIONS):
                filepath = os.path.join(root, fname)
                rel = os.path.relpath(filepath, repo_path)
                # Skip meta/ and excluded files
                if rel.startswith("meta/"):
                    continue
                if fname in EXCLUDE_FILES:
                    continue
                files.append(filepath)
    return sorted(files)


def scan_file(filepath, repo_path, old_names, exclude_pats):
    """Scan a file for outdated company names."""
    issues = []
    rel = os.path.relpath(filepath, repo_path)

    search_pat = re.compile(
        "|".join(re.escape(n) for n in old_names), re.IGNORECASE)
    exclude_re = re.compile(
        "|".join(re.escape(p) for p in exclude_pats),
        re.IGNORECASE) if exclude_pats else None

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for num, line in enumerate(f, 1):
                m = search_pat.search(line)
                if m:
                    if exclude_re and exclude_re.search(line):
                        continue
                    issues.append({
                        "file": rel,
                        "line": num,
                        "old_name": m.group(),
                        "raw": line.rstrip(),
                    })
    except (IOError, OSError) as e:
        print(f"  Error reading {filepath}: {e}", file=sys.stderr)

    return issues


def apply_fixes(filepath, issues, old_names, new_name):
    """Replace old company names with new name."""
    if not issues or not new_name:
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    modified = False
    exclude_re = re.compile(
        "|".join(re.escape(p) for p in EXCLUDE_PATTERNS),
        re.IGNORECASE)

    for old_name in old_names:
        # Replace case-insensitively but preserve surrounding context
        pattern = re.compile(re.escape(old_name), re.IGNORECASE)
        new_content = []
        last_end = 0
        for m in pattern.finditer(content):
            # Check if this occurrence is in an excluded context
            line_start = content.rfind("\n", 0, m.start()) + 1
            line_end = content.find("\n", m.end())
            if line_end == -1:
                line_end = len(content)
            line_text = content[line_start:line_end]
            if exclude_re.search(line_text):
                continue
            new_content.append(content[last_end:m.start()])
            new_content.append(new_name)
            last_end = m.end()
            modified = True
        new_content.append(content[last_end:])
        content = "".join(new_content)

    if modified:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

    return modified


def main():
    parser = argparse.ArgumentParser(
        description="Find and fix outdated company names in Ansible-Lockdown roles")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix", action="store_true", help="Apply fixes automatically")
    parser.add_argument("--old-name", nargs="*", default=None,
                        help="Old company names to search for (default: mindpoint)")
    parser.add_argument("--new-name", default=None,
                        help="New company name to replace with (required for --fix)")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    if args.fix and not args.new_name:
        print("Error: --new-name is required when using --fix", file=sys.stderr)
        sys.exit(1)

    old_names = args.old_name or DEFAULT_OLD_NAMES

    # Load from .qa_config.yml if present
    qa_config = os.path.join(args.repo_path, ".qa_config.yml")
    if os.path.isfile(qa_config) and args.old_name is None:
        try:
            with open(qa_config, "r") as f:
                content = f.read()
                m = re.search(r"company_old_names:\s*\[([^\]]+)\]", content)
                if m:
                    old_names = [n.strip().strip("'\"")
                                 for n in m.group(1).split(",")]
        except (IOError, OSError):
            pass

    files = find_files(args.repo_path)
    total_issues = 0

    for filepath in files:
        issues = scan_file(filepath, args.repo_path, old_names, EXCLUDE_PATTERNS)
        if issues:
            for issue in issues:
                total_issues += 1
                print(f"  [warning] {issue['file']}:{issue['line']} "
                      f"- Outdated name '{issue['old_name']}'")

            if args.fix:
                if apply_fixes(filepath, issues, old_names, args.new_name):
                    rel = os.path.relpath(filepath, args.repo_path)
                    print(f"  FIXED: {rel}")

    print(f"\n{'='*60}")
    print(f"Total outdated names: {total_issues}")
    if not args.fix and total_issues > 0:
        print("Run with --fix --new-name <name> to apply replacements")

    sys.exit(1 if total_issues > 0 and not args.fix else 0)


if __name__ == "__main__":
    main()
