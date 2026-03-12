#!/usr/bin/env python3
"""Find and optionally fix single-item when:/tags: lists to inline format.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Converts single-item YAML lists to inline format:
    when:                ->  when: ubtu20cis_rule_1_1_1_1
      - ubtu20cis_rule_1_1_1_1

    tags:                ->  tags: always
      - always

Multi-item lists are left unchanged.

Usage:
    python fix_when_inline.py <repo_path> [--fix] [--dry-run-stats]
"""

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}

# Keywords that can have single-item lists converted to inline
INLINE_KEYWORDS = {"when", "tags", "notify"}


def find_yaml_files(repo_path):
    """Find all YAML task files."""
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


def scan_file(filepath, repo_path):
    """Scan for single-item when:/tags: lists that should be inline."""
    issues = []
    rel = os.path.relpath(filepath, repo_path)

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        lstripped = stripped.lstrip()

        # Look for "keyword:" with nothing after it (start of a list)
        for keyword in INLINE_KEYWORDS:
            pat = re.match(rf"^(\s*){keyword}:\s*$", stripped)
            if not pat:
                continue

            indent = len(pat.group(1))
            # Check if next line is a single list item
            if i + 1 < len(lines):
                next_line = lines[i + 1].rstrip()
                next_lstripped = next_line.lstrip()
                next_indent = len(next_line) - len(next_lstripped)

                # Must be a list item at deeper indent
                item_match = re.match(r"^(\s*)- (.+)$", next_line)
                if item_match and next_indent > indent:
                    # Check there's no second list item
                    has_second = False
                    if i + 2 < len(lines):
                        third_line = lines[i + 2].rstrip()
                        third_lstripped = third_line.lstrip()
                        third_indent = len(third_line) - len(third_lstripped)
                        if third_lstripped.startswith("- ") and third_indent == next_indent:
                            has_second = True

                    if not has_second:
                        value = item_match.group(2).strip()
                        issues.append({
                            "file": rel,
                            "line": i + 1,  # 1-indexed
                            "keyword": keyword,
                            "value": value,
                            "keyword_line_idx": i,
                            "item_line_idx": i + 1,
                            "indent": pat.group(1),
                        })
            break  # Only match one keyword per line

        i += 1

    return issues


def apply_fixes(filepath, issues):
    """Convert single-item lists to inline format."""
    if not issues:
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Process in reverse order to preserve line indices
    for issue in sorted(issues, key=lambda i: i["keyword_line_idx"], reverse=True):
        kw_idx = issue["keyword_line_idx"]
        item_idx = issue["item_line_idx"]
        indent = issue["indent"]
        keyword = issue["keyword"]
        value = issue["value"]

        # Replace keyword line with inline version
        lines[kw_idx] = f"{indent}{keyword}: {value}\n"
        # Remove the list item line
        del lines[item_idx]

    with open(filepath, "w", encoding="utf-8") as f:
        f.writelines(lines)

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Convert single-item when:/tags: lists to inline format")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix", action="store_true", help="Apply fixes automatically")
    parser.add_argument("--dry-run-stats", action="store_true",
                        help="Show only counts per keyword")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    files = find_yaml_files(args.repo_path)
    total_issues = 0
    total_fixed = 0
    keyword_counts = {}

    for filepath in files:
        issues = scan_file(filepath, args.repo_path)
        if issues:
            rel = os.path.relpath(filepath, args.repo_path)
            for issue in issues:
                total_issues += 1
                kw = issue["keyword"]
                keyword_counts[kw] = keyword_counts.get(kw, 0) + 1
                if not args.dry_run_stats:
                    print(f"  [info] {issue['file']}:{issue['line']} "
                          f"- {kw}: single-item list -> inline "
                          f"({kw}: {issue['value']})")

            if args.fix:
                if apply_fixes(filepath, issues):
                    total_fixed += len(issues)
                    print(f"  FIXED: {rel} ({len(issues)} conversion(s))")

    print(f"\n{'='*60}")
    print(f"Total single-item lists: {total_issues}")
    if keyword_counts:
        for kw, count in sorted(keyword_counts.items()):
            print(f"  {kw}: {count}")
    if args.fix:
        print(f"Total fixed: {total_fixed}")
    elif total_issues > 0:
        print("Run with --fix to apply automatic fixes")

    sys.exit(1 if total_issues > 0 and not args.fix else 0)


if __name__ == "__main__":
    main()
