#!/usr/bin/env python3
"""Check and optionally fix file mode notation in Ansible task files.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Lockdown convention requires relative symbolic (minus/plus) notation for all
mode: directives. This script detects and fixes:
  1. Octal modes (0644, '0755')
  2. Absolute symbolic modes using = notation (u=rw,g=r,o=r)
  3. Mixed notation (g=r,o-rwx)

All are converted to relative symbolic (minus/plus) notation:
  mode: '0644'        ->  mode: 'go-rwx'        (if 0600)
  mode: 'u=rw,g=,o='  ->  mode: 'go-rwx'
  mode: 'u=rw,g=r,o=r' -> mode: 'u-x,go-wx'

Usage:
    python check_file_modes.py <repo_path>             # Report only
    python check_file_modes.py <repo_path> --fix       # Apply fixes
    python check_file_modes.py <repo_path> --tasks-only  # Only scan tasks/
"""

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}

# Mapping: absolute symbolic -> relative symbolic
EQUALS_TO_MINUS = {
    "u=rw,g=,o=":       "go-rwx",
    "u=rw,g=r,o=r":     "u-x,go-wx",
    "u=rw,g=r,o=":      "u-x,g-wx,o-rwx",
    "u=rwx,g=,o=":      "u+rwx,go-rwx",
    "u=rwx,g=rx,o=rx":  "go-w",
    "u=rwx,g=rx,o=":    "g-w,o-rwx",
    "u=rwx,go=rx":       "go-w",
    "u=r,g=,o=":         "u-wx,go-rwx",
    "u=rw,g=,o=r":       "u-x,g-rwx,o-wx",
}

# Mapping: mixed notation -> pure minus
MIXED_TO_MINUS = {
    "g=r,o-rwx":         "g-wx,o-rwx",
}

# Mapping: octal -> relative symbolic
OCTAL_TO_MINUS = {
    "0600": "go-rwx",
    "0644": "u-x,go-wx",
    "0640": "u-x,g-wx,o-rwx",
    "0700": "u+rwx,go-rwx",
    "0755": "go-w",
    "0750": "g-w,o-rwx",
    "0400": "u-wx,go-rwx",
    "0440": "u-wx,g-wx,o-rwx",
    "0444": "u-wx,go-wx",
    "0555": "u-w,go-w",
    "0550": "u-w,g-w,o-rwx",
    "0500": "u-w,go-rwx",
}

# Category labels
CAT_OCTAL = "OCTAL"
CAT_ABSOLUTE = "ABSOLUTE_SYMBOLIC"
CAT_MIXED = "MIXED_NOTATION"


def find_yaml_files(repo_path, tasks_only=False):
    """Find YAML files to scan."""
    search_path = os.path.join(repo_path, "tasks") if tasks_only else repo_path
    files = []
    for root, dirs, filenames in os.walk(search_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith((".yml", ".yaml")):
                files.append(os.path.join(root, fname))
    return sorted(files)


def classify_mode(val):
    """Classify a mode value and return (category, replacement) or None."""
    clean = val.strip().strip("'\"")

    # Skip already-good relative symbolic, preserve, jinja2, variables
    if (clean.startswith("{") or "preserve" in clean
            or "item" in clean or "ansible" in clean
            or clean.startswith("0o")):
        return None

    # Check mixed notation first (has both = and -)
    if clean in MIXED_TO_MINUS:
        return (CAT_MIXED, MIXED_TO_MINUS[clean])

    # Check absolute symbolic (contains = with u/g/o)
    if re.search(r"[ugo]=[rwx]", clean):
        # Handle Jinja2 conditional modes
        jinja_match = re.match(r"\{%.*%\}(.+)\{%.*%\}", clean)
        if jinja_match:
            inner = jinja_match.group(1).strip()
            if inner in EQUALS_TO_MINUS:
                replacement = clean.replace(inner, EQUALS_TO_MINUS[inner])
                return (CAT_ABSOLUTE, replacement)
            return (CAT_ABSOLUTE, None)  # Unknown pattern inside Jinja2

        if clean in EQUALS_TO_MINUS:
            return (CAT_ABSOLUTE, EQUALS_TO_MINUS[clean])
        return (CAT_ABSOLUTE, None)  # Unknown = pattern

    # Check octal (3-4 digit number)
    if re.match(r"^0?\d{3,4}$", clean):
        # Normalize to 4-digit
        normalized = clean.zfill(4) if len(clean) <= 4 else clean
        if not normalized.startswith("0"):
            normalized = "0" + normalized
        if normalized in OCTAL_TO_MINUS:
            return (CAT_OCTAL, OCTAL_TO_MINUS[normalized])
        return (CAT_OCTAL, None)  # Unknown octal

    return None


def scan_file(filepath, repo_path):
    """Scan a file for deprecated mode patterns."""
    issues = []
    rel = os.path.relpath(filepath, repo_path)

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for num, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue

        m = re.match(r"^(\s*mode:\s+)(.+?)(\s*)$", line)
        if not m:
            # Check inside Jinja2 conditionals
            m = re.match(r'^(\s*mode:\s+")(.+?)(")\s*$', line)
            if not m:
                continue

        prefix = m.group(1)
        val = m.group(2)
        suffix = m.group(3)

        result = classify_mode(val)
        if result is None:
            continue

        category, replacement = result
        issues.append({
            "file": rel,
            "line": num,
            "category": category,
            "old": val.strip().strip("'\""),
            "new": replacement,
            "prefix": prefix,
            "suffix": suffix,
            "raw": line.rstrip(),
        })

    return issues


def apply_fixes(filepath, issues):
    """Apply mode fixes to a file."""
    fixable = [i for i in issues if i["new"] is not None]
    if not fixable:
        return 0

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    fixed = 0
    fix_lines = {i["line"]: i for i in fixable}

    for idx, line in enumerate(lines):
        line_num = idx + 1
        if line_num not in fix_lines:
            continue

        issue = fix_lines[line_num]
        old_val = issue["old"]
        new_val = issue["new"]

        # Handle quoted values
        if f"'{old_val}'" in line:
            new_line = line.replace(f"'{old_val}'", f"'{new_val}'")
        elif f'"{old_val}"' in line:
            new_line = line.replace(f'"{old_val}"', f'"{new_val}"')
        elif old_val in line:
            # Unquoted — add quotes
            new_line = line.replace(old_val, f"'{new_val}'")
        else:
            continue

        if new_line != line:
            lines[idx] = new_line
            fixed += 1

    if fixed:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)

    return fixed


def print_summary(all_issues, do_fix, total_fixed):
    """Print summary report."""
    by_cat = {}
    for issue in all_issues:
        cat = issue["category"]
        by_cat.setdefault(cat, []).append(issue)

    print(f"\n{'=' * 70}")
    print("File Mode Check Results")
    print(f"{'=' * 70}")

    for cat in [CAT_OCTAL, CAT_ABSOLUTE, CAT_MIXED]:
        items = by_cat.get(cat, [])
        if not items:
            continue
        print(f"\n{cat} ({len(items)}):")
        for issue in items:
            arrow = f" -> mode: '{issue['new']}'" if issue["new"] else " [UNKNOWN - manual fix needed]"
            print(f"  {issue['file']}:{issue['line']}  mode: '{issue['old']}'{arrow}")

    unknown = [i for i in all_issues if i["new"] is None]

    print(f"\n{'─' * 70}")
    print(f"Total issues:     {len(all_issues)}")
    print(f"  Octal:          {len(by_cat.get(CAT_OCTAL, []))}")
    print(f"  Absolute (=):   {len(by_cat.get(CAT_ABSOLUTE, []))}")
    print(f"  Mixed:          {len(by_cat.get(CAT_MIXED, []))}")
    if unknown:
        print(f"  Unknown:        {len(unknown)} (manual fix needed)")
    if do_fix:
        print(f"  Fixed:          {total_fixed}")
    elif all_issues:
        print("\nRun with --fix to apply automatic fixes")


def main():
    parser = argparse.ArgumentParser(
        description="Check and fix file mode notation in Ansible-Lockdown roles")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix", action="store_true",
                        help="Apply fixes automatically")
    parser.add_argument("--tasks-only", action="store_true",
                        help="Only scan tasks/ directory")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    files = find_yaml_files(args.repo_path, args.tasks_only)
    all_issues = []
    total_fixed = 0

    for filepath in files:
        issues = scan_file(filepath, args.repo_path)
        if issues:
            all_issues.extend(issues)
            if args.fix:
                fixed = apply_fixes(filepath, issues)
                total_fixed += fixed

    if not all_issues:
        print("No deprecated mode patterns found.")
        sys.exit(0)

    print_summary(all_issues, args.fix, total_fixed)
    sys.exit(0 if args.fix or not all_issues else 1)


if __name__ == "__main__":
    main()
