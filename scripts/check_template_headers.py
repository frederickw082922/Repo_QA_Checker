#!/usr/bin/env python3
"""Verify all .j2 template files have the managed-by-ansible header.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Checks that {{ file_managed_by_ansible }} is present on line 1 of each
.j2 file in the templates directory, with optional auto-fix.

Excluded by default:
- Banner files (issue.j2, issue.net.j2, motd.j2) - content renders to system output
- YAML audit templates (*_goss*.yml.j2) - require --- on line 1 for valid YAML
- sshd_config.j2 - system config file that should not have Jinja2 header

Usage:
    python check_template_headers.py <repo_path> [--fix] [--exclude FILE ...]
"""

import argparse
import os
import re
import sys

HEADER_LINE = '{{ file_managed_by_ansible }}\n'

# Files excluded by default (banner files, YAML audit templates, system configs)
DEFAULT_EXCLUDE_NAMES = {'issue.j2', 'issue.net.j2', 'motd.j2', 'sshd_config.j2'}

# Patterns for files that should be excluded (audit YAML templates)
DEFAULT_EXCLUDE_PATTERNS = [
    re.compile(r'.*goss.*\.yml\.j2$', re.IGNORECASE),
    re.compile(r'.*audit.*\.yml\.j2$', re.IGNORECASE),
]


def should_exclude(fname, excludes, exclude_patterns):
    """Check if a filename should be excluded."""
    if fname in excludes:
        return True
    for pattern in exclude_patterns:
        if pattern.match(fname):
            return True
    return False


def find_templates(repo_path, excludes, exclude_patterns):
    """Find all .j2 files under templates/."""
    templates_dir = os.path.join(repo_path, 'templates')
    if not os.path.isdir(templates_dir):
        print(f"Error: {templates_dir} not found", file=sys.stderr)
        sys.exit(1)

    found = []
    excluded = []
    for root, _, filenames in os.walk(templates_dir):
        for fname in filenames:
            if not fname.endswith('.j2'):
                continue
            filepath = os.path.join(root, fname)
            if should_exclude(fname, excludes, exclude_patterns):
                excluded.append(os.path.relpath(filepath, repo_path))
            else:
                found.append(filepath)
    return sorted(found), sorted(excluded)


def check_header(filepath):
    """Check if file has the managed-by-ansible header on line 1."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            first_line = f.readline()
        return 'file_managed_by_ansible' in first_line
    except (IOError, OSError):
        return False


def add_header(filepath):
    """Prepend the managed-by-ansible header to a file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(HEADER_LINE + '\n' + content)


def main():
    parser = argparse.ArgumentParser(
        description='Check .j2 template headers for ansible-lockdown roles')
    parser.add_argument('repo_path', help='Path to the repo root')
    parser.add_argument('--fix', action='store_true', help='Add missing headers')
    parser.add_argument('--exclude', nargs='*', default=[],
                        help='Additional filenames to exclude')
    parser.add_argument('--list-excluded', action='store_true',
                        help='Show excluded files')
    args = parser.parse_args()

    excludes = DEFAULT_EXCLUDE_NAMES | set(args.exclude)
    files, excluded_files = find_templates(args.repo_path, excludes,
                                           DEFAULT_EXCLUDE_PATTERNS)

    missing = []
    present = []

    for filepath in files:
        rel_path = os.path.relpath(filepath, args.repo_path)
        if check_header(filepath):
            present.append(rel_path)
        else:
            missing.append((filepath, rel_path))

    print(f"Templates with header:    {len(present)}")
    print(f"Templates missing header: {len(missing)}")
    print(f"Excluded files:           {len(excluded_files)}")

    if args.list_excluded and excluded_files:
        print(f"\nExcluded:")
        for f in excluded_files:
            print(f"  {f}")

    if missing:
        print(f"\nMissing header:")
        for filepath, rel_path in missing:
            print(f"  {rel_path}")
            if args.fix:
                add_header(filepath)
                print(f"    -> FIXED")

    if not args.fix and missing:
        print(f"\nRun with --fix to add missing headers")

    sys.exit(1 if missing and not args.fix else 0)


if __name__ == '__main__':
    main()
