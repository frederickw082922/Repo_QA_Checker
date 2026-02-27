#!/usr/bin/env python3
"""Detect duplicate keys in audit templates (e.g. ansible_vars_goss.yml.j2).

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Scans Jinja2 audit templates for YAML keys that appear at the same
indentation level outside of for-loops, which can cause unexpected
behavior during audits.

Usage:
    python check_audit_keys.py <repo_path> [--pattern GLOB]
"""

import argparse
import os
import re
import sys


# Default filename patterns for audit variable templates
AUDIT_TEMPLATE_PATTERNS = [
    re.compile(r'.*goss.*\.j2$', re.IGNORECASE),
    re.compile(r'.*audit_vars.*\.j2$', re.IGNORECASE),
    re.compile(r'.*vars_goss.*\.j2$', re.IGNORECASE),
]


def find_audit_templates(repo_path, extra_patterns=None):
    """Find audit variable templates in the repo."""
    patterns = AUDIT_TEMPLATE_PATTERNS + (extra_patterns or [])
    templates = []

    templates_dir = os.path.join(repo_path, 'templates')
    if not os.path.isdir(templates_dir):
        return templates

    for root, _, files in os.walk(templates_dir):
        for f in files:
            if not f.endswith('.j2'):
                continue
            for pattern in patterns:
                if pattern.match(f):
                    templates.append(os.path.join(root, f))
                    break

    return sorted(templates)


def extract_keys(filepath):
    """Extract YAML keys with their indentation level and line number."""
    keys = []
    key_pattern = re.compile(r'^(\s*)(\w[\w.-]*)\s*:')
    loop_depth = 0

    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            stripped = line.strip()

            # Track Jinja2 for-loop nesting
            if '{%' in stripped:
                if 'for ' in stripped:
                    loop_depth += 1
                    continue
                if 'endfor' in stripped:
                    loop_depth = max(0, loop_depth - 1)
                    continue

            # Skip comments, Jinja2 expressions, list items
            if stripped.startswith('#') or stripped.startswith('{%'):
                continue
            if stripped.startswith('{{') and ':' not in stripped:
                continue
            if stripped.startswith('- '):
                continue

            match = key_pattern.match(line)
            if match:
                indent = len(match.group(1))
                key_name = match.group(2)
                keys.append({
                    'key': key_name,
                    'indent': indent,
                    'line': line_num,
                    'in_loop': loop_depth > 0,
                    'raw': line.rstrip(),
                })

    return keys


def find_duplicates(keys):
    """Find duplicate keys at the same indentation level outside loops."""
    issues = []
    seen = {}  # (indent, key) -> first occurrence line

    for entry in keys:
        lookup = (entry['indent'], entry['key'])

        # Keys inside for-loops are expected to repeat (list items)
        if entry['in_loop']:
            continue

        if lookup in seen:
            issues.append({
                'key': entry['key'],
                'indent': entry['indent'],
                'line': entry['line'],
                'first_line': seen[lookup],
                'severity': 'warning',
            })
        else:
            seen[lookup] = entry['line']

    return issues


def main():
    parser = argparse.ArgumentParser(
        description='Check for duplicate keys in audit templates')
    parser.add_argument('repo_path', help='Path to the repo root')
    parser.add_argument('--pattern', nargs='*', default=[],
                        help='Additional filename regex patterns to match')
    args = parser.parse_args()

    extra_patterns = [re.compile(p) for p in args.pattern]
    templates = find_audit_templates(args.repo_path, extra_patterns)

    if not templates:
        print("No audit templates found")
        sys.exit(0)

    total_issues = 0

    for template in templates:
        rel_path = os.path.relpath(template, args.repo_path)
        keys = extract_keys(template)
        issues = find_duplicates(keys)

        if issues:
            print(f"\n{rel_path}:")
            for issue in issues:
                total_issues += 1
                print(f"  [{issue['severity']}] Line {issue['line']}: "
                      f"Duplicate key '{issue['key']}' at indent {issue['indent']} "
                      f"(first seen at line {issue['first_line']})")
        else:
            print(f"{rel_path}: OK")

    print(f"\n{'='*60}")
    print(f"Total duplicate keys: {total_issues}")
    sys.exit(1 if total_issues > 0 else 0)


if __name__ == '__main__':
    main()
