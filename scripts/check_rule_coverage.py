#!/usr/bin/env python3
"""Find rules defined in defaults/main.yml that have no corresponding task.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).
Auto-detects the benchmark prefix from defaults/main.yml by finding
the most common *_rule_* variable pattern.

Supported prefix formats:
- CIS:  deb11cis, deb12cis, ubuntu2204cis, rhel8cis, rhel9cis, amzn2023cis, etc.
- STIG: rhel7stig, rhel8stig, rhel9stig, ubuntu2004stig, etc.

Usage:
    python check_rule_coverage.py <repo_path> [--prefix PREFIX]
"""

import argparse
import os
import re
import sys
from collections import Counter


def detect_prefix(repo_path):
    """Auto-detect the benchmark prefix from defaults/main.yml.

    Finds the most common prefix pattern matching *_rule_* variables.
    Works with any ansible-lockdown naming convention.
    """
    defaults_file = os.path.join(repo_path, 'defaults', 'main.yml')
    if not os.path.isfile(defaults_file):
        return None

    # Match any word characters before _rule_
    pattern = re.compile(r'^(\w+)_rule_\d', re.MULTILINE)
    prefixes = Counter()

    with open(defaults_file, 'r', encoding='utf-8') as f:
        for line in f:
            match = pattern.match(line.strip())
            if match:
                prefixes[match.group(1)] += 1

    if not prefixes:
        return None

    # Return the most common prefix
    return prefixes.most_common(1)[0][0]


def find_rule_definitions(repo_path, prefix):
    """Find all rule toggle variables in defaults/main.yml."""
    defaults_file = os.path.join(repo_path, 'defaults', 'main.yml')
    rules = {}
    pattern = re.compile(rf'^({re.escape(prefix)}_rule_[\d_]+)\s*:', re.IGNORECASE)

    with open(defaults_file, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            match = pattern.match(line.strip())
            if match:
                rules[match.group(1)] = line_num

    return rules


def find_rule_usage(search_dir, rules, extensions):
    """Find which rules are referenced in files under a directory."""
    used_rules = set()

    if not os.path.isdir(search_dir):
        return used_rules

    for root, _, files in os.walk(search_dir):
        for fname in files:
            if not any(fname.endswith(ext) for ext in extensions):
                continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                for rule_name in rules:
                    if rule_name in content:
                        used_rules.add(rule_name)
            except (IOError, OSError):
                continue

    return used_rules


def main():
    parser = argparse.ArgumentParser(
        description='Check rule coverage between defaults and tasks '
                    'for any ansible-lockdown role')
    parser.add_argument('repo_path', help='Path to the repo root')
    parser.add_argument('--prefix',
                        help='Benchmark prefix (e.g. rhel9stig, deb12cis). '
                             'Auto-detected if omitted.')
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    prefix = args.prefix or detect_prefix(args.repo_path)
    if not prefix:
        print("Error: Could not detect benchmark prefix. Use --prefix.",
              file=sys.stderr)
        sys.exit(1)

    print(f"Benchmark prefix: {prefix}")

    rules = find_rule_definitions(args.repo_path, prefix)
    print(f"Rules defined in defaults: {len(rules)}")

    tasks_dir = os.path.join(args.repo_path, 'tasks')
    templates_dir = os.path.join(args.repo_path, 'templates')
    handlers_dir = os.path.join(args.repo_path, 'handlers')

    used_in_tasks = find_rule_usage(tasks_dir, rules, {'.yml', '.yaml'})
    used_in_templates = find_rule_usage(templates_dir, rules, {'.j2', '.yml'})
    used_in_handlers = find_rule_usage(handlers_dir, rules, {'.yml', '.yaml'})

    all_used = used_in_tasks | used_in_templates | used_in_handlers
    missing_from_tasks = set(rules.keys()) - used_in_tasks

    print(f"Rules used in tasks:      {len(used_in_tasks)}")
    print(f"Rules used in templates:  {len(used_in_templates)}")
    print(f"Rules used in handlers:   {len(used_in_handlers)}")

    if missing_from_tasks:
        print(f"\nRules NOT referenced in tasks ({len(missing_from_tasks)}):")
        for rule in sorted(missing_from_tasks):
            locations = []
            if rule in used_in_templates:
                locations.append("templates")
            if rule in used_in_handlers:
                locations.append("handlers")
            location = ', '.join(locations) if locations else "NOWHERE"
            print(f"  [warning] {rule} (defaults/main.yml:{rules[rule]}) "
                  f"- found in: {location}")
    else:
        print("\nAll rules have corresponding tasks.")

    missing_from_all = set(rules.keys()) - all_used
    print(f"\n{'='*60}")
    print(f"Missing from tasks:    {len(missing_from_tasks)}")
    print(f"Missing from all code: {len(missing_from_all)}")
    sys.exit(1 if missing_from_tasks else 0)


if __name__ == '__main__':
    main()
