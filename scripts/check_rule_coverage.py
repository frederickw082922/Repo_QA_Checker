#!/usr/bin/env python3
"""Find rules defined in defaults/main.yml that have no corresponding task.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).
Auto-detects the benchmark prefix and type from defaults/main.yml.

Supported toggle formats:
- CIS:  {prefix}_rule_{section}  (e.g. ubtu20cis_rule_1_1_1_1)
- STIG: {prefix}_{6digits}       (e.g. rhel_08_010000, az2023stig_001010)

The prefix is auto-detected by finding the most common pattern among
top-level variables in defaults/main.yml.

Usage:
    python check_rule_coverage.py <repo_path> [--prefix PREFIX] [--type cis|stig]
"""

import argparse
import os
import re
import sys
from collections import Counter


def detect_prefix_and_type(repo_path):
    """Auto-detect the benchmark prefix and type from defaults/main.yml.

    Returns (prefix, benchmark_type) where:
    - CIS:  prefix like 'ubtu20cis', type='cis'
    - STIG: prefix like 'rhel_08', type='stig'
    """
    defaults_file = os.path.join(repo_path, 'defaults', 'main.yml')
    if not os.path.isfile(defaults_file):
        return None, None

    # Try CIS pattern first: {prefix}_rule_\d
    cis_pattern = re.compile(r'^(\w+)_rule_\d')
    cis_prefixes = Counter()

    # Try STIG patterns: {prefix}_\d{6}: (bool)
    # Pattern A: prefix with 2-digit numeric segment (e.g. rhel_08_010000)
    stig_pattern_a = re.compile(r'^(\w+_\d{2})_(\d{6})\s*:')
    # Pattern B: prefix ending in "stig" followed by _6digits (e.g. az2023stig_001010)
    stig_pattern_b = re.compile(r'^(\w*stig)_(\d{6})\s*:', re.IGNORECASE)
    stig_prefixes = Counter()

    with open(defaults_file, 'r', encoding='utf-8') as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            m = cis_pattern.match(stripped)
            if m:
                cis_prefixes[m.group(1)] += 1
                continue

            m = stig_pattern_a.match(stripped)
            if not m:
                m = stig_pattern_b.match(stripped)
            if m:
                stig_prefixes[m.group(1)] += 1

    if cis_prefixes and (not stig_prefixes
                         or cis_prefixes.most_common(1)[0][1]
                         >= stig_prefixes.most_common(1)[0][1]):
        return cis_prefixes.most_common(1)[0][0], 'cis'

    if stig_prefixes:
        return stig_prefixes.most_common(1)[0][0], 'stig'

    return None, None


def find_rule_definitions(repo_path, prefix, benchmark_type):
    """Find all rule toggle variables in defaults/main.yml."""
    defaults_file = os.path.join(repo_path, 'defaults', 'main.yml')
    rules = {}

    if benchmark_type == 'stig':
        pattern = re.compile(
            rf'^({re.escape(prefix)}_\d{{6}})\s*:', re.IGNORECASE)
    else:
        pattern = re.compile(
            rf'^({re.escape(prefix)}_rule_[\d_]+)\s*:', re.IGNORECASE)

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
                        help='Rule toggle prefix (e.g. ubtu20cis, rhel_08). '
                             'Auto-detected if omitted.')
    parser.add_argument('--type', choices=['cis', 'stig'], default=None,
                        help='Benchmark type. Auto-detected if omitted.')
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    prefix = args.prefix
    bm_type = args.type

    if not prefix:
        prefix, detected_type = detect_prefix_and_type(args.repo_path)
        if not bm_type:
            bm_type = detected_type

    if not prefix:
        print("Error: Could not detect benchmark prefix. Use --prefix.",
              file=sys.stderr)
        sys.exit(1)

    if not bm_type:
        bm_type = 'cis'

    print(f"Benchmark prefix: {prefix}")
    print(f"Benchmark type:   {bm_type}")

    rules = find_rule_definitions(args.repo_path, prefix, bm_type)
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
