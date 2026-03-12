#!/usr/bin/env python3
"""Check that all tasks have required tags for Ansible-Lockdown roles.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).
Auto-detects the benchmark type from defaults/main.yml.

Required tags vary by benchmark type:
- CIS:  rule ID tag (e.g. rule_1_1_1_1), level tag (level1-server, level2-workstation)
- STIG: rule ID tag (e.g. RHEL-08-010000), severity tag (CAT1, CAT2, CAT3)
- Both: automated/manual tag, "always" for prelim/setup tasks

Detection:
- Scans tasks/ for all tasks (- name:)
- Checks if each task has a tags: key
- For tagged tasks, checks for expected tag categories

Usage:
    python check_tags_completeness.py <repo_path> [--require-level]
                                       [--require-severity] [--prefix PREFIX]
"""

import argparse
import os
import re
import sys
from collections import Counter

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}


def detect_benchmark_type(repo_path):
    """Auto-detect benchmark type and prefix from defaults/main.yml."""
    defaults_file = os.path.join(repo_path, "defaults", "main.yml")
    if not os.path.isfile(defaults_file):
        return None, None

    cis_pattern = re.compile(r"^(\w+)_rule_\d")
    # STIG pattern A: prefix with 2-digit numeric segment (e.g. rhel_08_010000)
    stig_pattern_a = re.compile(r"^(\w+_\d{2})_(\d{6})\s*:")
    # STIG pattern B: prefix ending in "stig" + _6digits (e.g. az2023stig_001010)
    stig_pattern_b = re.compile(r"^(\w*stig)_(\d{6})\s*:", re.IGNORECASE)

    cis_prefixes = Counter()
    stig_prefixes = Counter()

    with open(defaults_file, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
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
        return cis_prefixes.most_common(1)[0][0], "cis"

    if stig_prefixes:
        return stig_prefixes.most_common(1)[0][0], "stig"

    return None, None


def find_task_files(repo_path):
    """Find all YAML task files."""
    files = []
    tasks_dir = os.path.join(repo_path, "tasks")
    if not os.path.isdir(tasks_dir):
        return files
    for root, dirs, filenames in os.walk(tasks_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith((".yml", ".yaml")):
                files.append(os.path.join(root, fname))
    return sorted(files)


def parse_tasks(filepath, repo_path):
    """Parse tasks from a YAML file and extract tag information."""
    tasks = []
    rel = os.path.relpath(filepath, repo_path)

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i]

        # Look for task start
        name_match = re.match(r"^(\s*)- name:\s*(.+)", line)
        if not name_match:
            i += 1
            continue

        task_indent = len(name_match.group(1)) + 2
        task_name = name_match.group(2).strip().strip("'\"")
        task_start = i

        # Scan task block for tags
        tags = []
        has_tags = False
        end_of_task = len(lines)

        j = i + 1
        while j < len(lines):
            tline = lines[j]
            tstripped = tline.lstrip()
            if not tstripped or tstripped.startswith("#"):
                j += 1
                continue

            tindent = len(tline) - len(tstripped)

            # Task boundary
            if tindent < task_indent:
                end_of_task = j
                break
            if tstripped.startswith("- ") and tindent <= task_indent - 2:
                end_of_task = j
                break

            # Inline tags: "tags: value" or "tags: [v1, v2]"
            tags_inline = re.match(r"\s*tags:\s+(.+)", tline)
            if tags_inline:
                has_tags = True
                val = tags_inline.group(1).strip()
                # Inline list: [tag1, tag2]
                if val.startswith("["):
                    inner = val.strip("[]")
                    tags.extend(t.strip().strip("'\"")
                                for t in inner.split(",") if t.strip())
                else:
                    tags.append(val.strip("'\""))

            # Block tags list
            if tstripped == "tags:":
                has_tags = True
                k = j + 1
                while k < len(lines):
                    tag_line = lines[k]
                    tag_stripped = tag_line.lstrip()
                    if tag_stripped.startswith("- "):
                        tag_indent = len(tag_line) - len(tag_stripped)
                        if tag_indent > tindent:
                            tag_val = tag_stripped[2:].strip().strip("'\"")
                            tags.append(tag_val)
                            k += 1
                            continue
                    break

            j += 1

        if j >= len(lines):
            end_of_task = len(lines)

        tasks.append({
            "file": rel,
            "line": task_start + 1,
            "name": task_name,
            "has_tags": has_tags,
            "tags": tags,
        })

        i = end_of_task if end_of_task > i else i + 1

    return tasks


def check_task_tags(task, benchmark_type, prefix, require_level, require_severity):
    """Check a task's tags for completeness. Returns list of issues."""
    issues = []

    # Prelim/setup tasks should have "always" tag
    is_prelim = bool(re.search(
        r"\b(PRELIM|SETUP|PRE.?AUDIT|POST.?AUDIT|GATHER)\b",
        task["name"], re.IGNORECASE))

    if not task["has_tags"]:
        severity = "info" if is_prelim else "warning"
        issues.append({
            "type": "no_tags",
            "severity": severity,
            "message": "Task has no tags",
        })
        return issues

    tags_lower = [t.lower() for t in task["tags"]]

    # Check for rule ID tag
    if not is_prelim:
        has_rule_id = False
        if benchmark_type == "cis":
            has_rule_id = any(re.match(r"rule_[\d_]+", t) for t in tags_lower)
        elif benchmark_type == "stig":
            # STIG tags like RHEL-08-010000 or the variable name
            has_rule_id = any(
                re.match(r"[a-z]+-\d{2}-\d{6}", t)
                or re.match(r"\w+_\d{6}", t)
                for t in tags_lower
            )

        if not has_rule_id and benchmark_type:
            issues.append({
                "type": "missing_rule_id",
                "severity": "warning",
                "message": f"No rule ID tag found (benchmark: {benchmark_type})",
            })

    # Check for level/severity tags
    if require_level and benchmark_type == "cis" and not is_prelim:
        level_tags = {"level1-server", "level1-workstation",
                      "level2-server", "level2-workstation"}
        if not any(t in level_tags for t in tags_lower):
            issues.append({
                "type": "missing_level",
                "severity": "info",
                "message": "No CIS level tag (level1-server, etc.)",
            })

    if require_severity and benchmark_type == "stig" and not is_prelim:
        cat_tags = {"cat1", "cat2", "cat3"}
        if not any(t in cat_tags for t in tags_lower):
            issues.append({
                "type": "missing_severity",
                "severity": "info",
                "message": "No STIG severity tag (CAT1/CAT2/CAT3)",
            })

    # Check prelim tasks have "always"
    if is_prelim and "always" not in tags_lower:
        issues.append({
            "type": "missing_always",
            "severity": "info",
            "message": "Prelim/setup task should have 'always' tag",
        })

    return issues


def main():
    parser = argparse.ArgumentParser(
        description="Check task tags completeness for Ansible-Lockdown roles")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--prefix", help="Rule toggle prefix (auto-detected)")
    parser.add_argument("--type", choices=["cis", "stig"], default=None,
                        help="Benchmark type (auto-detected)")
    parser.add_argument("--require-level", action="store_true",
                        help="Require CIS level tags (level1-server, etc.)")
    parser.add_argument("--require-severity", action="store_true",
                        help="Require STIG severity tags (CAT1/2/3)")
    parser.add_argument("--summary-only", action="store_true",
                        help="Show only summary counts, not individual issues")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    prefix = args.prefix
    bm_type = args.type

    if not prefix:
        prefix, detected_type = detect_benchmark_type(args.repo_path)
        if not bm_type:
            bm_type = detected_type

    print(f"Benchmark prefix: {prefix or '(not detected)'}")
    print(f"Benchmark type:   {bm_type or '(not detected)'}")

    files = find_task_files(args.repo_path)
    total_tasks = 0
    tasks_no_tags = 0
    tasks_with_issues = 0
    issue_counts = Counter()

    for filepath in files:
        tasks = parse_tasks(filepath, args.repo_path)
        for task in tasks:
            total_tasks += 1
            issues = check_task_tags(
                task, bm_type, prefix,
                args.require_level, args.require_severity)

            if not task["has_tags"]:
                tasks_no_tags += 1

            if issues:
                tasks_with_issues += 1
                for issue in issues:
                    issue_counts[issue["type"]] += 1
                    if not args.summary_only:
                        print(f"  [{issue['severity']}] {task['file']}:"
                              f"{task['line']} - {issue['message']}: "
                              f"{task['name'][:60]}")

    print(f"\n{'='*60}")
    print(f"Total tasks:          {total_tasks}")
    print(f"Tasks without tags:   {tasks_no_tags}")
    print(f"Tasks with issues:    {tasks_with_issues}")
    if issue_counts:
        print(f"\nIssue breakdown:")
        for issue_type, count in sorted(issue_counts.items()):
            print(f"  {issue_type}: {count}")

    has_warnings = any(
        k in issue_counts for k in ("no_tags", "missing_rule_id"))
    sys.exit(1 if has_warnings else 0)


if __name__ == "__main__":
    main()
