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
import tempfile
import re
import sys
from collections import Counter

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}

# Lockdown-convention orchestration files. Tasks in these files use
# include_tasks/import_tasks/set_fact for play wiring (not rule remediation),
# so they don't need rule-ID tags. Matched by basename so per-category
# tasks/Cat?/main.yml is covered alongside tasks/main.yml.
ORCHESTRATION_FILES = {
    "main.yml",
    "LE_audit_setup.yml",
    "audit_only.yml",
    "auditd.yml",
    "check_prereqs.yml",
    "fetch_audit_output.yml",
    "parse_etc_password.yml",
    "post_remediation_audit.yml",
    "pre_remediation_audit.yml",
    "prelim.yml",
    "warning_facts.yml",
}


def _defaults_view(role_path):
    """Return one readable path covering the role's defaults.

    Ansible accepts either defaults/main.yml or a defaults/main/ directory. For the
    directory shape, concatenate the files into a temporary view so callers that open
    a single path keep working. Line numbers in findings then refer to the
    concatenation rather than the individual file, which is the trade for having these
    checks run at all instead of silently reading nothing.
    """
    single = os.path.join(role_path, "defaults", "main.yml")
    if os.path.isfile(single):
        return single
    as_dir = os.path.join(role_path, "defaults", "main")
    if not os.path.isdir(as_dir):
        return single  # caller's isfile() guard reports it missing
    parts = []
    for name in sorted(os.listdir(as_dir)):
        if name.endswith((".yml", ".yaml")):
            with open(os.path.join(as_dir, name), encoding="utf-8") as fh:
                parts.append(fh.read())
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False,
                                      encoding="utf-8")
    tmp.write("\n".join(parts))
    tmp.close()
    return tmp.name


def detect_benchmark_type(repo_path):
    """Auto-detect benchmark type and prefix from defaults/main.yml."""
    defaults_file = _defaults_view(repo_path)
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
    """Parse tasks from a YAML file and extract tag information.

    Tracks block: nesting so that sub-tasks inside a tagged block are
    marked as inheriting those tags (in_tagged_block = True).
    """
    tasks = []
    rel = os.path.relpath(filepath, repo_path)

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # First pass: collect all tasks with their indent, tags, and block info
    raw_tasks = []
    i = 0
    while i < len(lines):
        line = lines[i]

        # Look for task start
        name_match = re.match(r"^(\s*)- name:\s*(.+)", line)
        if not name_match:
            i += 1
            continue

        name_indent = len(name_match.group(1))
        task_indent = name_indent + 2
        task_name = name_match.group(2).strip().strip("'\"")
        task_start = i

        # Scan task block for tags and block: key
        tags = []
        has_tags = False
        has_block = False
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

            # Detect block: key at the task's own indent level
            # Note: tstripped preserves trailing newline from lstrip(),
            # so use .strip() for exact string comparisons
            tclean = tstripped.strip()
            if tindent == task_indent and tclean == "block:":
                has_block = True

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

            # Block tags list (bare "tags:" on its own line)
            if tclean == "tags:":
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

        raw_tasks.append({
            "file": rel,
            "line": task_start + 1,
            "name": task_name,
            "has_tags": has_tags,
            "tags": tags,
            "name_indent": name_indent,
            "has_block": has_block,
        })

        i = end_of_task if end_of_task > i else i + 1

    # Second pass: determine block-tag inheritance
    # Stack of (name_indent, tags) for parent blocks that have tags
    block_stack = []

    for task in raw_tasks:
        # Pop blocks that are at the same or deeper indent (we've left them)
        while block_stack and block_stack[-1][0] >= task["name_indent"]:
            block_stack.pop()

        # Check if this task is inside a tagged block
        in_tagged_block = len(block_stack) > 0

        # If this task has a block with tags, push onto stack
        if task["has_block"] and task["has_tags"]:
            block_stack.append((task["name_indent"], task["tags"]))

        tasks.append({
            "file": task["file"],
            "line": task["line"],
            "name": task["name"],
            "has_tags": task["has_tags"],
            "tags": task["tags"],
            "in_tagged_block": in_tagged_block,
        })

    return tasks


def check_task_tags(task, benchmark_type, prefix, require_level, require_severity):
    """Check a task's tags for completeness. Returns list of issues."""
    issues = []

    # Prelim/setup tasks should have "always" tag
    is_prelim = bool(re.search(
        r"\b(PRELIM|SETUP|PRE.?AUDIT|POST.?AUDIT|GATHER)\b",
        task["name"], re.IGNORECASE))

    # Section includes and infrastructure tasks inherit tags from imported files
    is_section_include = bool(re.match(
        r"^(SECTION\s*\|)", task["name"], re.IGNORECASE))
    is_infra_task = bool(re.search(
        r"\b(Import\s+(preliminary|section)|flush\s+handlers?|"
        r"Include\s+(audit|section|pre-remediation)|"
        r"Run\s+(parse|post)|"
        r"Add\s+ansible\s+file|"
        r"Setup\s+rules|"
        r"If\s+Warning\s+count|"
        r"Fetch\s+audit|Show\s+Audit|Output\s+Warning|"
        r"POST\s*\|\s*(flush|reboot|FETCH))\b",
        task["name"], re.IGNORECASE))
    # File-level skip: tasks living in Lockdown-convention orchestration
    # files are play wiring, not rule remediation. The name-pattern checks
    # above only cover a subset of phrasings ("Run Cat 2 STIG 21xxxx tasks",
    # "Audit_Only | ...", etc. are missed) so we additionally allowlist
    # the file basename.
    is_orchestration_file = (
        os.path.basename(task["file"]) in ORCHESTRATION_FILES)

    if not task["has_tags"]:
        # Section includes and infra tasks don't need tags — they use
        # import_tasks which inherits tags from the imported file
        if is_section_include or is_infra_task or is_orchestration_file:
            return issues  # no issue
        # Sub-tasks inside a block: inherit tags from the parent block
        if task.get("in_tagged_block"):
            return issues  # no issue — tags inherited from parent block
        severity = "info" if is_prelim else "warning"
        issues.append({
            "type": "no_tags",
            "severity": severity,
            "message": "Task has no tags",
        })
        return issues

    tags_lower = [t.lower() for t in task["tags"]]

    # Check for rule ID tag — skip for infrastructure tasks
    # (tagged "always", section includes, infra orchestration tasks)
    if not is_prelim and "always" not in tags_lower \
            and not is_section_include and not is_infra_task \
            and not is_orchestration_file:
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
