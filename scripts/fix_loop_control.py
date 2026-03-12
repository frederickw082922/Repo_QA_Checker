#!/usr/bin/env python3
"""Find and optionally fix loop tasks missing loop_control.label.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Without loop_control.label, Ansible dumps the entire loop item to stdout
on each iteration. This can leak sensitive data (passwords, hashes) and
produces unreadable output. Adding `loop_control: label: "{{ item.name }}"
(or similar) keeps output clean and safe.

Detection:
- Finds tasks with `loop:` or `with_items:` / `with_dict:` etc.
- Checks if task block contains `loop_control:` with a `label:` key
- Flags tasks missing it

Fix mode adds a sensible default:
    loop_control:
        label: "{{ item }}"

For `with_dict:` loops it uses: "{{ item.key }}"

Usage:
    python fix_loop_control.py <repo_path> [--fix] [--label LABEL]
"""

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}
SEARCH_DIRS = ("tasks", "handlers")
EXTENSIONS = {".yml", ".yaml"}

# Loop keywords
LOOP_KEYWORDS = {
    "loop", "with_items", "with_list", "with_dict", "with_fileglob",
    "with_filetree", "with_together", "with_subelements",
    "with_nested", "with_sequence", "with_lines",
}


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
    """Scan a file for loop tasks missing loop_control.label."""
    issues = []
    rel = os.path.relpath(filepath, repo_path)

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i]

        # Look for task start: "- name:"
        name_match = re.match(r"^(\s*)- name:\s*(.+)", line)
        if not name_match:
            i += 1
            continue

        task_indent = len(name_match.group(1)) + 2
        task_name = name_match.group(2).strip().strip("'\"")
        task_start = i

        # Scan the task block
        has_loop = False
        loop_keyword = None
        loop_line_idx = None
        has_loop_control = False
        has_label = False
        end_of_task = len(lines)
        last_task_line = i

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

            last_task_line = j

            # Check for loop keyword
            for kw in LOOP_KEYWORDS:
                if tstripped.startswith(f"{kw}:"):
                    has_loop = True
                    loop_keyword = kw
                    loop_line_idx = j
                    break

            if tstripped.startswith("loop_control:"):
                has_loop_control = True
            if has_loop_control and tstripped.startswith("label:"):
                has_label = True

            j += 1

        if j >= len(lines):
            end_of_task = len(lines)

        if has_loop and not has_label:
            issues.append({
                "file": rel,
                "line": task_start + 1,
                "task_name": task_name,
                "loop_keyword": loop_keyword,
                "has_loop_control": has_loop_control,
                "loop_line_idx": loop_line_idx,
                "last_task_line": last_task_line,
                "task_indent": task_indent,
            })

        i = end_of_task if end_of_task > i else i + 1

    return issues


def apply_fixes(filepath, issues, custom_label=None):
    """Add loop_control.label to loop tasks missing it."""
    if not issues:
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Process in reverse to preserve line numbers
    for issue in sorted(issues, key=lambda i: i["last_task_line"], reverse=True):
        indent = " " * issue["task_indent"]
        insert_idx = issue["last_task_line"] + 1

        if custom_label:
            label = custom_label
        elif issue["loop_keyword"] == "with_dict":
            label = '"{{ item.key }}"'
        else:
            label = '"{{ item }}"'

        if issue["has_loop_control"]:
            # loop_control exists but no label — find it and add label inside
            for k in range(issue["last_task_line"], issue["line"] - 2, -1):
                if k < len(lines) and "loop_control:" in lines[k]:
                    lc_indent = len(lines[k]) - len(lines[k].lstrip())
                    label_line = f"{' ' * (lc_indent + 2)}label: {label}\n"
                    lines.insert(k + 1, label_line)
                    break
        else:
            # Add both loop_control and label
            lc_line = f"{indent}loop_control:\n"
            label_line = f"{indent}    label: {label}\n"
            lines.insert(insert_idx, label_line)
            lines.insert(insert_idx, lc_line)

    with open(filepath, "w", encoding="utf-8") as f:
        f.writelines(lines)

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Find and fix loop tasks missing loop_control.label")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix", action="store_true",
                        help="Apply fixes automatically")
    parser.add_argument("--label", default=None,
                        help='Custom label expression (default: "{{ item }}")')
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
                extra = " (has loop_control but no label)" \
                    if issue["has_loop_control"] else ""
                print(f"  [warning] {issue['file']}:{issue['line']} "
                      f"- {issue['loop_keyword']}: missing loop_control.label"
                      f"{extra}: {issue['task_name'][:60]}")

            if args.fix:
                if apply_fixes(filepath, issues, args.label):
                    rel = os.path.relpath(filepath, args.repo_path)
                    print(f"  FIXED: {rel} ({len(issues)} task(s))")

    print(f"\n{'='*60}")
    print(f"Total loops missing loop_control.label: {total_issues}")
    if not args.fix and total_issues > 0:
        print("Run with --fix to add loop_control.label")

    sys.exit(1 if total_issues > 0 and not args.fix else 0)


if __name__ == "__main__":
    main()
