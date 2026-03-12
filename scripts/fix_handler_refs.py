#!/usr/bin/env python3
"""Find missing, unused, and duplicate handlers in Ansible-Lockdown roles.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Checks:
- Missing handlers: notify references with no matching handler definition
- Unused handlers: defined handlers that are never notified
- Duplicate handlers: multiple handlers with the same name
- Case mismatches: notify name differs only in case from handler name
- FQCN in handlers: bare module names in handler definitions

Usage:
    python fix_handler_refs.py <repo_path> [--fix-case] [--fix-fqcn]
"""

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}

# ansible.builtin modules (subset most commonly used in handlers)
ANSIBLE_BUILTIN_MODULES = {
    "command", "copy", "file", "lineinfile", "meta", "reboot",
    "replace", "service", "shell", "systemd", "systemd_service",
    "template", "mount", "apt", "dnf", "yum", "package",
    "blockinfile", "set_fact", "debug", "sysvinit",
}

TASK_KEYWORDS = {
    "name", "when", "register", "tags", "vars", "block", "rescue", "always",
    "become", "become_user", "become_method", "become_flags",
    "changed_when", "failed_when", "ignore_errors", "ignore_unreachable",
    "loop", "loop_control", "notify", "listen", "handler", "environment",
    "no_log", "retries", "delay", "until", "check_mode", "diff",
    "any_errors_fatal", "throttle", "timeout", "args", "async", "poll",
}


def find_handler_files(repo_path):
    """Find handler YAML files."""
    handlers_dir = os.path.join(repo_path, "handlers")
    if not os.path.isdir(handlers_dir):
        return []
    files = []
    for root, dirs, filenames in os.walk(handlers_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith((".yml", ".yaml")):
                files.append(os.path.join(root, fname))
    return sorted(files)


def find_task_files(repo_path):
    """Find task YAML files."""
    files = []
    for subdir in ("tasks",):
        dirpath = os.path.join(repo_path, subdir)
        if not os.path.isdir(dirpath):
            continue
        for root, dirs, filenames in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                if fname.endswith((".yml", ".yaml")):
                    files.append(os.path.join(root, fname))
    return sorted(files)


def extract_handler_definitions(handler_files, repo_path):
    """Extract handler names and their definitions."""
    handlers = {}  # name -> {"file": rel, "line": num, "module": str}
    duplicates = []

    for filepath in handler_files:
        rel = os.path.relpath(filepath, repo_path)
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for num, line in enumerate(lines, 1):
            m = re.match(r"\s*- name:\s*(.+)", line)
            if m:
                name = m.group(1).strip().strip("'\"")
                # Look ahead for the module used
                module = None
                for j in range(num, min(num + 10, len(lines))):
                    mod_m = re.match(r"\s+([a-z][a-z0-9_.]*\.[a-z0-9_.]+|[a-z][a-z0-9_]*):",
                                     lines[j])
                    if mod_m:
                        key = mod_m.group(1)
                        if key not in TASK_KEYWORDS:
                            module = key
                            break

                if name in handlers:
                    duplicates.append({
                        "name": name,
                        "file": rel,
                        "line": num,
                        "first_file": handlers[name]["file"],
                        "first_line": handlers[name]["line"],
                    })
                else:
                    handlers[name] = {
                        "file": rel,
                        "line": num,
                        "module": module,
                    }

    return handlers, duplicates


def extract_notify_references(task_files, repo_path):
    """Extract all notify references from task files."""
    refs = {}  # name -> [{"file": rel, "line": num}]

    for filepath in task_files:
        rel = os.path.relpath(filepath, repo_path)
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        in_notify_list = False
        notify_indent = 0

        for num, line in enumerate(lines, 1):
            stripped = line.lstrip()

            # Inline notify: "notify: Handler Name"
            m = re.match(r"\s*notify:\s+(.+)", line)
            if m:
                val = m.group(1).strip()
                if val.startswith("["):
                    # Inline list: notify: [A, B]
                    items = val.strip("[]").split(",")
                    for item in items:
                        name = item.strip().strip("'\"")
                        if name:
                            refs.setdefault(name, []).append(
                                {"file": rel, "line": num})
                elif val.startswith("-"):
                    pass  # Will be caught by list detection
                elif not val.startswith("{"):
                    name = val.strip("'\"")
                    if name:
                        refs.setdefault(name, []).append(
                            {"file": rel, "line": num})
                    in_notify_list = False
                continue

            # Start of notify list: "notify:"
            if re.match(r"\s*notify:\s*$", line):
                in_notify_list = True
                notify_indent = len(line) - len(stripped)
                continue

            # List item under notify
            if in_notify_list:
                indent = len(line) - len(stripped)
                if indent <= notify_indent and stripped:
                    in_notify_list = False
                elif stripped.startswith("- "):
                    name = stripped[2:].strip().strip("'\"")
                    if name:
                        refs.setdefault(name, []).append(
                            {"file": rel, "line": num})

    return refs


def check_fqcn_in_handlers(handler_files, repo_path):
    """Check for bare module names in handler definitions."""
    issues = []

    for filepath in handler_files:
        rel = os.path.relpath(filepath, repo_path)
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        task_indent = None
        for num, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                continue

            tm = re.match(r"^(\s*)- name:", line)
            if tm:
                task_indent = len(tm.group(1)) + 2
                continue

            if task_indent is not None:
                indent = len(line) - len(stripped)
                if indent < task_indent and stripped.startswith("- "):
                    task_indent = None
                    continue
                km = re.match(r"^(\s+)([a-z][a-z0-9_]*):\s", line)
                if km and len(km.group(1)) == task_indent:
                    key = km.group(2)
                    if key in ANSIBLE_BUILTIN_MODULES and key not in TASK_KEYWORDS:
                        issues.append({
                            "file": rel,
                            "line": num,
                            "bare": key,
                            "fqcn": f"ansible.builtin.{key}",
                        })

    return issues


def main():
    parser = argparse.ArgumentParser(
        description="Find handler issues in Ansible-Lockdown roles")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix-case", action="store_true",
                        help="Fix case mismatches in notify references")
    parser.add_argument("--fix-fqcn", action="store_true",
                        help="Fix bare module names in handlers")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    handler_files = find_handler_files(args.repo_path)
    task_files = find_task_files(args.repo_path)

    handlers, duplicates = extract_handler_definitions(handler_files, args.repo_path)
    refs = extract_notify_references(task_files, args.repo_path)

    total_issues = 0

    # Check for duplicates
    if duplicates:
        print("\nDuplicate Handlers:")
        for dup in duplicates:
            total_issues += 1
            print(f"  [warning] {dup['file']}:{dup['line']} "
                  f"- Duplicate handler '{dup['name']}' "
                  f"(first at {dup['first_file']}:{dup['first_line']})")

    # Check for missing handlers
    handler_names_lower = {n.lower(): n for n in handlers}
    missing = []
    case_mismatches = []
    for ref_name, locations in refs.items():
        if ref_name not in handlers:
            low = ref_name.lower()
            if low in handler_names_lower:
                case_mismatches.append({
                    "notify_name": ref_name,
                    "handler_name": handler_names_lower[low],
                    "locations": locations,
                })
            else:
                missing.append({"name": ref_name, "locations": locations})

    if missing:
        print("\nMissing Handlers (notify references with no definition):")
        for m in missing:
            total_issues += 1
            loc = m["locations"][0]
            count = len(m["locations"])
            print(f"  [error] {loc['file']}:{loc['line']} "
                  f"- Missing handler: '{m['name']}' ({count} reference(s))")

    if case_mismatches:
        print("\nCase Mismatches:")
        for cm in case_mismatches:
            total_issues += 1
            loc = cm["locations"][0]
            print(f"  [warning] {loc['file']}:{loc['line']} "
                  f"- Case mismatch: notify '{cm['notify_name']}' "
                  f"vs handler '{cm['handler_name']}'")

    # Check for unused handlers
    notified_names = set(refs.keys())
    notified_lower = {n.lower() for n in notified_names}
    unused = []
    for name, info in handlers.items():
        # Check both exact and case-insensitive
        if name not in notified_names and name.lower() not in notified_lower:
            unused.append({"name": name, **info})

    if unused:
        print("\nUnused Handlers (defined but never notified):")
        for u in unused:
            total_issues += 1
            print(f"  [info] {u['file']}:{u['line']} "
                  f"- Unused handler: '{u['name']}'")

    # Check FQCN in handlers
    fqcn_issues = check_fqcn_in_handlers(handler_files, args.repo_path)
    if fqcn_issues:
        print("\nBare Module Names in Handlers:")
        for issue in fqcn_issues:
            total_issues += 1
            print(f"  [warning] {issue['file']}:{issue['line']} "
                  f"- {issue['bare']} -> {issue['fqcn']}")

    # Summary
    print(f"\n{'='*60}")
    print(f"Handlers defined:   {len(handlers)}")
    print(f"Notify references:  {sum(len(v) for v in refs.values())}")
    print(f"Total issues:       {total_issues}")
    print(f"  Missing:          {len(missing)}")
    print(f"  Duplicates:       {len(duplicates)}")
    print(f"  Case mismatches:  {len(case_mismatches)}")
    print(f"  Unused:           {len(unused)}")
    print(f"  Bare FQCN:        {len(fqcn_issues)}")

    sys.exit(1 if missing or duplicates else 0)


if __name__ == "__main__":
    main()
