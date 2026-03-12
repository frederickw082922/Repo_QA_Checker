#!/usr/bin/env python3
"""Find and optionally fix non-FQCN (bare) Ansible module names in task/handler files.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Converts bare module names to fully qualified collection names:
    template:  ->  ansible.builtin.template:
    copy:      ->  ansible.builtin.copy:
    shell:     ->  ansible.builtin.shell:

Usage:
    python fix_fqcn.py <repo_path> [--fix] [--exclude-path PATH ...]
"""

import argparse
import os
import re
import sys

# Known ansible.builtin module short names
ANSIBLE_BUILTIN_MODULES = {
    "add_host", "apt", "apt_key", "apt_repository", "assemble", "assert",
    "async_status", "blockinfile", "command", "copy", "cron",
    "debug", "dnf", "dpkg_selections",
    "expect", "fail", "fetch", "file", "find",
    "gather_facts", "get_url", "getent", "git", "group", "group_by",
    "hostname",
    "import_playbook", "import_role", "import_tasks",
    "include_role", "include_tasks", "include_vars",
    "iptables", "known_hosts", "lineinfile",
    "meta", "mount",
    "package", "package_facts", "pause", "ping", "pip",
    "raw", "reboot", "replace", "rpm_key",
    "script", "service", "service_facts", "set_fact", "set_stats",
    "setup", "shell", "slurp", "stat", "subversion",
    "systemd", "systemd_service", "sysvinit",
    "tempfile", "template", "unarchive", "uri", "user",
    "validate_argument_spec", "wait_for", "wait_for_connection",
    "yum", "yum_repository",
}

# Task-level keywords that are NOT module names
TASK_KEYWORDS = {
    "name", "when", "register", "tags", "vars", "block", "rescue", "always",
    "become", "become_user", "become_method", "become_flags",
    "changed_when", "failed_when", "ignore_errors", "ignore_unreachable",
    "loop", "loop_control", "with_items", "with_dict", "with_list",
    "with_fileglob", "with_first_found", "with_together", "with_sequence",
    "notify", "listen", "handler", "environment",
    "no_log", "retries", "delay", "until", "check_mode", "diff",
    "any_errors_fatal", "throttle", "timeout", "collections",
    "module_defaults", "run_once", "delegate_to", "delegate_facts",
    "connection", "args", "async", "poll",
    "action", "local_action", "debugger",
}

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}


def find_files(repo_path, exclude_paths):
    """Find all YAML files under tasks/ and handlers/."""
    files = []
    for subdir in ("tasks", "handlers"):
        dirpath = os.path.join(repo_path, subdir)
        if not os.path.isdir(dirpath):
            continue
        for root, dirs, filenames in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                if fname.endswith((".yml", ".yaml")):
                    filepath = os.path.join(root, fname)
                    rel = os.path.relpath(filepath, repo_path)
                    if not any(rel.startswith(ep) for ep in exclude_paths):
                        files.append(filepath)
    return sorted(files)


def scan_file(filepath, repo_path):
    """Scan a file for bare module names. Returns list of issues."""
    issues = []
    rel = os.path.relpath(filepath, repo_path)

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    task_indent = None
    for num, raw in enumerate(lines, 1):
        stripped = raw.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(stripped)

        # Detect task start: "  - name:"
        tm = re.match(r"^(\s*)- name:", raw)
        if tm:
            task_indent = len(tm.group(1)) + 2
            continue

        # Detect unnamed task: "  - bare_module:"
        um = re.match(r"^(\s*)- ([a-z][a-z0-9_]*):", raw)
        if um:
            task_indent = len(um.group(1)) + 2
            key = um.group(2)
            if key in ANSIBLE_BUILTIN_MODULES and key not in TASK_KEYWORDS:
                issues.append({
                    "file": rel,
                    "line": num,
                    "bare": key,
                    "fqcn": f"ansible.builtin.{key}",
                    "pattern": "unnamed_task",
                })
            continue

        if task_indent is None:
            continue

        # Reset on task boundary
        if indent < task_indent and stripped.startswith("- "):
            task_indent = None
            continue

        # Check for bare module at task level
        km = re.match(r"^(\s+)([a-z][a-z0-9_]*):\s", raw)
        if km and len(km.group(1)) == task_indent:
            key = km.group(2)
            if key in ANSIBLE_BUILTIN_MODULES and key not in TASK_KEYWORDS:
                issues.append({
                    "file": rel,
                    "line": num,
                    "bare": key,
                    "fqcn": f"ansible.builtin.{key}",
                    "pattern": "named_task",
                })

    return issues


def apply_fixes(filepath, issues):
    """Replace bare module names with FQCN in a file."""
    if not issues:
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    modified = False
    # Process in reverse line order to preserve line numbers
    for issue in sorted(issues, key=lambda i: i["line"], reverse=True):
        idx = issue["line"] - 1
        old_line = lines[idx]
        if issue["pattern"] == "unnamed_task":
            new_line = old_line.replace(
                f"- {issue['bare']}:", f"- {issue['fqcn']}:", 1)
        else:
            # Named task: replace the indented module key
            new_line = re.sub(
                rf"^(\s+){re.escape(issue['bare'])}:",
                rf"\1{issue['fqcn']}:",
                old_line, count=1)
        if new_line != old_line:
            lines[idx] = new_line
            modified = True

    if modified:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)

    return modified


def main():
    parser = argparse.ArgumentParser(
        description="Find and fix non-FQCN module names in Ansible-Lockdown roles")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix", action="store_true", help="Apply fixes automatically")
    parser.add_argument("--exclude-path", nargs="*", default=[],
                        help="Relative paths to exclude (e.g. molecule/)")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    exclude_paths = set(args.exclude_path) | {"molecule/"}
    files = find_files(args.repo_path, exclude_paths)
    total_issues = 0
    total_fixed = 0

    for filepath in files:
        issues = scan_file(filepath, args.repo_path)
        if issues:
            rel = os.path.relpath(filepath, args.repo_path)
            for issue in issues:
                total_issues += 1
                print(f"  [warning] {issue['file']}:{issue['line']} "
                      f"- {issue['bare']} -> {issue['fqcn']}")

            if args.fix:
                if apply_fixes(filepath, issues):
                    total_fixed += len(issues)
                    print(f"  FIXED: {rel} ({len(issues)} module(s))")

    print(f"\n{'='*60}")
    print(f"Total bare modules: {total_issues}")
    if args.fix:
        print(f"Total fixed: {total_fixed}")
    elif total_issues > 0:
        print("Run with --fix to apply automatic fixes")

    sys.exit(1 if total_issues > 0 and not args.fix else 0)


if __name__ == "__main__":
    main()
