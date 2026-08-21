#!/usr/bin/env python3
"""Report ansible.builtin.shell tasks missing Lockdown pipefail layout.

Every ansible.builtin.shell task should have:
  1. set -o pipefail as the first line of the shell block (or inline)
  2. args: executable: "{{ <prefix>_shell_executable }}"

Detection reuses fix_shell_pipefail.scan_file (read-only).

Usage:
    python check_shell_pipefail.py <role_path>
    python check_shell_pipefail.py --all <cis_or_stig_root>
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import sys
from dataclasses import dataclass, field

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SHELL_EXECUTABLE_RE = re.compile(r"^(\w+_shell_executable)\s*:")


@dataclass
class Issue:
    severity: str  # error | warning
    message: str
    file: str = ""
    line: int = 0


@dataclass
class RoleReport:
    role_path: str
    exec_var: str | None = None
    issues: list[Issue] = field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(1 for i in self.issues if i.severity == "error")

    @property
    def warnings(self) -> int:
        return sum(1 for i in self.issues if i.severity == "warning")


def _load_scan_module():
    path = os.path.join(SCRIPT_DIR, "fix_shell_pipefail.py")
    spec = importlib.util.spec_from_file_location("fix_shell_pipefail", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fix_shell_pipefail"] = mod
    spec.loader.exec_module(mod)
    return mod



def _defaults_files(role_path):
    """defaults/main.yml, or every YAML file in a defaults/main/ directory.

    Ansible accepts either shape; sorted to match its alphabetical load order.
    """
    _b = os.path.join(role_path, "defaults")
    _s = os.path.join(_b, "main.yml")
    if os.path.isfile(_s):
        return [_s]
    _d = os.path.join(_b, "main")
    if os.path.isdir(_d):
        return sorted(os.path.join(_d, f) for f in os.listdir(_d)
                      if f.endswith((".yml", ".yaml")))
    return []

def discover_shell_executable_var(role_path: str) -> str | None:
    candidates = [os.path.join(role_path, "vars", "main.yml")]
    candidates += _defaults_files(role_path)
    for fpath in candidates:
        if not os.path.isfile(fpath):
            continue
        with open(fpath, encoding="utf-8") as fh:
            for line in fh:
                m = SHELL_EXECUTABLE_RE.match(line)
                if m:
                    return m.group(1)
    return None


def _find_roles(root: str) -> list[str]:
    roles: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in {".git", "__pycache__", ".github", "collections", "molecule"}
        ]
        if (os.path.basename(dirpath) == "defaults"
                and ("main.yml" in filenames or "main" in dirnames)):
            role = os.path.dirname(dirpath)
            if os.path.isdir(os.path.join(role, "tasks")):
                roles.append(role)
    return sorted(roles)


def check_role(role_path: str, scan_mod) -> RoleReport:
    role_path = os.path.abspath(role_path)
    report = RoleReport(role_path=role_path)
    exec_var = discover_shell_executable_var(role_path)
    report.exec_var = exec_var

    tasks_dir = os.path.join(role_path, "tasks")
    if not os.path.isdir(tasks_dir):
        report.issues.append(Issue(
            severity="error",
            message="tasks/ directory not found",
            file="tasks/",
        ))
        return report

    if not exec_var:
        report.issues.append(Issue(
            severity="warning",
            message="No *_shell_executable variable in vars/main.yml or the role defaults",
            file="vars/main.yml",
        ))

    for filepath in scan_mod.find_yaml_files(tasks_dir):
        rel = os.path.relpath(filepath, role_path)
        try:
            _lines, fixes, warnings = scan_mod.scan_file(filepath)
        except OSError as exc:
            report.issues.append(Issue(
                severity="error",
                message=f"Cannot read file: {exc}",
                file=rel,
            ))
            continue

        for warn in warnings:
            report.issues.append(Issue(
                severity="warning",
                message="set -o pipefail present but not first content line",
                file=rel,
                line=warn["line_idx"] + 1,
            ))

        for fix in fixes:
            line = fix["line_idx"] + 1
            parts: list[str] = []
            if fix.get("needs_block_indicator"):
                parts.append("missing block scalar indicator (|)")
            if fix.get("needs_pipefail"):
                parts.append("missing set -o pipefail")
            if not fix.get("has_args"):
                parts.append(
                    f'missing args: executable: "{{{{ {exec_var or "<prefix>_shell_executable"} }}}}"'
                )
            report.issues.append(Issue(
                severity="error",
                message="; ".join(parts),
                file=rel,
                line=line,
            ))

        if exec_var:
            with open(filepath, encoding="utf-8") as fh:
                file_lines = fh.readlines()
            report.issues.extend(
                _wrong_executable_var_issues(rel, exec_var, file_lines)
            )
            # scan_file already reports the Case D shell line above; pass those
            # line numbers so args.cmd findings are not double-counted.
            reported_lines = {fix["line_idx"] + 1 for fix in fixes}
            report.issues.extend(
                _args_cmd_shell_issues(rel, file_lines, scan_mod, reported_lines)
            )

    return report


def _args_cmd_shell_issues(
    rel: str,
    lines: list[str],
    scan_mod,
    reported_lines: set[int] | None = None,
) -> list[Issue]:
    """Flag shell tasks that still use args.cmd or an empty shell body."""
    reported_lines = reported_lines or set()
    issues: list[Issue] = []
    shell_re = re.compile(r"^(\s+)ansible\.builtin\.shell:")
    i = 0
    while i < len(lines):
        m = shell_re.match(lines[i])
        if not m:
            i += 1
            continue
        if (i + 1) in reported_lines:
            i += 1
            continue
        shell_indent = len(m.group(1))
        body = scan_mod.collect_shell_body_commands(lines, i, shell_indent)
        args_cmd = scan_mod.find_args_cmd(lines, i, shell_indent)
        if args_cmd:
            issues.append(Issue(
                severity="error",
                message="shell command must be in the shell block, not args.cmd",
                file=rel,
                line=i + 1,
            ))
        elif body and not scan_mod.task_has_shell_command(body):
            issues.append(Issue(
                severity="error",
                message="shell block contains pipefail but no command",
                file=rel,
                line=i + 1,
            ))
        i += 1
    return issues


def _wrong_executable_var_issues(
    rel: str,
    exec_var: str,
    lines: list[str],
) -> list[Issue]:
    """Flag shell tasks whose args.executable does not reference exec_var."""
    issues: list[Issue] = []
    shell_re = re.compile(r"^\s+ansible\.builtin\.shell:")
    i = 0
    while i < len(lines):
        if not shell_re.match(lines[i]):
            i += 1
            continue
        shell_line = i + 1
        has_executable = False
        wrong_var = False
        for j in range(i + 1, len(lines)):
            if re.match(r"\s*- name:", lines[j]):
                break
            if "executable:" in lines[j]:
                has_executable = True
                if exec_var not in lines[j]:
                    wrong_var = True
                break
        if has_executable and wrong_var:
            issues.append(Issue(
                severity="error",
                message=f'args.executable should reference "{exec_var}"',
                file=rel,
                line=shell_line,
            ))
        i += 1
    return issues


def _print_report(report: RoleReport, *, compact: bool = False) -> None:
    role_name = os.path.basename(report.role_path)
    if compact:
        status = "OK" if not report.issues else "ISSUES"
        print(
            f"{report.role_path}\t{status}\t"
            f"errors={report.errors} warnings={report.warnings}"
        )
        return

    print(f"Shell Pipefail Check — {role_name}")
    print("=" * (22 + len(role_name)))
    print(f"Path: {report.role_path}")
    if report.exec_var:
        print(f"Expected executable var: {report.exec_var}")

    if not report.issues:
        print("Result: OK")
        return

    for issue in report.issues:
        label = issue.severity.upper()
        loc = f"{issue.file}:{issue.line}" if issue.line else issue.file
        print(f"  [{label}] {loc}: {issue.message}")

    print(f"Result: {report.errors} error(s), {report.warnings} warning(s)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check ansible.builtin.shell pipefail and args.executable layout",
    )
    parser.add_argument(
        "path",
        help="Role directory, or CIS/STIG root when used with --all",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan every Ansible role under path",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="With --all, print one tab-separated line per role",
    )
    args = parser.parse_args()

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"Error: not a directory: {root}", file=sys.stderr)
        sys.exit(2)

    scan_mod = _load_scan_module()

    if args.all:
        roles = _find_roles(root)
        if not roles:
            print(f"No roles found under {root}", file=sys.stderr)
            sys.exit(2)
        reports = [check_role(role, scan_mod) for role in roles]
        for report in reports:
            _print_report(report, compact=args.compact)
            if not args.compact and report is not reports[-1]:
                print()
        sys.exit(1 if any(r.issues for r in reports) else 0)

    if not _defaults_files(root):
        print(f"Error: {root} does not look like a role (no defaults/main.yml)", file=sys.stderr)
        sys.exit(2)

    report = check_role(root, scan_mod)
    _print_report(report)
    sys.exit(1 if report.issues else 0)


if __name__ == "__main__":
    main()
