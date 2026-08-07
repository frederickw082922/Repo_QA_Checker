#!/usr/bin/env python3
"""Check audit variable placement across Lockdown remediation roles.

User-overridable audit toggles belong in defaults/main.yml (lowest precedence).
Role-internal audit constants belong in vars/audit.yml (higher precedence).

Canonical split follows Private-RHEL10-CIS (defaults + vars/audit.yml).

Usage:
    python check_audit_vars.py <role_path>
    python check_audit_vars.py --all <cis_or_stig_root>
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field

# Must be overridable from molecule, inventory, or playbook vars.
DEFAULTS_VARS = frozenset({
    "setup_audit",
    "run_audit",
    "audit_only",
    "fetch_audit_output",
    "audit_output_collection_method",
    "audit_output_destination",
    "audit_run_heavy_tests",
})

# Role-internal; should not live in defaults/main.yml.
VARS_AUDIT_VARS = frozenset({
    "audit_cmd_timeout",
    "get_audit_binary_method",
    "audit_bin_copy_location",
    "audit_max_concurrent",
    "audit_content",
    "audit_bin_validate_certs",
    "audit_conf_source",
    "audit_conf_dest",
    "audit_log_dir",
    "audit_bin_url",
    "audit_file_git",
    "audit_git_version",
    "audit_conf_dir",
    "pre_audit_outfile",
    "post_audit_outfile",
    "audit_bin_version",
    "audit_bin_path",
    "audit_bin",
    "audit_format",
    "audit_vars_path",
    "audit_results",
})

TOP_LEVEL_KEY = re.compile(r"^([a-zA-Z_][\w.-]*)\s*:")
MOLECULE_FILES = (
    "molecule/default/converge.yml",
    "molecule/default/molecule.yml",
    "molecule/default/prepare.yml",
    "molecule/default/verify.yml",
)

OLD_BRIDGE = "templates/ansible_vars_goss.yml.j2"
NEW_BRIDGE = "templates/lockdown_audit.yml.j2"


@dataclass
class Issue:
    check: str
    severity: str  # error | warning | info
    message: str
    file: str = ""
    line: int = 0


@dataclass
class RoleReport:
    role_path: str
    issues: list[Issue] = field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(1 for i in self.issues if i.severity == "error")

    @property
    def warnings(self) -> int:
        return sum(1 for i in self.issues if i.severity == "warning")


def _read_lines(path: str) -> list[str] | None:
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return handle.readlines()


def _top_level_keys(lines: list[str]) -> dict[str, int]:
    """Map top-level YAML keys to 1-based line numbers."""
    keys: dict[str, int] = {}
    for index, line in enumerate(lines, 1):
        if line.startswith((" ", "\t")) or not line.strip():
            continue
        if line.lstrip().startswith("#"):
            continue
        match = TOP_LEVEL_KEY.match(line)
        if match:
            keys[match.group(1)] = index
    return keys


def _molecule_var_refs(role_path: str) -> dict[str, list[str]]:
    """Find play/host var assignments in molecule YAML files.

    Assignments inside a ``set_fact:`` block are excluded: set_fact has
    precedence 19, which DOES override the ``include_vars`` (precedence 18)
    that loads ``vars/audit.yml``, so it is a legitimate way to override an
    audit var from molecule and must not be flagged by CHECK C.
    """
    set_fact_re = re.compile(r"(^|\.)set_fact\s*:")
    refs: dict[str, list[str]] = {}
    for rel in MOLECULE_FILES:
        path = os.path.join(role_path, rel)
        lines = _read_lines(path)
        if lines is None:
            continue
        set_fact_indent: int | None = None
        for index, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            # Leave the set_fact scope once indentation returns to its level.
            if set_fact_indent is not None and indent <= set_fact_indent:
                set_fact_indent = None
            if set_fact_re.search(stripped):
                set_fact_indent = indent
                continue
            if set_fact_indent is not None:
                continue  # child of a set_fact block -> legitimate override
            match = re.match(r"^\s+([a-zA-Z_][\w.-]*)\s*:", line)
            if match:
                name = match.group(1)
                refs.setdefault(name, []).append(f"{rel}:{index}")
    return refs


def _find_roles(root: str) -> list[str]:
    roles: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in {".git", "__pycache__", "node_modules", ".github"}
        ]
        if "main.yml" in filenames and os.path.basename(dirpath) == "defaults":
            role = os.path.dirname(dirpath)
            if os.path.isdir(os.path.join(role, "tasks")):
                roles.append(role)
    return sorted(roles)


def check_role(role_path: str) -> RoleReport:
    role_path = os.path.abspath(role_path)
    report = RoleReport(role_path=role_path)

    defaults_path = os.path.join(role_path, "defaults", "main.yml")
    audit_vars_path = os.path.join(role_path, "vars", "audit.yml")

    defaults_lines = _read_lines(defaults_path)
    if defaults_lines is None:
        report.issues.append(Issue(
            check="structure",
            severity="warning",
            message="defaults/main.yml not found",
            file="defaults/main.yml",
        ))
        return report

    defaults_keys = _top_level_keys(defaults_lines)
    audit_lines = _read_lines(audit_vars_path)
    audit_keys = _top_level_keys(audit_lines) if audit_lines is not None else {}

    audit_related = (
        set(defaults_keys) | set(audit_keys)
    ) & (DEFAULTS_VARS | VARS_AUDIT_VARS)

    if not audit_related:
        report.issues.append(Issue(
            check="presence",
            severity="warning",
            message="No canonical audit variables found in defaults/main.yml or vars/audit.yml",
            file="defaults/main.yml",
        ))

    if audit_lines is None:
        report.issues.append(Issue(
            check="structure",
            severity="info",
            message="vars/audit.yml not present (acceptable for older roles)",
            file="vars/audit.yml",
        ))

    # Check A — user-overridable vars must not be in vars/audit.yml
    for name in sorted(DEFAULTS_VARS & set(audit_keys)):
        report.issues.append(Issue(
            check="A",
            severity="warning",
            message=(
                f"{name} in vars/audit.yml "
                "(move to defaults/main.yml; molecule cannot override role vars)"
            ),
            file="vars/audit.yml",
            line=audit_keys[name],
        ))

    # Check B — internal constants should not be in defaults/main.yml
    for name in sorted(VARS_AUDIT_VARS & set(defaults_keys)):
        report.issues.append(Issue(
            check="B",
            severity="warning",
            message=(
                f"{name} in defaults/main.yml "
                "(move to vars/audit.yml; role-internal constant)"
            ),
            file="defaults/main.yml",
            line=defaults_keys[name],
        ))

    # Duplicate definitions — vars/audit.yml wins over defaults
    for name in sorted(DEFAULTS_VARS & set(defaults_keys) & set(audit_keys)):
        report.issues.append(Issue(
            check="dup",
            severity="warning",
            message=(
                f"{name} defined in both defaults/main.yml and vars/audit.yml "
                "(vars wins; defaults entry is dead)"
            ),
            file="vars/audit.yml",
            line=audit_keys[name],
        ))

    # Check C — molecule cannot override vars/audit.yml entries.
    # Canonical role-internal constants (VARS_AUDIT_VARS, e.g. audit_git_version)
    # are *supposed* to live in vars/audit.yml - that placement is the fleet-wide
    # CIS/STIG convention - so a molecule reference to them is not a placement
    # defect and must not be flagged here. The correct way to override such a var
    # from molecule is --extra-vars or set_fact (both outrank include_vars), not a
    # play/host var. Only non-canonical keys parked in vars/audit.yml are flagged.
    molecule_refs = _molecule_var_refs(role_path)
    for name in sorted((set(audit_keys) & set(molecule_refs)) - VARS_AUDIT_VARS):
        locations = ", ".join(molecule_refs[name])
        report.issues.append(Issue(
            check="C",
            severity="warning",
            message=(
                f"{name} in vars/audit.yml and molecule ({locations}); "
                "molecule override is ignored"
            ),
            file="vars/audit.yml",
            line=audit_keys.get(name, 0),
        ))

    # Check D — canonical variables missing from both files
    combined = set(defaults_keys) | set(audit_keys)
    for name in sorted((DEFAULTS_VARS | VARS_AUDIT_VARS) - combined):
        report.issues.append(Issue(
            check="D",
            severity="warning",
            message=f"{name} missing from defaults/main.yml and vars/audit.yml",
            file="defaults/main.yml",
        ))

    # Check E — bridge template filename
    old_bridge = os.path.join(role_path, OLD_BRIDGE)
    new_bridge = os.path.join(role_path, NEW_BRIDGE)
    if os.path.isfile(old_bridge):
        # Warning, not error: the lockdown_audit.yml.j2 rename is not yet a
        # fleet-wide convention (most roles still ship the legacy name), so an
        # error here would fail nearly every role in the shared QA suite.
        report.issues.append(Issue(
            check="E",
            severity="warning",
            message=f"{OLD_BRIDGE} present; rename to {NEW_BRIDGE}",
            file=OLD_BRIDGE,
        ))
    elif not os.path.isfile(new_bridge) and audit_lines is not None:
        report.issues.append(Issue(
            check="E",
            severity="warning",
            message=f"Neither {NEW_BRIDGE} nor legacy bridge template found",
            file=NEW_BRIDGE,
        ))

    return report


def _print_report(report: RoleReport, *, compact: bool = False) -> None:
    role_name = os.path.basename(report.role_path)
    if compact:
        status = "OK" if not report.issues else "ISSUES"
        counts = f"errors={report.errors} warnings={report.warnings}"
        print(f"{report.role_path}\t{status}\t{counts}")
        return

    print(f"Audit Variables Check — {role_name}")
    print("=" * (26 + len(role_name)))
    print(f"Path: {report.role_path}")

    if not report.issues:
        print("Result: OK")
        return

    for issue in report.issues:
        label = issue.severity.upper()
        print(f"  [{label}] CHECK {issue.check}: {issue.message}")

    print(
        f"Result: {report.errors} error(s), {report.warnings} warning(s)"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check audit variable placement (defaults vs vars/audit.yml)",
    )
    parser.add_argument(
        "path",
        help="Role directory, or CIS/STIG root when used with --all",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan every Ansible role under path (requires tasks/ and defaults/main.yml)",
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

    if args.all:
        roles = _find_roles(root)
        if not roles:
            print(f"No roles found under {root}", file=sys.stderr)
            sys.exit(2)
        reports = [check_role(role) for role in roles]
        for report in reports:
            _print_report(report, compact=args.compact)
            if not args.compact and report is not reports[-1]:
                print()
    else:
        reports = [check_role(root)]
        _print_report(reports[0])

    total_errors = sum(r.errors for r in reports)
    total_warnings = sum(r.warnings for r in reports)

    if args.all and not args.compact:
        print()
        print("=" * 60)
        print(f"Roles scanned: {len(reports)}")
        print(f"Total errors:   {total_errors}")
        print(f"Total warnings: {total_warnings}")

    sys.exit(1 if total_errors > 0 else 0)


if __name__ == "__main__":
    main()
