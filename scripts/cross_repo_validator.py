#!/usr/bin/env python3
"""Cross-Repo Validator for Ansible-Lockdown remediation + audit repo pairs.

Validates consistency between a remediation role and its corresponding Goss
audit repo across 14 checks.  Supports both STIG and CIS benchmark types,
and works with public repos (no Private- prefix) or private repos.

  1. Rule Toggle Sync              - toggles match across defaults/template/audit vars/audit files
  2. Audit File Coverage           - every rule has an audit file and vice-versa
  3. Rule_ID Consistency           - SV-* Rule_IDs match between task tags and audit metadata
  4. STIG_ID Consistency           - rule IDs agree across task names, audit filenames, metadata
  5. Category Alignment            - rules live in matching cat_X dirs in both repos
  6. Version Consistency           - benchmark version matches across all locations
  7. Goss Include Coverage         - every audit file is reachable via goss.yml globs
  8. Config Variable Parity        - non-toggle config vars match between defaults and audit vars
  9. Template Variable Sync        - hardcoded template values match defaults/main.yml
 10. Audit Vars Completeness       - all vars referenced in goss tests are defined in audit vars
 11. Toggle Value Sync             - toggle boolean values match between defaults and audit vars
 12. Severity-Directory Alignment  - task severity labels match cat_X directories (STIG)
 13. Goss Block Pairing            - if/range/end blocks are balanced in audit files
 14. When-Toggle Alignment         - task when: conditions reference correct toggle (STIG)

Zero external dependencies — uses Python 3 standard library only.
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple, TypedDict


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "2.2.0"

BENCHMARK_STIG = "stig"
BENCHMARK_CIS = "cis"


# ---------------------------------------------------------------------------
# Data models (compatible with QA tool patterns)
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    file: str
    line: int
    description: str
    severity: str  # "error", "warning", "info"
    check_name: str


@dataclass
class CheckResult:
    name: str
    status: str  # "PASS", "FAIL", "WARN", "SKIP"
    findings: List[Finding] = field(default_factory=list)
    summary: str = ""
    elapsed: float = 0.0


@dataclass
class ReportMetadata:
    remediation_repo: str
    audit_repo: str
    date: str
    benchmark_prefix: str
    benchmark_type: str
    rule_id_prefix: str  # STIG_ID prefix (e.g. "AZLX-23") or "" for CIS
    benchmark_version: str = ""
    remediation_branch: str = ""
    audit_branch: str = ""


class AuditInfo(TypedDict, total=False):
    """Metadata extracted from a single audit file."""
    file: str
    cat: Optional[int]
    meta_cat: Optional[int]
    rule_id: Optional[str]
    meta_id: Optional[str]
    toggle: Optional[str]


class TaskInfo(TypedDict, total=False):
    """Metadata extracted from a single task entry."""
    rule_id: Optional[str]
    cat: int
    file: str


# ---------------------------------------------------------------------------
# Auto-detection helpers
# ---------------------------------------------------------------------------

def _get_git_branch(repo_dir: str) -> str:
    """Get the current git branch for a repository directory.

    Returns the branch name or '' if not a git repo / git unavailable.
    """
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return ""


def auto_detect_prefix(defaults_path: str) -> str:
    """Auto-detect benchmark variable prefix from defaults/main.yml.

    Uses Counter-voting on underscore-delimited parts of top-level variable
    names.  Shorter prefixes accumulate more votes, surfacing the common root.
    """
    counter: Counter = Counter()
    try:
        with open(defaults_path, "r", encoding="utf-8") as fh:
            for line in fh:
                s = line.rstrip()
                if not s or s.startswith("#") or s[0] in (" ", "\t"):
                    continue
                m = re.match(r"^([a-zA-Z_]\w*):", s)
                if m:
                    parts = m.group(1).split("_")
                    for i in range(1, min(4, len(parts))):
                        counter["_".join(parts[:i])] += 1
    except FileNotFoundError:
        return ""
    return counter.most_common(1)[0][0] if counter else ""


def detect_benchmark_type(defaults_path: str, prefix: str) -> str:
    """Detect whether this is a STIG or CIS benchmark.

    CIS benchmarks use '{prefix}_rule_{section}' variables.
    STIG benchmarks use '{prefix}_{6digits}' variables.
    """
    rule_pat = re.compile(rf"^{re.escape(prefix)}_rule_\d")
    stig_pat = re.compile(rf"^{re.escape(prefix)}_\d{{6}}\s*:")
    cis_count = 0
    stig_count = 0
    try:
        with open(defaults_path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if rule_pat.match(stripped):
                    cis_count += 1
                elif stig_pat.match(stripped):
                    stig_count += 1
    except FileNotFoundError:
        pass
    return BENCHMARK_CIS if cis_count > stig_count else BENCHMARK_STIG


def build_toggle_pattern(prefix: str, benchmark_type: str) -> re.Pattern:
    """Build the compiled regex for matching rule toggle variables.

    STIG: {prefix}_{6digits}        e.g. az2023stig_000100
    CIS:  {prefix}_rule_{sections}  e.g. rhel9cis_rule_1_1_1_1
    """
    if benchmark_type == BENCHMARK_CIS:
        return re.compile(rf"^({re.escape(prefix)}_rule_[\d_]+)\s*:")
    return re.compile(rf"^({re.escape(prefix)}_\d{{6}})\s*:")


def build_conditional_pattern(prefix: str, benchmark_type: str) -> re.Pattern:
    """Build the compiled regex for matching audit file conditionals.

    Matches: {{ if .Vars.{toggle} }}
    """
    if benchmark_type == BENCHMARK_CIS:
        return re.compile(
            rf"\{{\{{\s*if\s+\.Vars\.({re.escape(prefix)}_rule_[\d_]+)"
        )
    return re.compile(
        rf"\{{\{{\s*if\s+\.Vars\.({re.escape(prefix)}_\d{{6}})"
    )


def auto_detect_rule_id_prefix(audit_dir: str) -> str:
    """Auto-detect the rule ID prefix from audit file names.

    For STIG repos: extracts e.g. 'AZLX-23' from 'AZLX-23-000100.yml'
    For CIS repos: returns '' (CIS uses section-based naming)
    """
    for cat in ("cat_1", "cat_2", "cat_3"):
        cat_path = os.path.join(audit_dir, cat)
        if not os.path.isdir(cat_path):
            continue
        for _root, _dirs, files in os.walk(cat_path):
            for fname in sorted(files):
                if not fname.endswith(".yml"):
                    continue
                # STIG pattern: AZLX-23-000100.yml
                m = re.match(r"^([A-Z]+-\d+)-\d{6}\.yml$", fname)
                if m:
                    return m.group(1)
    return ""


def discover_audit_repo(remediation_dir: str) -> Optional[str]:
    """Attempt to find the sibling audit repo from the remediation repo path.

    Handles both private (Private-AMAZON2023-STIG) and public (RHEL9-CIS)
    repo naming conventions.

    Search order:
      1. {basename}-Audit               (public: RHEL9-CIS -> RHEL9-CIS-Audit)
      2. Strip Private- then try -Audit  (private: Private-X -> X-Audit)
      3. Fuzzy match any *-Audit sibling sharing the benchmark root
    """
    parent = os.path.dirname(os.path.abspath(remediation_dir))
    base = os.path.basename(os.path.abspath(remediation_dir))

    # 1. Try exact: {base}-Audit (works for public repos like RHEL9-CIS)
    candidate = os.path.join(parent, f"{base}-Audit")
    if os.path.isdir(candidate):
        return candidate

    # 2. Strip Private- or Private_ prefix, try again
    benchmark = re.sub(r"^[Pp]rivate[-_]", "", base)
    if benchmark != base:
        candidate = os.path.join(parent, f"{benchmark}-Audit")
        if os.path.isdir(candidate):
            return candidate

    # 3. Fuzzy: find any *-Audit sibling containing the benchmark root word
    root_word = benchmark.split("-")[0]
    try:
        for entry in sorted(os.listdir(parent)):
            full = os.path.join(parent, entry)
            if os.path.isdir(full) and entry.endswith("-Audit") and root_word in entry:
                return full
    except OSError:
        pass

    return None


def discover_audit_vars_file(audit_dir: str) -> str:
    """Find the audit variables file (STIG.yml, CIS.yml, or similar).

    Searches vars/ directory for common names, falling back to the first
    .yml file found.
    """
    vars_dir = os.path.join(audit_dir, "vars")
    if not os.path.isdir(vars_dir):
        return os.path.join(vars_dir, "STIG.yml")  # default fallback path

    # Try well-known names in priority order
    for name in ("STIG.yml", "CIS.yml", "stig.yml", "cis.yml"):
        candidate = os.path.join(vars_dir, name)
        if os.path.isfile(candidate):
            return candidate

    # Fall back to first .yml file
    for fname in sorted(os.listdir(vars_dir)):
        if fname.endswith(".yml") or fname.endswith(".yaml"):
            return os.path.join(vars_dir, fname)

    return os.path.join(vars_dir, "STIG.yml")  # default fallback


# ---------------------------------------------------------------------------
# Extraction functions
# ---------------------------------------------------------------------------

def extract_rule_toggles(filepath: str, toggle_pat: re.Pattern) -> Dict[str, int]:
    """Extract rule toggle variables matching the toggle pattern from a file.

    Returns {variable_name: line_number}.
    """
    toggles: Dict[str, int] = {}
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                m = toggle_pat.match(line.strip())
                if m:
                    toggles[m.group(1)] = lineno
    except FileNotFoundError:
        pass
    return toggles


def extract_toggle_values(filepath: str,
                          toggle_pat: re.Pattern) -> Dict[str, Tuple[str, int]]:
    """Extract rule toggle variables with their boolean values.

    Returns {variable_name: (value_string, line_number)}.
    Values are typically 'true' or 'false'.
    """
    toggles: Dict[str, Tuple[str, int]] = {}
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                stripped = line.strip()
                m = toggle_pat.match(stripped)
                if m:
                    var_name = m.group(1)
                    # Extract the value after the variable name and ':'
                    val_match = re.match(
                        rf"^{re.escape(var_name)}\s*:\s*(\S+)", stripped
                    )
                    val = val_match.group(1) if val_match else ""
                    toggles[var_name] = (val, lineno)
    except FileNotFoundError:
        pass
    return toggles


def extract_audit_conditionals(audit_dir: str,
                               cond_pat: re.Pattern) -> Dict[str, str]:
    """Extract rule toggle references from audit file conditionals.

    Walks all .yml files under cat_*/ directories (and section_*/ for CIS).
    Returns {variable_name: relative_filepath}.
    """
    conditionals: Dict[str, str] = {}
    audit_dirs = _find_audit_subdirs(audit_dir)

    for subdir in audit_dirs:
        for root, _dirs, files in os.walk(subdir):
            for fname in sorted(files):
                if not fname.endswith(".yml"):
                    continue
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, audit_dir)
                try:
                    with open(fpath, "r", encoding="utf-8") as fh:
                        for line in fh:
                            m = cond_pat.search(line)
                            if m:
                                conditionals[m.group(1)] = rel
                except (IOError, OSError):
                    pass
    return conditionals


def extract_audit_files(audit_dir: str, benchmark_type: str,
                        prefix: str) -> Dict[str, AuditInfo]:
    """Map rule identifiers to their audit file info.

    For STIG: keys are STIG_IDs (e.g. 'AZLX-23-000100')
    For CIS: keys are toggle names (e.g. 'rhel9cis_rule_1_1_1_1')

    Returns {rule_key: {"file": relpath, "cat": int|None,
                         "rule_id": str|None, "meta_id": str|None}}.
    """
    rule_id_pat = re.compile(r"Rule_ID:\s*(SV-\d+r\d+_rule)")
    stig_id_pat = re.compile(r"STIG_ID:\s*(\S+)")
    cat_pat = re.compile(r"Cat:\s*(\d+)")

    if benchmark_type == BENCHMARK_CIS:
        cond_pat = re.compile(
            rf"\{{\{{\s*if\s+\.Vars\.({re.escape(prefix)}_rule_[\d_]+)"
        )
    else:
        cond_pat = re.compile(
            rf"\{{\{{\s*if\s+\.Vars\.({re.escape(prefix)}_\d{{6}})"
        )

    audit_map: Dict[str, AuditInfo] = {}
    audit_dirs = _find_audit_subdirs(audit_dir)

    for subdir in audit_dirs:
        for root, _dirs, files in os.walk(subdir):
            for fname in sorted(files):
                if not fname.endswith(".yml") or fname in ("goss.yml", "main.yml"):
                    continue

                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, audit_dir)
                stem = os.path.splitext(fname)[0]

                # Determine cat from directory path
                dir_cat = None
                cat_match = re.search(r"cat_(\d)", rel)
                if cat_match:
                    dir_cat = int(cat_match.group(1))

                rule_id = None
                meta_id = None  # STIG_ID from metadata
                meta_cat = None
                toggle_from_conditional = None

                try:
                    with open(fpath, "r", encoding="utf-8") as fh:
                        for line in fh:
                            if rule_id is None:
                                m = rule_id_pat.search(line)
                                if m:
                                    rule_id = m.group(1)
                            if meta_id is None:
                                m = stig_id_pat.search(line)
                                if m:
                                    meta_id = m.group(1)
                            if meta_cat is None:
                                m = cat_pat.search(line)
                                if m:
                                    meta_cat = int(m.group(1))
                            if toggle_from_conditional is None:
                                m = cond_pat.search(line)
                                if m:
                                    toggle_from_conditional = m.group(1)
                except (IOError, OSError):
                    continue

                # Determine the key for this audit file
                if benchmark_type == BENCHMARK_STIG:
                    # Use filename stem as key if it matches STIG_ID pattern
                    if re.match(r"^[A-Z]+-\d+-\d{6}$", stem):
                        key = stem
                    else:
                        # Non-standard name; skip or use conditional
                        key = meta_id or stem
                else:
                    # CIS: key by the toggle variable from the conditional
                    key = toggle_from_conditional or stem

                if key:
                    audit_map[key] = {
                        "file": rel,
                        "cat": dir_cat,
                        "meta_cat": meta_cat,
                        "rule_id": rule_id,
                        "meta_id": meta_id,
                        "toggle": toggle_from_conditional,
                    }

    return audit_map


def extract_task_data(tasks_dir: str, benchmark_type: str,
                      prefix: str,
                      rule_id_prefix: str) -> Dict[str, TaskInfo]:
    """Extract rule identifiers, Rule_IDs, and categories from task files.

    For STIG: keys are STIG_IDs from task names (e.g. 'AZLX-23-000100')
    For CIS: keys are toggle names from when: conditions (e.g. 'rhel9cis_rule_1_1_1_1')

    Returns {rule_key: {"rule_id": str|None, "cat": int, "file": relpath}}.
    """
    rule_id_pat = re.compile(r"(SV-\d+r\d+_rule)")
    task_map: Dict[str, TaskInfo] = {}

    if benchmark_type == BENCHMARK_STIG and rule_id_prefix:
        # STIG: extract STIG_ID from task names
        name_pat = re.compile(
            rf"({re.escape(rule_id_prefix)}-\d{{6}})", re.IGNORECASE
        )
    else:
        name_pat = None

    # CIS: extract toggle from when: conditions
    if benchmark_type == BENCHMARK_CIS:
        when_pat = re.compile(rf"({re.escape(prefix)}_rule_[\d_]+)")
    else:
        when_pat = None

    for cat in ("cat_1", "cat_2", "cat_3"):
        cat_path = os.path.join(tasks_dir, cat)
        if not os.path.isdir(cat_path):
            continue
        cat_num = int(cat.split("_")[1])

        for fname in sorted(os.listdir(cat_path)):
            if not fname.endswith(".yml") or fname == "main.yml":
                continue
            fpath = os.path.join(cat_path, fname)
            rel = os.path.relpath(fpath, os.path.dirname(tasks_dir))

            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except (IOError, OSError):
                continue

            current_key = None
            for line in lines:
                stripped = line.strip()

                if benchmark_type == BENCHMARK_STIG and name_pat:
                    # Detect STIG_ID from task name lines
                    if stripped.startswith("- name:") or stripped.startswith("name:"):
                        m = name_pat.search(stripped)
                        if m:
                            current_key = m.group(1).upper()
                            if current_key not in task_map:
                                task_map[current_key] = {
                                    "rule_id": None,
                                    "cat": cat_num,
                                    "file": rel,
                                }

                elif benchmark_type == BENCHMARK_CIS and when_pat:
                    # Detect toggle from when: conditions or task name
                    if "when:" in stripped or stripped.startswith("- name:") or stripped.startswith("name:"):
                        m = when_pat.search(stripped)
                        if m:
                            current_key = m.group(1)
                            if current_key not in task_map:
                                task_map[current_key] = {
                                    "rule_id": None,
                                    "cat": cat_num,
                                    "file": rel,
                                }
                    # Also check bare lines that are just the toggle (in when: lists)
                    elif when_pat.fullmatch(stripped):
                        current_key = stripped
                        if current_key not in task_map:
                            task_map[current_key] = {
                                "rule_id": None,
                                "cat": cat_num,
                                "file": rel,
                            }

                # Detect Rule_ID from tags (works for both STIG and CIS)
                if current_key and current_key in task_map:
                    m = rule_id_pat.search(stripped)
                    if m and task_map[current_key]["rule_id"] is None:
                        task_map[current_key]["rule_id"] = m.group(1)

    return task_map


def extract_versions(defaults_path: str, audit_vars_path: str,
                     run_audit_path: str) -> Dict[str, str]:
    """Extract raw benchmark version strings from all three locations."""
    versions: Dict[str, str] = {}

    # defaults/main.yml
    try:
        with open(defaults_path, "r", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"^benchmark_version:\s*['\"]?([^'\"#\n]+)", line)
                if m:
                    versions["defaults/main.yml"] = m.group(1).strip()
                    break
    except FileNotFoundError:
        pass

    # Audit vars file (STIG.yml or CIS.yml)
    audit_vars_name = os.path.relpath(audit_vars_path,
                                      os.path.dirname(os.path.dirname(audit_vars_path)))
    try:
        with open(audit_vars_path, "r", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"^benchmark_version:\s*['\"]?([^'\"#\n]+)", line)
                if m:
                    versions[audit_vars_name] = m.group(1).strip()
                    break
    except FileNotFoundError:
        pass

    # run_audit.sh
    try:
        with open(run_audit_path, "r", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"^BENCHMARK_VER\s*=\s*([^\s#]+)", line)
                if m:
                    versions["run_audit.sh"] = m.group(1).strip()
                    break
    except FileNotFoundError:
        pass

    return versions


def normalize_version(raw: str) -> Tuple[int, ...]:
    """Normalize a version string to a comparable tuple.

    Handles formats: 'v1.2.0', 'v1r2', '1.2.0', '1.2'
    """
    raw = raw.strip().lstrip("vV")

    # Try v{major}r{minor} format (STIG convention)
    m = re.match(r"^(\d+)[rR](\d+)$", raw)
    if m:
        return (int(m.group(1)), int(m.group(2)))

    # Try dotted format
    parts = raw.split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return ()


def parse_goss_globs(goss_path: str) -> List[str]:
    """Extract file glob patterns from goss.yml.

    Parses lines like '  cat_1/*.yml: {}' ignoring Go template conditionals.
    """
    patterns: List[str] = []
    try:
        with open(goss_path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "{{" in stripped:
                    continue
                m = re.match(r"^([\w.*?/\[\]-]+\.yml)\s*:\s*\{\}", stripped)
                if m:
                    patterns.append(m.group(1))
    except FileNotFoundError:
        pass
    return patterns


def _determine_status(findings: List[Finding],
                      warn_on_any: bool = False) -> str:
    """Determine check status from findings.

    Returns 'FAIL' if any error-severity findings exist, 'WARN' if any
    warning-severity findings exist (or if warn_on_any is True and there
    are any findings at all), and 'PASS' otherwise.
    """
    if any(f.severity == "error" for f in findings):
        return "FAIL"
    if warn_on_any and findings:
        return "WARN"
    if any(f.severity == "warning" for f in findings):
        return "WARN"
    return "PASS"


def _is_toggle_var(var: str, prefix: str, benchmark_type: str) -> bool:
    """Check if a variable name matches the toggle naming convention.

    STIG: {prefix}_{6digits}  e.g. az2023stig_000100
    CIS:  {prefix}_rule_{sections}  e.g. rhel9cis_rule_1_1_1_1
    """
    if benchmark_type == BENCHMARK_CIS:
        return bool(re.match(rf"^{re.escape(prefix)}_rule_\d", var))
    return bool(re.match(rf"^{re.escape(prefix)}_\d{{6}}$", var))


def _strip_yaml_value(raw: str) -> str:
    """Strip inline comments and surrounding quotes from a raw YAML value."""
    if "  #" in raw:
        raw = raw[:raw.index("  #")].strip()
    if len(raw) >= 2 and raw[0] in ("'", '"') and raw[-1] == raw[0]:
        raw = raw[1:-1]
    return raw


def _find_audit_subdirs(audit_dir: str) -> List[str]:
    """Find all audit content subdirectories (cat_*, section_*, etc.)."""
    subdirs: List[str] = []
    if not os.path.isdir(audit_dir):
        return subdirs
    for entry in sorted(os.listdir(audit_dir)):
        full = os.path.join(audit_dir, entry)
        if os.path.isdir(full) and (entry.startswith("cat_") or
                                     entry.startswith("section_")):
            subdirs.append(full)
    return subdirs


# ---------------------------------------------------------------------------
# Extraction: non-toggle config variables
# ---------------------------------------------------------------------------

def extract_config_variables(filepath: str, prefix: str,
                             toggle_pat: re.Pattern) -> Dict[str, Tuple[str, int]]:
    """Extract non-toggle config variables ({prefix}_*) from a YAML file.

    Returns {variable_name: (raw_value_string, line_number)}.
    Skips rule toggle variables (matched by toggle_pat) and non-prefixed vars.
    Only captures simple scalar values (not multi-line blocks).
    """
    config_pat = re.compile(
        rf"^({re.escape(prefix)}_\w+)\s*:\s*(.+)$"
    )
    variables: Dict[str, Tuple[str, int]] = {}
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                # Skip toggles
                if toggle_pat.match(stripped):
                    continue
                m = config_pat.match(stripped)
                if m:
                    var_name = m.group(1)
                    raw_val = _strip_yaml_value(m.group(2).strip())
                    variables[var_name] = (raw_val, lineno)
    except FileNotFoundError:
        pass
    return variables


def extract_template_variables(
    template_path: str, prefix: str, toggle_pat: re.Pattern,
) -> Dict[str, Tuple[str, bool, int]]:
    """Extract variables from the goss Jinja2 template.

    Returns {variable_name: (value_or_template_expr, is_hardcoded, line_number)}.
    A value is "hardcoded" if it does NOT contain '{{' Jinja2 templating.
    Skips rule toggle variables.
    """
    var_pat = re.compile(
        rf"^({re.escape(prefix)}_\w+)\s*:\s*(.+)$"
    )
    variables: Dict[str, Tuple[str, bool, int]] = {}
    try:
        with open(template_path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if toggle_pat.match(stripped):
                    continue
                m = var_pat.match(stripped)
                if m:
                    var_name = m.group(1)
                    raw_val = m.group(2).strip()
                    is_hardcoded = "{{" not in raw_val
                    if is_hardcoded:
                        raw_val = _strip_yaml_value(raw_val)
                    variables[var_name] = (raw_val, is_hardcoded, lineno)
    except FileNotFoundError:
        pass
    return variables


def extract_goss_var_references(audit_dir: str) -> Dict[str, Set[str]]:
    """Extract all .Vars.xxx references from goss audit test files.

    Returns {variable_name: {set_of_relative_filepaths}}.
    """
    var_pat = re.compile(r"\.Vars\.(\w+)")
    references: Dict[str, Set[str]] = defaultdict(set)
    audit_dirs = _find_audit_subdirs(audit_dir)

    for subdir in audit_dirs:
        for root, _dirs, files in os.walk(subdir):
            for fname in sorted(files):
                if not fname.endswith(".yml"):
                    continue
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, audit_dir)
                try:
                    with open(fpath, "r", encoding="utf-8") as fh:
                        for line in fh:
                            for m in var_pat.finditer(line):
                                references[m.group(1)].add(rel)
                except (IOError, OSError):
                    pass
    return dict(references)


def extract_audit_vars_defined(audit_vars_path: str) -> Set[str]:
    """Extract all top-level variable names defined in the audit vars file.

    Returns a set of variable names (regardless of value).
    """
    defined: Set[str] = set()
    try:
        with open(audit_vars_path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped[0] in (" ", "\t"):
                    continue  # skip indented (nested) lines
                m = re.match(r"^(\w+)\s*:", stripped)
                if m:
                    defined.add(m.group(1))
    except FileNotFoundError:
        pass
    return defined


# ---------------------------------------------------------------------------
# ID conversion helpers
# ---------------------------------------------------------------------------

def toggle_to_rule_key(toggle: str, prefix: str, rule_id_prefix: str,
                       benchmark_type: str) -> str:
    """Convert a toggle variable name to the rule key used in audit_files.

    STIG: 'az2023stig_000100' -> 'AZLX-23-000100'
    CIS:  'rhel9cis_rule_1_1_1_1' -> 'rhel9cis_rule_1_1_1_1' (identity)
    """
    if benchmark_type == BENCHMARK_CIS:
        return toggle  # CIS keys are the toggle names themselves

    m = re.match(rf"^{re.escape(prefix)}_(\d{{6}})$", toggle)
    if m and rule_id_prefix:
        return f"{rule_id_prefix}-{m.group(1)}"
    return ""


def rule_key_to_toggle(key: str, prefix: str, benchmark_type: str) -> str:
    """Convert a rule key back to a toggle variable name.

    STIG: 'AZLX-23-000100' -> 'az2023stig_000100'
    CIS:  'rhel9cis_rule_1_1_1_1' -> 'rhel9cis_rule_1_1_1_1' (identity)
    """
    if benchmark_type == BENCHMARK_CIS:
        return key

    m = re.search(r"(\d{6})$", key)
    if m:
        return f"{prefix}_{m.group(1)}"
    return ""


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------

def check_rule_toggle_sync(
    defaults_toggles: Dict[str, int],
    template_toggles: Dict[str, int],
    audit_vars_toggles: Dict[str, int],
    audit_conditionals: Dict[str, str],
    audit_vars_name: str,
) -> CheckResult:
    """Check 1: Verify rule toggles are synchronized across all 4 locations."""
    findings: List[Finding] = []
    all_keys = (set(defaults_toggles) | set(template_toggles) |
                set(audit_vars_toggles) | set(audit_conditionals))

    for key in sorted(all_keys):
        in_defaults = key in defaults_toggles
        in_template = key in template_toggles
        in_vars = key in audit_vars_toggles
        in_audit = key in audit_conditionals

        if in_defaults and not in_template:
            findings.append(Finding(
                file="templates/ansible_vars_goss.yml.j2",
                line=0,
                description=f"In defaults but missing from goss template: '{key}'",
                severity="warning",
                check_name="rule_toggle_sync",
            ))
        if in_defaults and not in_vars:
            findings.append(Finding(
                file=audit_vars_name,
                line=0,
                description=f"In defaults but missing from {audit_vars_name}: '{key}'",
                severity="warning",
                check_name="rule_toggle_sync",
            ))
        if in_defaults and not in_audit:
            findings.append(Finding(
                file="(audit files)",
                line=0,
                description=f"In defaults but no audit conditional found: '{key}'",
                severity="warning",
                check_name="rule_toggle_sync",
            ))
        if not in_defaults and in_template:
            findings.append(Finding(
                file="templates/ansible_vars_goss.yml.j2",
                line=template_toggles[key],
                description=f"In goss template but missing from defaults: '{key}'",
                severity="warning",
                check_name="rule_toggle_sync",
            ))
        if not in_defaults and in_vars:
            findings.append(Finding(
                file=audit_vars_name,
                line=audit_vars_toggles[key],
                description=f"In {audit_vars_name} but missing from defaults: '{key}'",
                severity="warning",
                check_name="rule_toggle_sync",
            ))
        if not in_defaults and in_audit:
            findings.append(Finding(
                file=audit_conditionals[key],
                line=0,
                description=f"In audit conditional but missing from defaults: '{key}'",
                severity="warning",
                check_name="rule_toggle_sync",
            ))

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Rule Toggle Sync", status, findings,
                       f"{len(findings)} issue(s)")


def check_audit_coverage(
    defaults_toggles: Dict[str, int],
    audit_files: Dict[str, AuditInfo],
    prefix: str,
    rule_id_prefix: str,
    benchmark_type: str,
) -> CheckResult:
    """Check 2: Every rule toggle has an audit file and vice-versa."""
    findings: List[Finding] = []

    # Build set of rule keys from defaults
    default_keys: Set[str] = set()
    for toggle in defaults_toggles:
        key = toggle_to_rule_key(toggle, prefix, rule_id_prefix, benchmark_type)
        if key:
            default_keys.add(key)

    audit_keys = set(audit_files.keys())

    # Rules with no audit file
    for key in sorted(default_keys - audit_keys):
        toggle = rule_key_to_toggle(key, prefix, benchmark_type)
        findings.append(Finding(
            file="defaults/main.yml",
            line=defaults_toggles.get(toggle, 0),
            description=f"Rule has no audit file: '{key}'",
            severity="warning",
            check_name="audit_coverage",
        ))

    # Audit files with no rule toggle
    for key in sorted(audit_keys - default_keys):
        info = audit_files[key]
        findings.append(Finding(
            file=info["file"],
            line=0,
            description=f"Audit file exists but no rule toggle in defaults: '{key}'",
            severity="warning",
            check_name="audit_coverage",
        ))

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Audit File Coverage", status, findings,
                       f"{len(findings)} issue(s)")


def check_rule_id_match(
    task_data: Dict[str, TaskInfo],
    audit_files: Dict[str, AuditInfo],
) -> CheckResult:
    """Check 3: Rule_IDs match between task tags and audit metadata."""
    findings: List[Finding] = []
    common = set(task_data.keys()) & set(audit_files.keys())

    for sid in sorted(common):
        task_rid = task_data[sid].get("rule_id")
        audit_rid = audit_files[sid].get("rule_id")

        if task_rid and audit_rid and task_rid != audit_rid:
            findings.append(Finding(
                file=audit_files[sid]["file"],
                line=0,
                description=(
                    f"Rule_ID mismatch for {sid}: "
                    f"task='{task_rid}' vs audit='{audit_rid}'"
                ),
                severity="error",
                check_name="rule_id_match",
            ))
        elif task_rid and not audit_rid:
            findings.append(Finding(
                file=audit_files[sid]["file"],
                line=0,
                description=f"Audit file missing Rule_ID metadata for {sid}",
                severity="warning",
                check_name="rule_id_match",
            ))
        elif audit_rid and not task_rid:
            findings.append(Finding(
                file=task_data[sid]["file"],
                line=0,
                description=f"Task missing Rule_ID tag for {sid}",
                severity="warning",
                check_name="rule_id_match",
            ))

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Rule_ID Consistency", status, findings,
                       f"{len(findings)} issue(s)")


def check_rule_key_match(
    task_data: Dict[str, TaskInfo],
    audit_files: Dict[str, AuditInfo],
    benchmark_type: str,
) -> CheckResult:
    """Check 4: Rule keys consistent across task names, audit filenames, metadata.

    For STIG: validates STIG_ID filename vs metadata consistency.
    For CIS: validates toggle from conditional vs toggle from task when:.
    """
    findings: List[Finding] = []

    if benchmark_type == BENCHMARK_STIG:
        # STIG: check audit filename vs metadata STIG_ID
        for sid, info in sorted(audit_files.items()):
            meta_sid = info.get("meta_id")
            if meta_sid and meta_sid != sid:
                findings.append(Finding(
                    file=info["file"],
                    line=0,
                    description=(
                        f"Audit filename/metadata STIG_ID mismatch: "
                        f"file='{sid}' vs metadata='{meta_sid}'"
                    ),
                    severity="error",
                    check_name="rule_key_match",
                ))

    # Keys only in tasks (no audit)
    task_only = set(task_data.keys()) - set(audit_files.keys())
    for key in sorted(task_only):
        findings.append(Finding(
            file=task_data[key]["file"],
            line=0,
            description=f"Rule found in tasks but no audit file: '{key}'",
            severity="info",
            check_name="rule_key_match",
        ))

    # Keys only in audit (no task)
    audit_only = set(audit_files.keys()) - set(task_data.keys())
    for key in sorted(audit_only):
        findings.append(Finding(
            file=audit_files[key]["file"],
            line=0,
            description=f"Rule found in audit but no task: '{key}'",
            severity="info",
            check_name="rule_key_match",
        ))

    status = _determine_status(findings)
    return CheckResult("Rule Key Consistency", status, findings,
                       f"{len(findings)} issue(s)")


def check_category_alignment(
    task_data: Dict[str, TaskInfo],
    audit_files: Dict[str, AuditInfo],
) -> CheckResult:
    """Check 5: Rules live in matching cat_X dirs in both repos."""
    findings: List[Finding] = []
    common = set(task_data.keys()) & set(audit_files.keys())

    for sid in sorted(common):
        task_cat = task_data[sid].get("cat")
        audit_cat = audit_files[sid].get("cat")

        if task_cat is not None and audit_cat is not None and task_cat != audit_cat:
            findings.append(Finding(
                file=audit_files[sid]["file"],
                line=0,
                description=(
                    f"Category mismatch for {sid}: "
                    f"task=cat_{task_cat} vs audit=cat_{audit_cat}"
                ),
                severity="error",
                check_name="category_alignment",
            ))

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Category Alignment", status, findings,
                       f"{len(findings)} issue(s)")


def check_version_consistency(versions: Dict[str, str]) -> CheckResult:
    """Check 6: Benchmark version matches across all locations."""
    findings: List[Finding] = []

    if len(versions) < 2:
        return CheckResult("Version Consistency", "SKIP", [],
                           f"Only {len(versions)} version(s) found")

    normalized: Dict[str, Tuple[int, ...]] = {}
    for loc, raw in versions.items():
        normalized[loc] = normalize_version(raw)

    def major_minor(t: Tuple[int, ...]) -> Tuple[int, ...]:
        return t[:2] if len(t) >= 2 else t

    base_loc = next(iter(versions))
    base_mm = major_minor(normalized[base_loc])

    for loc, norm in normalized.items():
        if loc == base_loc:
            continue
        if major_minor(norm) != base_mm:
            findings.append(Finding(
                file=loc,
                line=0,
                description=(
                    f"Version mismatch: {base_loc}='{versions[base_loc]}' "
                    f"vs {loc}='{versions[loc]}'"
                ),
                severity="error",
                check_name="version_consistency",
            ))

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Version Consistency", status, findings,
                       f"{len(findings)} issue(s)")


def check_goss_include_coverage(
    goss_globs: List[str],
    audit_files: Dict[str, AuditInfo],
) -> CheckResult:
    """Check 7: Every audit file is reachable via goss.yml glob patterns."""
    findings: List[Finding] = []

    for _sid, info in sorted(audit_files.items()):
        rel = info["file"]
        if not any(fnmatch.fnmatch(rel, p) for p in goss_globs):
            findings.append(Finding(
                file=rel,
                line=0,
                description=f"Audit file not matched by any goss.yml glob: '{rel}'",
                severity="error",
                check_name="goss_include_coverage",
            ))

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Goss Include Coverage", status, findings,
                       f"{len(findings)} issue(s)")


def check_config_variable_parity(
    defaults_config: Dict[str, Tuple[str, int]],
    audit_config: Dict[str, Tuple[str, int]],
    audit_vars_name: str,
) -> CheckResult:
    """Check 8: Non-toggle config variables match between defaults and audit vars.

    Compares variables like syslog paths, cipher lists, password policies, etc.
    that appear in both defaults/main.yml and the audit vars file.
    """
    findings: List[Finding] = []

    common = set(defaults_config.keys()) & set(audit_config.keys())
    for var in sorted(common):
        def_val, _def_line = defaults_config[var]
        aud_val, aud_line = audit_config[var]

        # Skip multi-line/block values (starting with |, >, or [)
        if def_val in ("|", ">", "|-", ">-") or aud_val in ("|", ">", "|-", ">-"):
            continue
        if def_val.startswith("[") or aud_val.startswith("["):
            continue

        if def_val != aud_val:
            findings.append(Finding(
                file=audit_vars_name,
                line=aud_line,
                description=(
                    f"Config value mismatch for '{var}': "
                    f"defaults='{def_val}' vs {audit_vars_name}='{aud_val}'"
                ),
                severity="warning",
                check_name="config_variable_parity",
            ))

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Config Variable Parity", status, findings,
                       f"{len(findings)} issue(s)")


def check_goss_template_var_sync(
    template_vars: Dict[str, Tuple[str, bool, int]],
    defaults_config: Dict[str, Tuple[str, int]],
    defaults_toggles: Dict[str, int],
) -> CheckResult:
    """Check 9: Hardcoded values in goss template match defaults/main.yml.

    Scans ansible_vars_goss.yml.j2 for variables that use literal values
    instead of Jinja2 templating, and verifies those values match defaults.
    """
    findings: List[Finding] = []

    for var, (val, is_hardcoded, lineno) in sorted(template_vars.items()):
        if not is_hardcoded:
            continue

        # Skip block indicators
        if val in ("|", ">", "|-", ">-"):
            continue

        # Check against defaults config vars
        if var in defaults_config:
            def_val, _def_line = defaults_config[var]
            if def_val in ("|", ">", "|-", ">-"):
                continue
            if val != def_val:
                findings.append(Finding(
                    file="templates/ansible_vars_goss.yml.j2",
                    line=lineno,
                    description=(
                        f"Hardcoded template value mismatch for '{var}': "
                        f"template='{val}' vs defaults='{def_val}'"
                    ),
                    severity="warning",
                    check_name="goss_template_var_sync",
                ))
        elif var not in defaults_toggles:
            # Variable hardcoded in template but not found in defaults at all
            findings.append(Finding(
                file="templates/ansible_vars_goss.yml.j2",
                line=lineno,
                description=(
                    f"Hardcoded template variable '{var}' not found in defaults/main.yml"
                ),
                severity="info",
                check_name="goss_template_var_sync",
            ))

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Template Variable Sync", status, findings,
                       f"{len(findings)} issue(s)")


def check_audit_vars_completeness(
    goss_var_refs: Dict[str, Set[str]],
    audit_vars_defined: Set[str],
    prefix: str,
    benchmark_type: str,
) -> CheckResult:
    """Check 10: All vars referenced in goss tests are defined in audit vars.

    Scans goss test files for {{ .Vars.xxx }} references and verifies each
    non-toggle variable is defined in the audit vars file.
    """
    findings: List[Finding] = []

    # Well-known runtime variables injected by the audit script/goss runner
    # (not expected to be in vars file)
    runtime_vars = {
        "machine_uuid", "epoch", "os_locale", "os_release",
        "os_distribution", "auto_group", "os_hostname", "system_type",
        "benchmark_type", "benchmark_version", "benchmark_os",
        "system_is_container",
    }

    for var, files in sorted(goss_var_refs.items()):
        # Skip rule toggles (covered by check 1)
        if _is_toggle_var(var, prefix, benchmark_type):
            continue
        # Skip known runtime variables
        if var in runtime_vars:
            continue
        # Skip non-prefixed variables (general goss/system vars)
        if not var.startswith(prefix + "_"):
            continue
        # Check if defined in audit vars
        if var not in audit_vars_defined:
            example_files = sorted(files)[:3]
            file_list = ", ".join(example_files)
            if len(files) > 3:
                file_list += f" (+{len(files) - 3} more)"
            findings.append(Finding(
                file="(audit test files)",
                line=0,
                description=(
                    f"Goss test references '.Vars.{var}' but not defined in audit vars. "
                    f"Used in: {file_list}"
                ),
                severity="warning",
                check_name="audit_vars_completeness",
            ))

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Audit Vars Completeness", status, findings,
                       f"{len(findings)} issue(s)")


def check_toggle_value_sync(
    defaults_values: Dict[str, Tuple[str, int]],
    audit_values: Dict[str, Tuple[str, int]],
    audit_vars_name: str,
) -> CheckResult:
    """Check 11: Toggle boolean values match between defaults and audit vars.

    A toggle set to 'true' in defaults but 'false' in audit vars means
    the audit will skip a test that remediation actively runs (and vice-versa).
    """
    findings: List[Finding] = []
    common = set(defaults_values.keys()) & set(audit_values.keys())

    for var in sorted(common):
        def_val, _def_line = defaults_values[var]
        aud_val, aud_line = audit_values[var]

        # Normalize boolean strings for comparison
        def_norm = def_val.lower().strip()
        aud_norm = aud_val.lower().strip()

        if def_norm != aud_norm:
            findings.append(Finding(
                file=audit_vars_name,
                line=aud_line,
                description=(
                    f"Toggle value mismatch for '{var}': "
                    f"defaults='{def_val}' vs {audit_vars_name}='{aud_val}'"
                ),
                severity="warning",
                check_name="toggle_value_sync",
            ))

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Toggle Value Sync", status, findings,
                       f"{len(findings)} issue(s)")


def check_severity_directory(
    benchmark_type: str,
    tasks_dir: str,
) -> CheckResult:
    """Check 12: Task name severity label matches cat directory (STIG only).

    Extracts HIGH/MEDIUM/LOW from task names and verifies the task
    file lives in the corresponding cat_1/cat_2/cat_3 directory.
    """
    findings: List[Finding] = []

    if benchmark_type != BENCHMARK_STIG:
        return CheckResult("Severity-Directory Alignment", "SKIP", [],
                           "CIS benchmarks do not use severity labels")

    severity_to_cat = {"HIGH": 1, "MEDIUM": 2, "LOW": 3}
    severity_pat = re.compile(r"^\s*-?\s*name:\s*\"?(HIGH|MEDIUM|LOW)\s*\|", re.IGNORECASE)

    for cat in ("cat_1", "cat_2", "cat_3"):
        cat_path = os.path.join(tasks_dir, cat)
        if not os.path.isdir(cat_path):
            continue
        cat_num = int(cat.split("_")[1])

        for fname in sorted(os.listdir(cat_path)):
            if not fname.endswith(".yml") or fname == "main.yml":
                continue
            fpath = os.path.join(cat_path, fname)
            rel = os.path.relpath(fpath, os.path.dirname(tasks_dir))

            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, 1):
                        m = severity_pat.match(line)
                        if m:
                            sev_label = m.group(1).upper()
                            expected_cat = severity_to_cat.get(sev_label)
                            if expected_cat and expected_cat != cat_num:
                                findings.append(Finding(
                                    file=rel,
                                    line=lineno,
                                    description=(
                                        f"Severity label '{sev_label}' "
                                        f"(expected cat_{expected_cat}) but "
                                        f"task is in cat_{cat_num}"
                                    ),
                                    severity="error",
                                    check_name="severity_directory",
                                ))
            except (IOError, OSError):
                continue

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Severity-Directory Alignment", status, findings,
                       f"{len(findings)} issue(s)")


def check_goss_block_pairing(audit_dir: str) -> CheckResult:
    """Check 13: Validate if/range/end block pairing in audit files.

    Counts opening blocks ({{ if ... }}, {{ range ... }}) and closing
    blocks ({{ end }}) in each audit file and reports mismatches.
    """
    findings: List[Finding] = []
    open_pat = re.compile(r"\{\{-?\s*(if|range)\s+")
    close_pat = re.compile(r"\{\{-?\s*end\s*-?\}\}")
    audit_dirs = _find_audit_subdirs(audit_dir)

    for subdir in audit_dirs:
        for root, _dirs, files in os.walk(subdir):
            for fname in sorted(files):
                if not fname.endswith(".yml") or fname in ("goss.yml", "main.yml"):
                    continue
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, audit_dir)

                opens = 0
                closes = 0
                try:
                    with open(fpath, "r", encoding="utf-8") as fh:
                        for line in fh:
                            opens += len(open_pat.findall(line))
                            closes += len(close_pat.findall(line))
                except (IOError, OSError):
                    continue

                if opens != closes:
                    findings.append(Finding(
                        file=rel,
                        line=0,
                        description=(
                            f"Block mismatch: {opens} opening "
                            f"(if/range) vs {closes} closing (end)"
                        ),
                        severity="warning",
                        check_name="goss_block_pairing",
                    ))

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("Goss Block Pairing", status, findings,
                       f"{len(findings)} issue(s)")


def check_when_toggle_alignment(
    tasks_dir: str,
    prefix: str,
    rule_id_prefix: str,
    benchmark_type: str,
) -> CheckResult:
    """Check 14: Task when: conditions reference the correct toggle (STIG only).

    For each task with a STIG_ID in its name, verifies that the when:
    condition uses the matching toggle variable (e.g. AZLX-23-000100
    should use when: az2023stig_000100).
    """
    findings: List[Finding] = []

    if benchmark_type != BENCHMARK_STIG or not rule_id_prefix:
        return CheckResult("When-Toggle Alignment", "SKIP", [],
                           "Only applicable to STIG benchmarks")

    stig_id_pat = re.compile(
        rf"({re.escape(rule_id_prefix)}-\d{{6}})", re.IGNORECASE
    )
    when_pat = re.compile(
        rf"when:\s*.*({re.escape(prefix)}_\d{{6}})"
    )

    for cat in ("cat_1", "cat_2", "cat_3"):
        cat_path = os.path.join(tasks_dir, cat)
        if not os.path.isdir(cat_path):
            continue
        for fname in sorted(os.listdir(cat_path)):
            if not fname.endswith(".yml") or fname == "main.yml":
                continue
            fpath = os.path.join(cat_path, fname)
            rel = os.path.relpath(fpath, os.path.dirname(tasks_dir))

            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except (IOError, OSError):
                continue

            current_stig_id: Optional[str] = None
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()

                # Detect STIG_ID from task name
                if stripped.startswith("- name:") or stripped.startswith("name:"):
                    m = stig_id_pat.search(stripped)
                    if m:
                        current_stig_id = m.group(1).upper()

                # Check when: condition
                if current_stig_id and "when:" in stripped:
                    m = when_pat.search(stripped)
                    if m:
                        when_toggle = m.group(1)
                        # Derive expected toggle from STIG_ID
                        digits = re.search(r"(\d{6})$", current_stig_id)
                        if digits:
                            expected_toggle = f"{prefix}_{digits.group(1)}"
                            if when_toggle != expected_toggle:
                                findings.append(Finding(
                                    file=rel,
                                    line=lineno,
                                    description=(
                                        f"When-toggle mismatch for "
                                        f"{current_stig_id}: "
                                        f"expected '{expected_toggle}' but "
                                        f"found '{when_toggle}'"
                                    ),
                                    severity="error",
                                    check_name="when_toggle_alignment",
                                ))
                        current_stig_id = None  # reset after checking

    status = _determine_status(findings, warn_on_any=True)
    return CheckResult("When-Toggle Alignment", status, findings,
                       f"{len(findings)} issue(s)")


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _count_statuses(results: List[CheckResult]) -> Dict[str, int]:
    """Count results by status.  Returns dict with total/passed/failed/warnings/skipped."""
    return {
        "total": len(results),
        "passed": sum(1 for r in results if r.status == "PASS"),
        "failed": sum(1 for r in results if r.status == "FAIL"),
        "warnings": sum(1 for r in results if r.status == "WARN"),
        "skipped": sum(1 for r in results if r.status == "SKIP"),
    }


def generate_markdown(metadata: ReportMetadata,
                      results: List[CheckResult]) -> str:
    """Generate a markdown report."""
    lines: List[str] = []
    lines.append("# Cross-Repo Validation Report\n")
    lines.append(f"**Remediation:** {metadata.remediation_repo}  ")
    lines.append(f"**Audit:** {metadata.audit_repo}  ")
    lines.append(f"**Date:** {metadata.date}  ")
    lines.append(f"**Benchmark Prefix:** {metadata.benchmark_prefix}  ")
    lines.append(f"**Benchmark Type:** {metadata.benchmark_type.upper()}  ")
    if metadata.rule_id_prefix:
        lines.append(f"**Rule ID Prefix:** {metadata.rule_id_prefix}  ")
    if metadata.benchmark_version:
        lines.append(f"**Benchmark Version:** {metadata.benchmark_version}  ")
    if metadata.remediation_branch:
        lines.append(f"**Remediation Branch:** {metadata.remediation_branch}  ")
    if metadata.audit_branch:
        lines.append(f"**Audit Branch:** {metadata.audit_branch}  ")
    lines.append("")

    counts = _count_statuses(results)
    total = counts["total"]
    passed = counts["passed"]
    failed = counts["failed"]
    warned = counts["warnings"]
    skipped = counts["skipped"]

    lines.append("## Summary\n")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Checks | {total} |")
    lines.append(f"| Passed | {passed} |")
    lines.append(f"| Failed | {failed} |")
    lines.append(f"| Warnings | {warned} |")
    lines.append(f"| Skipped | {skipped} |")
    lines.append("")

    lines.append("| Check | Status | Findings |")
    lines.append("|-------|--------|----------|")
    for r in results:
        lines.append(f"| {r.name} | {r.status} | {r.summary} |")
    lines.append("")

    for r in results:
        lines.append(f"## [{r.status}] {r.name}\n")
        lines.append(f"**Status:** {r.status}  ")
        lines.append(f"**Summary:** {r.summary}\n")

        if r.findings:
            lines.append("| Severity | File | Line | Description |")
            lines.append("|----------|------|------|-------------|")
            for f in r.findings[:200]:
                line_str = str(f.line) if f.line > 0 else "-"
                lines.append(
                    f"| {f.severity} | `{f.file}` | {line_str} "
                    f"| {f.description} |"
                )
            if len(r.findings) > 200:
                lines.append(
                    f"| ... | ... | ... "
                    f"| *({len(r.findings) - 200} more findings truncated)* |"
                )
            lines.append("")

    lines.append("---\n")
    lines.append(
        f"*Generated by cross_repo_validator.py v{VERSION} "
        f"for {metadata.remediation_repo} on {metadata.date}*\n"
    )

    return "\n".join(lines)


def _html_escape(text: str) -> str:
    """Escape HTML special characters."""
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))


_STATUS_COLOURS = {
    "PASS": "#28a745",
    "FAIL": "#dc3545",
    "WARN": "#ffc107",
    "SKIP": "#6c757d",
}

_SEVERITY_COLOURS = {
    "error": "#dc3545",
    "warning": "#ffc107",
    "info": "#17a2b8",
}


def generate_html(metadata: ReportMetadata,
                  results: List[CheckResult]) -> str:
    """Generate a self-contained HTML report with embedded CSS."""
    counts = _count_statuses(results)
    total = counts["total"]
    passed = counts["passed"]
    failed = counts["failed"]
    warned = counts["warnings"]
    skipped = counts["skipped"]

    h = _html_escape  # shorthand

    parts: List[str] = []
    parts.append("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cross-Repo Validation Report</title>
<style>
  :root {
    --pass: #28a745; --fail: #dc3545; --warn: #ffc107; --skip: #6c757d;
    --bg: #f8f9fa; --card: #fff; --border: #dee2e6; --text: #212529;
    --text-light: #6c757d; --mono: SFMono-Regular,Menlo,Monaco,Consolas,monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.5; padding: 2rem; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { font-size: 1.75rem; margin-bottom: 0.5rem; }
  .meta { color: var(--text-light); font-size: 0.9rem; margin-bottom: 1.5rem; }
  .meta span { margin-right: 1.5rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                   gap: 0.75rem; margin-bottom: 1.5rem; }
  .summary-card { background: var(--card); border: 1px solid var(--border); border-radius: 6px;
                   padding: 1rem; text-align: center; }
  .summary-card .count { font-size: 2rem; font-weight: 700; }
  .summary-card .label { font-size: 0.8rem; color: var(--text-light); text-transform: uppercase; letter-spacing: 0.05em; }
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: var(--bg); font-weight: 600; position: sticky; top: 0; }
  .check-section { background: var(--card); border: 1px solid var(--border); border-radius: 6px;
                    margin-bottom: 1rem; overflow: hidden; }
  .check-header { display: flex; align-items: center; justify-content: space-between;
                   padding: 0.75rem 1rem; cursor: pointer; user-select: none; }
  .check-header:hover { background: var(--bg); }
  .check-title { font-weight: 600; font-size: 0.95rem; }
  .badge { display: inline-block; padding: 0.15em 0.55em; border-radius: 4px;
           font-size: 0.75rem; font-weight: 700; color: #fff; }
  .badge-pass { background: var(--pass); }
  .badge-fail { background: var(--fail); }
  .badge-warn { background: var(--warn); color: #212529; }
  .badge-skip { background: var(--skip); }
  .sev-error { color: var(--fail); font-weight: 600; }
  .sev-warning { color: #b8860b; font-weight: 600; }
  .sev-info { color: #0c7c84; font-weight: 600; }
  .check-body { padding: 0 1rem 1rem; }
  .check-body table { margin-top: 0.5rem; }
  .file-col { font-family: var(--mono); font-size: 0.8rem; white-space: nowrap; }
  .desc-col { word-break: break-word; }
  .toggle-arrow { transition: transform 0.2s; font-size: 0.8rem; color: var(--text-light); }
  .check-section.collapsed .toggle-arrow { transform: rotate(-90deg); }
  .check-section.collapsed .check-body { display: none; }
  .overview-table { background: var(--card); border: 1px solid var(--border); border-radius: 6px;
                     overflow: hidden; margin-bottom: 1.5rem; }
  .truncated { font-style: italic; color: var(--text-light); padding: 0.5rem 0.75rem; }
  footer { margin-top: 2rem; text-align: center; font-size: 0.8rem; color: var(--text-light); }
</style>
</head>
<body>
<div class="container">
""")

    # Header
    parts.append(f"<h1>Cross-Repo Validation Report</h1>\n<div class='meta'>")
    parts.append(f"<span><b>Remediation:</b> {h(metadata.remediation_repo)}</span>")
    parts.append(f"<span><b>Audit:</b> {h(metadata.audit_repo)}</span>")
    parts.append(f"<span><b>Date:</b> {h(metadata.date)}</span><br>")
    parts.append(f"<span><b>Prefix:</b> {h(metadata.benchmark_prefix)}</span>")
    parts.append(f"<span><b>Type:</b> {metadata.benchmark_type.upper()}</span>")
    if metadata.rule_id_prefix:
        parts.append(f"<span><b>Rule ID Prefix:</b> {h(metadata.rule_id_prefix)}</span>")
    if metadata.benchmark_version:
        parts.append(f"<br><span><b>Benchmark Version:</b> {h(metadata.benchmark_version)}</span>")
    if metadata.remediation_branch:
        parts.append(f"<span><b>Remediation Branch:</b> {h(metadata.remediation_branch)}</span>")
    if metadata.audit_branch:
        parts.append(f"<span><b>Audit Branch:</b> {h(metadata.audit_branch)}</span>")
    parts.append("</div>\n")

    # Summary cards
    parts.append("<div class='summary-grid'>")
    for label, count, colour in [
        ("Total", total, "#495057"),
        ("Passed", passed, _STATUS_COLOURS["PASS"]),
        ("Failed", failed, _STATUS_COLOURS["FAIL"]),
        ("Warnings", warned, _STATUS_COLOURS["WARN"]),
        ("Skipped", skipped, _STATUS_COLOURS["SKIP"]),
    ]:
        parts.append(
            f"<div class='summary-card'>"
            f"<div class='count' style='color:{colour}'>{count}</div>"
            f"<div class='label'>{label}</div></div>"
        )
    parts.append("</div>\n")

    # Overview table
    parts.append("<div class='overview-table'><table>")
    parts.append("<tr><th>Check</th><th>Status</th><th>Findings</th></tr>")
    for r in results:
        badge_cls = f"badge-{r.status.lower()}"
        parts.append(
            f"<tr><td>{h(r.name)}</td>"
            f"<td><span class='badge {badge_cls}'>{r.status}</span></td>"
            f"<td>{h(r.summary)}</td></tr>"
        )
    parts.append("</table></div>\n")

    # Per-check detail sections
    for r in results:
        badge_cls = f"badge-{r.status.lower()}"
        collapsed = " collapsed" if r.status == "PASS" and not r.findings else ""
        parts.append(f"<div class='check-section{collapsed}'>")
        parts.append(
            f"<div class='check-header' onclick='this.parentElement.classList.toggle(\"collapsed\")'>"
            f"<span class='check-title'>{h(r.name)}</span>"
            f"<span><span class='badge {badge_cls}'>{r.status}</span> "
            f"<span class='toggle-arrow'>&#9660;</span></span></div>"
        )
        parts.append("<div class='check-body'>")
        if r.findings:
            parts.append("<table><tr><th>Severity</th><th>File</th>"
                         "<th>Line</th><th>Description</th></tr>")
            for f in r.findings[:200]:
                sev_cls = f"sev-{f.severity}"
                line_str = str(f.line) if f.line > 0 else "-"
                parts.append(
                    f"<tr><td class='{sev_cls}'>{h(f.severity)}</td>"
                    f"<td class='file-col'>{h(f.file)}</td>"
                    f"<td>{line_str}</td>"
                    f"<td class='desc-col'>{h(f.description)}</td></tr>"
                )
            if len(r.findings) > 200:
                parts.append(
                    f"<tr><td colspan='4' class='truncated'>"
                    f"({len(r.findings) - 200} more findings truncated)</td></tr>"
                )
            parts.append("</table>")
        else:
            parts.append("<p style='color:var(--text-light)'>No findings.</p>")
        parts.append("</div></div>\n")

    parts.append(
        f"<footer>Generated by <b>cross_repo_validator.py</b> v{VERSION} "
        f"for <b>{h(metadata.remediation_repo)}</b> on {h(metadata.date)}</footer>"
    )
    parts.append("</div>\n</body>\n</html>")

    return "\n".join(parts)


def generate_json(metadata: ReportMetadata,
                  results: List[CheckResult]) -> str:
    """Generate a JSON report."""
    meta = asdict(metadata)
    meta["generated_by"] = f"cross_repo_validator.py v{VERSION}"
    report = {
        "metadata": meta,
        "summary": _count_statuses(results),
        "checks": [
            {
                "name": r.name,
                "status": r.status,
                "summary": r.summary,
                "findings": [asdict(f) for f in r.findings],
            }
            for r in results
        ],
    }
    return json.dumps(report, indent=2)


def generate_report(metadata: ReportMetadata,
                    results: List[CheckResult], fmt: str) -> str:
    """Dispatch to the appropriate report generator based on format."""
    if fmt == "json":
        return generate_json(metadata, results)
    if fmt == "html":
        return generate_html(metadata, results)
    return generate_markdown(metadata, results)


# ---------------------------------------------------------------------------
# CLI and main
# ---------------------------------------------------------------------------

CHECK_NAMES = {
    "rule_toggle_sync": "Rule Toggle Sync",
    "audit_coverage": "Audit File Coverage",
    "rule_id_match": "Rule_ID Consistency",
    "rule_key_match": "Rule Key Consistency",
    "category_alignment": "Category Alignment",
    "version_consistency": "Version Consistency",
    "goss_include_coverage": "Goss Include Coverage",
    "config_variable_parity": "Config Variable Parity",
    "goss_template_var_sync": "Template Variable Sync",
    "audit_vars_completeness": "Audit Vars Completeness",
    "toggle_value_sync": "Toggle Value Sync",
    "severity_directory": "Severity-Directory Alignment",
    "goss_block_pairing": "Goss Block Pairing",
    "when_toggle_alignment": "When-Toggle Alignment",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cross-repo validator for Ansible-Lockdown remediation + audit pairs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supports both STIG and CIS benchmark types.  The benchmark type is
auto-detected from defaults/main.yml variable naming patterns.

Works with public repos (RHEL9-CIS) and private repos (Private-AMAZON2023-STIG).

Check keys for --skip / --only:
  rule_toggle_sync, audit_coverage, rule_id_match, rule_key_match,
  category_alignment, version_consistency, goss_include_coverage,
  config_variable_parity, goss_template_var_sync, audit_vars_completeness,
  toggle_value_sync, severity_directory, goss_block_pairing,
  when_toggle_alignment
""",
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    parser.add_argument(
        "-r", "--remediation",
        required=True,
        help="Path to remediation repo (e.g. Private-AMAZON2023-STIG or RHEL9-CIS)",
    )
    parser.add_argument(
        "-a", "--audit",
        default=None,
        help="Path to audit repo (auto-discovered if omitted)",
    )
    parser.add_argument(
        "-t", "--type",
        choices=["stig", "cis", "auto"], default="auto",
        help="Benchmark type (default: auto-detect)",
    )
    parser.add_argument(
        "--format", choices=["md", "json", "html"], default="md",
        help="Report format (default: md)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output file path (default: cross_repo_report_{repo}_{timestamp}.{fmt})",
    )
    parser.add_argument(
        "--skip", default="",
        help="Comma-separated check names to skip",
    )
    parser.add_argument(
        "--only", default="",
        help="Comma-separated check names to run exclusively",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit with code 1 on warnings",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print verbose progress to stderr",
    )
    parser.add_argument(
        "--console", action="store_true",
        help="Print report to stdout",
    )
    parser.add_argument(
        "--no-report", action="store_true",
        help="Skip writing report file",
    )
    return parser


def should_run(check_key: str, skip_set: Set[str], only_set: Set[str]) -> bool:
    if only_set:
        return check_key in only_set
    return check_key not in skip_set


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    remediation_dir = os.path.abspath(args.remediation)
    if not os.path.isdir(remediation_dir):
        print(f"Error: remediation directory not found: {remediation_dir}",
              file=sys.stderr)
        sys.exit(2)

    # Discover or validate audit repo
    if args.audit:
        audit_dir = os.path.abspath(args.audit)
    else:
        audit_dir_maybe = discover_audit_repo(remediation_dir)
        if audit_dir_maybe is None:
            print("Error: could not auto-discover audit repo. Use -a to specify.",
                  file=sys.stderr)
            sys.exit(2)
        audit_dir = audit_dir_maybe

    if not os.path.isdir(audit_dir):
        print(f"Error: audit directory not found: {audit_dir}",
              file=sys.stderr)
        sys.exit(2)

    log = (lambda msg: print(f"  [*] {msg}", file=sys.stderr)) if args.verbose else (lambda _msg: None)

    # Paths
    defaults_path = os.path.join(remediation_dir, "defaults", "main.yml")
    template_path = os.path.join(remediation_dir, "templates", "ansible_vars_goss.yml.j2")
    tasks_dir = os.path.join(remediation_dir, "tasks")
    audit_vars_path = discover_audit_vars_file(audit_dir)
    audit_vars_name = os.path.relpath(audit_vars_path, audit_dir)
    goss_path = os.path.join(audit_dir, "goss.yml")
    run_audit_path = os.path.join(audit_dir, "run_audit.sh")

    # Auto-detect prefix
    prefix = auto_detect_prefix(defaults_path)
    if not prefix:
        print("Error: could not auto-detect benchmark prefix from defaults/main.yml",
              file=sys.stderr)
        sys.exit(2)
    log(f"Detected benchmark prefix: {prefix}")

    # Detect benchmark type
    if args.type == "auto":
        benchmark_type = detect_benchmark_type(defaults_path, prefix)
    else:
        benchmark_type = args.type
    log(f"Benchmark type: {benchmark_type.upper()}")

    # Build patterns for this benchmark type
    toggle_pat = build_toggle_pattern(prefix, benchmark_type)
    cond_pat = build_conditional_pattern(prefix, benchmark_type)

    # Detect rule ID prefix (STIG only)
    rule_id_prefix = ""
    if benchmark_type == BENCHMARK_STIG:
        rule_id_prefix = auto_detect_rule_id_prefix(audit_dir)
        if rule_id_prefix:
            log(f"Detected rule ID prefix: {rule_id_prefix}")
        else:
            log("No STIG rule ID prefix detected from audit filenames")

    # Parse filters
    skip_set = {s.strip() for s in args.skip.split(",") if s.strip()}
    only_set = {s.strip() for s in args.only.split(",") if s.strip()}

    # -----------------------------------------------------------------------
    # Extract data
    # -----------------------------------------------------------------------
    log("Extracting rule toggles from defaults/main.yml...")
    defaults_toggles = extract_rule_toggles(defaults_path, toggle_pat)
    log(f"  Found {len(defaults_toggles)} toggles")

    log("Extracting rule toggles from goss template...")
    template_toggles = extract_rule_toggles(template_path, toggle_pat)
    log(f"  Found {len(template_toggles)} toggles")

    log(f"Extracting rule toggles from {audit_vars_name}...")
    audit_vars_toggles = extract_rule_toggles(audit_vars_path, toggle_pat)
    log(f"  Found {len(audit_vars_toggles)} toggles")

    log("Extracting audit file conditionals...")
    audit_conditionals = extract_audit_conditionals(audit_dir, cond_pat)
    log(f"  Found {len(audit_conditionals)} conditionals")

    log("Extracting audit file metadata...")
    audit_files = extract_audit_files(audit_dir, benchmark_type, prefix)
    log(f"  Found {len(audit_files)} audit files")

    log("Extracting task data...")
    task_data = extract_task_data(tasks_dir, benchmark_type, prefix,
                                 rule_id_prefix)
    log(f"  Found {len(task_data)} task entries")

    log("Extracting version information...")
    versions = extract_versions(defaults_path, audit_vars_path, run_audit_path)
    log(f"  Found versions: {versions}")

    log("Parsing goss.yml glob patterns...")
    goss_globs = parse_goss_globs(goss_path)
    log(f"  Found {len(goss_globs)} patterns")

    log("Extracting config variables from defaults/main.yml...")
    defaults_config = extract_config_variables(defaults_path, prefix, toggle_pat)
    log(f"  Found {len(defaults_config)} config variables")

    log(f"Extracting config variables from {audit_vars_name}...")
    audit_config = extract_config_variables(audit_vars_path, prefix, toggle_pat)
    log(f"  Found {len(audit_config)} config variables")

    log("Extracting template variables from goss template...")
    template_vars = extract_template_variables(template_path, prefix, toggle_pat)
    log(f"  Found {len(template_vars)} template variables")

    log("Extracting goss .Vars references from audit test files...")
    goss_var_refs = extract_goss_var_references(audit_dir)
    log(f"  Found {len(goss_var_refs)} unique variable references")

    log(f"Extracting defined variables from {audit_vars_name}...")
    audit_vars_defined = extract_audit_vars_defined(audit_vars_path)
    log(f"  Found {len(audit_vars_defined)} defined variables")

    log("Extracting toggle values from defaults/main.yml...")
    defaults_toggle_values = extract_toggle_values(defaults_path, toggle_pat)
    log(f"  Found {len(defaults_toggle_values)} toggle values")

    log(f"Extracting toggle values from {audit_vars_name}...")
    audit_toggle_values = extract_toggle_values(audit_vars_path, toggle_pat)
    log(f"  Found {len(audit_toggle_values)} toggle values")

    # -----------------------------------------------------------------------
    # Run checks
    # -----------------------------------------------------------------------
    results: List[CheckResult] = []

    def _run(key: str, fn, *a, **kw) -> None:  # type: ignore[no-untyped-def]
        """Run a check with timing if it's not skipped."""
        if not should_run(key, skip_set, only_set):
            return
        log(f"Running: {CHECK_NAMES.get(key, key)}...")
        t0 = time.perf_counter()
        result = fn(*a, **kw)
        result.elapsed = time.perf_counter() - t0
        log(f"  {result.status} ({result.elapsed:.3f}s)")
        results.append(result)

    _run("rule_toggle_sync", check_rule_toggle_sync,
         defaults_toggles, template_toggles,
         audit_vars_toggles, audit_conditionals, audit_vars_name)
    _run("audit_coverage", check_audit_coverage,
         defaults_toggles, audit_files, prefix, rule_id_prefix, benchmark_type)
    _run("rule_id_match", check_rule_id_match, task_data, audit_files)
    _run("rule_key_match", check_rule_key_match,
         task_data, audit_files, benchmark_type)
    _run("category_alignment", check_category_alignment, task_data, audit_files)
    _run("version_consistency", check_version_consistency, versions)
    _run("goss_include_coverage", check_goss_include_coverage,
         goss_globs, audit_files)
    _run("config_variable_parity", check_config_variable_parity,
         defaults_config, audit_config, audit_vars_name)
    _run("goss_template_var_sync", check_goss_template_var_sync,
         template_vars, defaults_config, defaults_toggles)
    _run("audit_vars_completeness", check_audit_vars_completeness,
         goss_var_refs, audit_vars_defined, prefix, benchmark_type)
    _run("toggle_value_sync", check_toggle_value_sync,
         defaults_toggle_values, audit_toggle_values, audit_vars_name)
    _run("severity_directory", check_severity_directory,
         benchmark_type, tasks_dir)
    _run("goss_block_pairing", check_goss_block_pairing, audit_dir)
    _run("when_toggle_alignment", check_when_toggle_alignment,
         tasks_dir, prefix, rule_id_prefix, benchmark_type)

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------
    # Gather git branch info
    rem_branch = _get_git_branch(remediation_dir)
    aud_branch = _get_git_branch(audit_dir)
    if rem_branch:
        log(f"Remediation branch: {rem_branch}")
    if aud_branch:
        log(f"Audit branch: {aud_branch}")

    # Resolve benchmark version for metadata (use defaults/main.yml as primary)
    bm_version = versions.get("defaults/main.yml", "")

    metadata = ReportMetadata(
        remediation_repo=os.path.basename(remediation_dir),
        audit_repo=os.path.basename(audit_dir),
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        benchmark_prefix=prefix,
        benchmark_type=benchmark_type,
        rule_id_prefix=rule_id_prefix,
        benchmark_version=bm_version,
        remediation_branch=rem_branch,
        audit_branch=aud_branch,
    )

    report = generate_report(metadata, results, args.format)

    if args.console:
        print(report)

    if not args.no_report:
        ext = {"json": "json", "html": "html"}.get(args.format, "md")
        repo_name = metadata.remediation_repo
        bm_ver = metadata.benchmark_version.replace(".", "_") if metadata.benchmark_version else "unknown"
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        output_path = args.output or f"cross_repo_report_{repo_name}_{bm_ver}_{timestamp}.{ext}"
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Report written to: {output_path}", file=sys.stderr)

    # Exit code
    has_errors = any(r.status == "FAIL" for r in results)
    has_warnings = any(r.status == "WARN" for r in results)
    if has_errors:
        sys.exit(2)
    if has_warnings and args.strict:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
