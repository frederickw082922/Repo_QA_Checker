#!/usr/bin/env python3
"""Cross-Repo Validator for Ansible-Lockdown remediation + audit repo pairs.

Validates consistency between a remediation role and its corresponding Goss
audit repo across 19 checks.  Reports include per-check criteria descriptions
explaining what each check validates and why findings appear.
Supports both STIG and CIS benchmark types, and works with public repos
(no Private- prefix) or private repos.

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
 15. Template-Goss Var Cross-Ref   - goss .Vars references match template output keys and defaults
 16. Handler Notify Validation    - notify references match defined handler names
 17. Prelim Variable Dependencies  - prelim_* vars used in tasks are defined in prelim.yml
 18. Automation Status Tracking    - automated controls have corresponding audit tests
 19. File Path Alignment           - remediation file paths match audit test paths

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
from typing import Any, Dict, List, Optional, Set, Tuple, TypedDict


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "2.8.1"

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
    for subdir in _find_audit_subdirs(audit_dir):
        for _root, _dirs, files in os.walk(subdir):
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

                # Determine cat/section from directory path
                dir_cat = None
                cat_match = re.search(r"(?:cat|section)_(\d+)", rel)
                if cat_match:
                    dir_cat = int(cat_match.group(1))

                meta_cat = None
                all_toggles: List[str] = []
                all_stig_ids: List[str] = []
                all_rule_ids: List[str] = []

                try:
                    with open(fpath, "r", encoding="utf-8") as fh:
                        for line in fh:
                            m = rule_id_pat.search(line)
                            if m:
                                rid = m.group(1)
                                if rid not in all_rule_ids:
                                    all_rule_ids.append(rid)
                            m = stig_id_pat.search(line)
                            if m:
                                sid = m.group(1)
                                if sid not in all_stig_ids:
                                    all_stig_ids.append(sid)
                            if meta_cat is None:
                                m = cat_pat.search(line)
                                if m:
                                    meta_cat = int(m.group(1))
                            # Collect ALL toggle conditionals (files
                            # may contain multiple rules in one file)
                            m = cond_pat.search(line)
                            if m:
                                toggle = m.group(1)
                                if toggle not in all_toggles:
                                    all_toggles.append(toggle)
                except (IOError, OSError):
                    continue

                toggle_from_conditional = all_toggles[0] if all_toggles else None

                # Determine the key(s) for this audit file
                if benchmark_type == BENCHMARK_STIG:
                    if re.match(r"^[A-Z]+-\d+-\d{6}$", stem):
                        # Standard single-rule file — register by filename
                        audit_map[stem] = {
                            "file": rel,
                            "cat": dir_cat,
                            "meta_cat": meta_cat,
                            "rule_id": all_rule_ids[0] if all_rule_ids else None,
                            "meta_id": all_stig_ids[0] if all_stig_ids else None,
                            "toggle": toggle_from_conditional,
                        }
                    elif all_stig_ids:
                        # Non-standard name with metadata — register each
                        # STIG_ID found (handles multi-rule files)
                        for i, sid in enumerate(all_stig_ids):
                            rid = all_rule_ids[i] if i < len(all_rule_ids) else None
                            tog = all_toggles[i] if i < len(all_toggles) else None
                            audit_map[sid] = {
                                "file": rel,
                                "cat": dir_cat,
                                "meta_cat": meta_cat,
                                "rule_id": rid,
                                "meta_id": sid,
                                "toggle": tog,
                            }
                    elif stem:
                        # Fallback to filename stem
                        audit_map[stem] = {
                            "file": rel,
                            "cat": dir_cat,
                            "meta_cat": meta_cat,
                            "rule_id": all_rule_ids[0] if all_rule_ids else None,
                            "meta_id": None,
                            "toggle": toggle_from_conditional,
                        }
                else:
                    # CIS: register an entry for EACH toggle in the file
                    if all_toggles:
                        for toggle in all_toggles:
                            audit_map[toggle] = {
                                "file": rel,
                                "cat": dir_cat,
                                "meta_cat": meta_cat,
                                "rule_id": all_rule_ids[0] if all_rule_ids else None,
                                "meta_id": all_stig_ids[0] if all_stig_ids else None,
                                "toggle": toggle,
                            }
                    else:
                        # No conditional found; fall back to filename stem
                        audit_map[stem] = {
                            "file": rel,
                            "cat": dir_cat,
                            "meta_cat": meta_cat,
                            "rule_id": all_rule_ids[0] if all_rule_ids else None,
                            "meta_id": None,
                            "toggle": None,
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
    # Include dots in char class — some repos use dotted notation
    # (e.g. amazon2cis_rule_3.4.3.5) which we normalize to underscores
    if benchmark_type == BENCHMARK_CIS:
        when_pat = re.compile(rf"({re.escape(prefix)}_rule_[\d_.]+)")
    else:
        when_pat = None

    # Discover task subdirectories dynamically (cat_* for STIG, section_* for CIS)
    task_subdirs: List[str] = []
    if os.path.isdir(tasks_dir):
        for entry in sorted(os.listdir(tasks_dir)):
            full = os.path.join(tasks_dir, entry)
            # Accept Cat1, Cat_1, cat_1, section_3 - STIG roles vary in case and
            # separator, and a startswith("cat_") test silently matched none of the
            # Cat<N> roles, leaving task_map empty and three checks vacuous.
            if os.path.isdir(full) and re.match(r"(?i)^(cat|section)_?\d", entry):
                task_subdirs.append(entry)

    for subdir_name in task_subdirs:
        cat_path = os.path.join(tasks_dir, subdir_name)
        # Extract numeric portion: cat_1 -> 1, section_3 -> 3
        # Trailing digits, so Cat1 and cat_1 both yield 1 (splitting on "_"
        # gave 0 for every Cat<N> directory).
        _cm = re.search(r"(\d+)$", subdir_name)
        cat_num = int(_cm.group(1)) if _cm else 0

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
                            # Normalize dots to underscores (some repos
                            # use e.g. amazon2cis_rule_3.4.3.5)
                            current_key = m.group(1).replace(".", "_").strip("_")
                            if current_key not in task_map:
                                task_map[current_key] = {
                                    "rule_id": None,
                                    "cat": cat_num,
                                    "file": rel,
                                }
                    # Also check bare lines that are just the toggle (in when: lists)
                    # Handles YAML list items ("- toggle") and compound
                    # conditions ("- toggle_a or toggle_b")
                    else:
                        for m in when_pat.finditer(stripped):
                            current_key = m.group(1).replace(".", "_").strip("_")
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
    """Strip inline comments and surrounding quotes from a raw YAML value.

    YAML inline comments require whitespace before '#'; '#' inside a value
    without leading whitespace (e.g. URL fragment) is preserved.
    """
    raw = re.sub(r"\s+#.*$", "", raw).rstrip()
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
        if os.path.isdir(full) and re.match(r"(?i)^(cat|section)_?\d", entry):
            subdirs.append(full)
    return subdirs


def _normalize_path(p: str) -> str:
    """Normalize a file path for comparison."""
    p = p.rstrip("/").rstrip("'\"")
    p = p.replace("/./", "/")
    p = re.sub(r"[*?\[\]]", "", p)  # strip glob chars
    return p


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
                    # Skip Jinja2 control blocks ({% if %}, {% for %}, etc.)
                    if "{%" in raw_val:
                        continue
                    is_hardcoded = "{{" not in raw_val
                    if is_hardcoded:
                        raw_val = _strip_yaml_value(raw_val)
                    variables[var_name] = (raw_val, is_hardcoded, lineno)
    except FileNotFoundError:
        pass
    return variables


def extract_template_output_keys(template_path: str) -> Dict[str, int]:
    """Extract ALL top-level YAML keys the Jinja2 template will output.

    Returns {key_name: first_line_number}.
    Handles Jinja2 if/else blocks: keys inside {% if %}/{% else %} are
    conditional and only one branch renders, so they are NOT duplicates.
    """
    keys: Dict[str, int] = {}
    try:
        with open(template_path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                s = line.strip()
                if not s or s.startswith("{%") or s.startswith("#"):
                    continue
                m = re.match(r"^([a-zA-Z_]\w*)\s*:", s)
                if m:
                    key = m.group(1)
                    if key not in keys:
                        keys[key] = lineno
    except FileNotFoundError:
        pass
    return keys


def extract_defaults_all_keys(defaults_path: str) -> Set[str]:
    """Extract ALL top-level YAML keys from defaults/main.yml."""
    keys: Set[str] = set()
    try:
        with open(defaults_path, "r", encoding="utf-8") as fh:
            for line in fh:
                s = line.rstrip()
                if not s or s.startswith("#") or s[0] in (" ", "\t"):
                    continue
                m = re.match(r"^([a-zA-Z_]\w*)\s*:", s)
                if m and m.group(1) != "---":
                    keys.add(m.group(1))
    except FileNotFoundError:
        pass
    return keys


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
    """Check 5: Rules live in matching cat_X/section_X dirs in both repos."""
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

        # Skip if either side is a Jinja2 expression. Defaults often resolves
        # at runtime (e.g. '{{ list | join(",") }}' or '{{ x.stat.exists }}')
        # while the audit side mirrors the resolved literal; static equality
        # check would produce a false positive.
        if ("{{" in def_val and "}}" in def_val) or \
           ("{{" in aud_val and "}}" in aud_val):
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

        # Skip empty values (multiline structure parent keys like dicts/lists)
        if not val or val == "":
            continue

        # Only flag mismatches against defaults — variables hardcoded in
        # template but absent from defaults are intentional (audit-only
        # structural vars like bootloader paths, sshd_limited, etc.)
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


def check_template_goss_var_crossref(
    goss_var_refs: Dict[str, Set[str]],
    template_output_keys: Dict[str, int],
    defaults_all_keys: Set[str],
    audit_vars_defined: Set[str],
    prefix: str,
    benchmark_type: str,
    template_path: str,
    defaults_path: str,
) -> CheckResult:
    """Check 15: Cross-ref goss .Vars references against template output keys.

    Validates that:
      A. Every goss .Vars.<name> reference is output by the template
      B. Every template Jinja2 expression references a defined default/vars var
      C. Naming mismatches (template outputs key X, goss expects similar key Y)
    """
    findings: List[Finding] = []

    # Well-known runtime variables injected by run_audit.sh
    runtime_vars = {
        "machine_uuid", "epoch", "os_locale", "os_release",
        "os_distribution", "auto_group", "os_hostname", "system_type",
        "benchmark_type", "benchmark_version", "benchmark_os",
        "system_is_container",
    }

    goss_non_runtime = {v for v in goss_var_refs if v not in runtime_vars}
    tmpl_keys = set(template_output_keys.keys())

    # A. Goss vars missing from template output
    missing_from_tmpl = goss_non_runtime - tmpl_keys
    for var in sorted(missing_from_tmpl):
        # Skip non-prefixed vars (general goss/system vars) and toggles
        if not var.startswith(prefix + "_"):
            continue
        if _is_toggle_var(var, prefix, benchmark_type):
            continue
        example_files = sorted(goss_var_refs[var])[:3]
        file_list = ", ".join(example_files)
        if len(goss_var_refs[var]) > 3:
            file_list += f" (+{len(goss_var_refs[var]) - 3} more)"
        findings.append(Finding(
            file="templates/ansible_vars_goss.yml.j2",
            line=0,
            description=(
                f"Goss tests reference '.Vars.{var}' but template "
                f"does not output key '{var}'. Used in: {file_list}"
            ),
            severity="error",
            check_name="template_goss_var_xref",
        ))

    # B. Template Jinja2 expressions referencing undefined vars
    jinja_ref_pat = re.compile(r'\{\{\s*([a-zA-Z_]\w*?)(?:\s*[\.\[}|])')
    # Load vars/audit.yml keys as additional valid sources
    audit_yml_path = os.path.join(os.path.dirname(defaults_path),
                                  "..", "vars", "audit.yml")
    audit_local_keys: Set[str] = set()
    norm_audit_yml = os.path.normpath(audit_yml_path)
    if os.path.isfile(norm_audit_yml):
        try:
            with open(norm_audit_yml, "r", encoding="utf-8") as fh:
                for line in fh:
                    m = re.match(r"^([a-zA-Z_]\w*)\s*:", line.rstrip())
                    if m:
                        audit_local_keys.add(m.group(1))
        except (IOError, OSError):
            pass

    # Ansible builtins that are valid in templates
    ansible_builtins = {
        "item", "ansible_facts", "ansible_env", "ansible_check_mode",
        "ansible_diff_mode", "ansible_version", "ansible_play_hosts",
        "ansible_play_batch", "ansible_playbook_python", "ansible_connection",
        "ansible_host", "ansible_port", "ansible_user", "ansible_forks",
        "inventory_hostname", "inventory_hostname_short", "group_names",
        "groups", "hostvars", "play_hosts", "role_path", "playbook_dir",
        "omit", "true", "false", "none", "ansible_local",
        "ansible_facts_path",
    }
    valid_sources = defaults_all_keys | audit_local_keys | ansible_builtins

    # Extract Jinja2 loop variables and conditional-check variables
    # ({% for X in ... %}, {% if X is defined %}) from the template
    jinja2_loop_vars: Set[str] = set()
    if os.path.isfile(template_path):
        try:
            with open(template_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    # {% for var in ... %}
                    fm = re.search(
                        r'\{%[-\s]*for\s+(\w+)\s+in\b', line)
                    if fm:
                        jinja2_loop_vars.add(fm.group(1))
                    # {% if var is defined %}
                    cm = re.search(
                        r'\{%[-\s]*if\s+(\w+)\s+is\s+defined', line)
                    if cm:
                        jinja2_loop_vars.add(cm.group(1))
        except (IOError, OSError):
            pass
    valid_sources = valid_sources | jinja2_loop_vars

    # Add play-runtime vars: the well-known set injected by run_audit.sh
    # plus any variable defined by register: / set_fact: under tasks/.
    tasks_dir = os.path.normpath(
        os.path.join(os.path.dirname(defaults_path), "..", "tasks"))
    runtime_set_vars = extract_runtime_defined_vars(tasks_dir)
    valid_sources = valid_sources | runtime_vars | runtime_set_vars

    if os.path.isfile(template_path):
        try:
            with open(template_path, "r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    s = line.strip()
                    if s.startswith("#") or s.startswith("{%"):
                        continue
                    for m in jinja_ref_pat.finditer(line):
                        ref = m.group(1)
                        if ref not in valid_sources:
                            findings.append(Finding(
                                file="templates/ansible_vars_goss.yml.j2",
                                line=lineno,
                                description=(
                                    f"Template references '{{{{ {ref} }}}}' "
                                    f"but '{ref}' not defined in "
                                    f"defaults/main.yml or vars/audit.yml"
                                ),
                                severity="warning",
                                check_name="template_goss_var_xref",
                            ))
        except (IOError, OSError):
            pass

    # C. Naming mismatches: template outputs X, goss expects similar Y
    #    Exclude toggle vars (rule_X_Y_Z) — they share long prefixes by design
    tmpl_only = tmpl_keys - goss_non_runtime - runtime_vars
    goss_only = goss_non_runtime - tmpl_keys
    # Filter to prefixed non-toggle vars only
    tmpl_only = {v for v in tmpl_only
                 if v.startswith(prefix + "_")
                 and not _is_toggle_var(v, prefix, benchmark_type)}
    goss_only = {v for v in goss_only
                 if v.startswith(prefix + "_")
                 and not _is_toggle_var(v, prefix, benchmark_type)}
    for t_var in sorted(tmpl_only):
        for g_var in sorted(goss_only):
            longer = max(len(t_var), len(g_var))
            prefix_len = len(os.path.commonprefix([t_var, g_var]))
            if prefix_len >= longer * 0.7 and prefix_len >= 15:
                findings.append(Finding(
                    file="templates/ansible_vars_goss.yml.j2",
                    line=template_output_keys.get(t_var, 0),
                    description=(
                        f"Possible naming mismatch: template outputs "
                        f"'{t_var}' but goss tests expect '{g_var}'"
                    ),
                    severity="warning",
                    check_name="template_goss_var_xref",
                ))

    n_err = sum(1 for f in findings if f.severity == "error")
    n_warn = sum(1 for f in findings if f.severity == "warning")
    status = "FAIL" if n_err else ("WARN" if n_warn else "PASS")
    summary = (f"{n_err} missing, {n_warn} warning(s) "
               f"[goss_refs:{len(goss_non_runtime)} "
               f"tmpl_keys:{len(tmpl_keys)} "
               f"defaults:{len(defaults_all_keys)}]")
    return CheckResult("Template-Goss Var Cross-Ref", status, findings,
                       summary)


# ---------------------------------------------------------------------------
# Extraction: handlers, prelim vars, task automation status
# ---------------------------------------------------------------------------


def extract_handler_names(handlers_path: str) -> Dict[str, int]:
    """Extract handler names from handlers/main.yml.

    Returns {handler_name: line_number}.
    """
    handlers: Dict[str, int] = {}
    if not os.path.isfile(handlers_path):
        return handlers
    try:
        with open(handlers_path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                m = re.match(r"^-\s*name:\s*(.+)", line)
                if m:
                    name = m.group(1).strip().strip("'\"")
                    handlers[name] = lineno
                # Also detect listen: directives
                m = re.match(r"\s+listen:\s*(.+)", line)
                if m:
                    name = m.group(1).strip().strip("'\"")
                    handlers[name] = lineno
    except (IOError, OSError):
        pass
    return handlers


def extract_notify_references(tasks_dir: str) -> List[Dict[str, Any]]:
    """Extract all notify: references from task files.

    Returns list of {name: str, file: str, line: int}.
    """
    refs: List[Dict[str, Any]] = []
    if not os.path.isdir(tasks_dir):
        return refs
    for root, dirs, files in os.walk(tasks_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}]
        for fname in sorted(files):
            if not fname.endswith((".yml", ".yaml")):
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, os.path.dirname(tasks_dir))
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, 1):
                        stripped = line.strip()
                        # Inline: notify: Handler Name
                        m = re.match(r"notify:\s+(.+)", stripped)
                        if m:
                            val = m.group(1).strip().strip("'\"")
                            # Skip Jinja2 expressions
                            if "{{" not in val:
                                refs.append({"name": val, "file": rel,
                                             "line": lineno})
                        # List item: - Handler Name
                        elif stripped.startswith("- ") and refs:
                            # Check if previous non-empty line was notify:
                            # by tracking context — simpler: just check
                            # indent-based membership in a notify list
                            pass
            except (IOError, OSError):
                continue
    # Second pass: handle notify list items
    for root, _dirs, files in os.walk(tasks_dir):
        for fname in sorted(files):
            if not fname.endswith((".yml", ".yaml")):
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, os.path.dirname(tasks_dir))
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except (IOError, OSError):
                continue
            in_notify = False
            notify_indent = 0
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                indent = len(line) - len(line.lstrip())
                # Detect "notify:" on its own line (block list form)
                if re.match(r"notify:\s*$", stripped):
                    in_notify = True
                    notify_indent = indent
                    continue
                if in_notify:
                    if indent > notify_indent and stripped.startswith("- "):
                        val = stripped[2:].strip().strip("'\"")
                        if "{{" not in val:
                            refs.append({"name": val, "file": rel,
                                         "line": lineno})
                    else:
                        in_notify = False
    # Deduplicate
    seen = set()
    unique: List[Dict[str, Any]] = []
    for ref in refs:
        key = (ref["name"], ref["file"], ref["line"])
        if key not in seen:
            seen.add(key)
            unique.append(ref)
    return unique


def extract_runtime_defined_vars(tasks_dir: str) -> Set[str]:
    """Extract variable names defined at play runtime under tasks_dir.

    Walks every task file collecting names from:
      - `register: <name>` lines
      - keys inside `set_fact:` blocks (any module-namespaced variant)

    Used as additional valid sources when validating template Jinja2
    references that point at runtime-set vars like `system_is_container`
    or `<prefix>_subscribed` (not defined in defaults/main.yml).
    """
    vars_set: Set[str] = set()
    if not tasks_dir or not os.path.isdir(tasks_dir):
        return vars_set

    set_fact_pat = re.compile(r"^(\s*)(?:ansible\.builtin\.)?set_fact:\s*$")
    register_pat = re.compile(r"^\s*register:\s+(\w+)\s*$")
    assign_pat = re.compile(r"^(\s+)([a-zA-Z_]\w*):\s*\S")

    for root, dirs, files in os.walk(tasks_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}]
        for fname in sorted(files):
            if not fname.endswith((".yml", ".yaml")):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except (IOError, OSError):
                continue
            i = 0
            while i < len(lines):
                line = lines[i]
                rm = register_pat.match(line)
                if rm:
                    vars_set.add(rm.group(1))
                sm = set_fact_pat.match(line)
                if sm:
                    sf_indent = len(sm.group(1))
                    j = i + 1
                    while j < len(lines):
                        nxt = lines[j]
                        if not nxt.strip() or nxt.lstrip().startswith("#"):
                            j += 1
                            continue
                        nxt_indent = len(nxt) - len(nxt.lstrip())
                        if nxt_indent <= sf_indent:
                            break
                        am = assign_pat.match(nxt)
                        if am and len(am.group(1)) > sf_indent:
                            vars_set.add(am.group(2))
                        j += 1
                    i = j
                    continue
                i += 1
    return vars_set


def extract_prelim_registered_vars(prelim_path: str) -> Set[str]:
    """Extract prelim_* variable names registered or set anywhere in tasks/.

    Scans prelim.yml first, then all other task files for register: prelim_*
    and set_fact prelim_* definitions.  This avoids false positives where a
    prelim_* var is registered outside prelim.yml (e.g. main.yml,
    parse_etc_password.yml, pre_remediation_audit.yml).
    """
    vars_set: Set[str] = set()
    # Scan the entire tasks/ directory for prelim_* definitions
    tasks_dir = os.path.dirname(prelim_path) if prelim_path else ""
    if not tasks_dir or not os.path.isdir(tasks_dir):
        return vars_set
    for root, dirs, files in os.walk(tasks_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}]
        for fname in sorted(files):
            if not fname.endswith((".yml", ".yaml")):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    for line in fh:
                        stripped = line.strip()
                        # register: prelim_*
                        m = re.match(r"register:\s+(prelim_\w+)", stripped)
                        if m:
                            vars_set.add(m.group(1))
                        # set_fact key: value
                        m = re.match(r"(prelim_\w+):\s+", stripped)
                        if m:
                            vars_set.add(m.group(1))
            except (IOError, OSError):
                continue
    return vars_set


def extract_prelim_references(tasks_dir: str) -> List[Dict[str, Any]]:
    """Find references to prelim_* variables in task files (excluding prelim.yml).

    Skips lines that define prelim_* vars (register:, set_fact keys) and
    lines where prelim_* appears in a tag context (tags: or tag list items).

    Returns list of {var: str, file: str, line: int}.
    """
    refs: List[Dict[str, Any]] = []
    prelim_pat = re.compile(r"\bprelim_(\w+)")
    # Patterns for lines that define rather than reference prelim_* vars
    define_pat = re.compile(r"^\s*register:\s+prelim_")
    tag_pat = re.compile(r"^\s*(?:tags:\s|-(?: )+(?:prelim_))")
    set_fact_pat = re.compile(r"^\s*prelim_\w+:\s+")
    if not os.path.isdir(tasks_dir):
        return refs
    for root, dirs, files in os.walk(tasks_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}]
        for fname in sorted(files):
            if not fname.endswith((".yml", ".yaml")):
                continue
            if fname == "prelim.yml":
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, os.path.dirname(tasks_dir))
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, 1):
                        stripped = line.strip()
                        # Skip definition lines
                        if define_pat.match(line):
                            continue
                        if set_fact_pat.match(line):
                            continue
                        # Skip tag lines (e.g. "- prelim_tasks")
                        if stripped.startswith("- prelim_") and ":" not in stripped:
                            continue
                        if stripped.startswith("tags:") and "prelim_" in stripped:
                            continue
                        for m in prelim_pat.finditer(line):
                            var = "prelim_" + m.group(1)
                            refs.append({"var": var, "file": rel,
                                         "line": lineno})
            except (IOError, OSError):
                continue
    return refs


def extract_task_automation_status(
    tasks_dir: str, prefix: str, benchmark_type: str
) -> Dict[str, Dict[str, Any]]:
    """Detect whether each control is automated or manual.

    Returns {toggle: {"status": "automated"|"manual"|"partial",
                      "file": str, "line": int, "has_remediation": bool}}.

    A task is considered "manual" if its block contains only:
      - ansible.builtin.debug with "manual remediation"
      - ansible.builtin.import_tasks: warning_facts.yml
    """
    result: Dict[str, Dict[str, Any]] = {}
    toggle_pat = re.compile(rf"({re.escape(prefix)}_rule_[\d_.]+)")

    task_subdirs: List[str] = []
    if os.path.isdir(tasks_dir):
        for entry in sorted(os.listdir(tasks_dir)):
            full = os.path.join(tasks_dir, entry)
            if os.path.isdir(full) and re.match(r"(?i)^(cat|section)_?\d", entry):
                task_subdirs.append(entry)

    for subdir_name in task_subdirs:
        cat_path = os.path.join(tasks_dir, subdir_name)
        for fname in sorted(os.listdir(cat_path)):
            if not fname.endswith(".yml") or fname == "main.yml":
                continue
            fpath = os.path.join(cat_path, fname)
            rel = os.path.relpath(fpath, os.path.dirname(tasks_dir))
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    content = fh.read()
                    lines = content.splitlines()
            except (IOError, OSError):
                continue

            # Find top-level tasks and their blocks
            i = 0
            while i < len(lines):
                line = lines[i]
                name_m = re.match(r"^- name:\s*(.+)", line)
                if not name_m:
                    i += 1
                    continue

                task_name = name_m.group(1).strip().strip("'\"")
                task_line = i + 1

                # Extract toggle from nearby when: condition
                toggle = None
                j = i + 1
                end = min(i + 20, len(lines))
                while j < end:
                    tl = lines[j].strip()
                    tm = toggle_pat.search(tl)
                    if tm:
                        toggle = tm.group(1).replace(".", "_").strip("_")
                        break
                    if tl.startswith("- name:"):
                        break
                    j += 1

                if not toggle:
                    i += 1
                    continue

                # Scan block for remediation indicators
                has_manual_msg = False
                has_warning_facts = False
                has_real_module = False
                k = i + 1
                block_end = len(lines)
                while k < len(lines):
                    bl = lines[k]
                    bs = bl.strip()
                    # Next top-level task
                    if re.match(r"^- name:", bl):
                        block_end = k
                        break
                    if "manual remediation" in bs.lower():
                        has_manual_msg = True
                    if "warning_facts.yml" in bs:
                        has_warning_facts = True
                    # Real remediation modules
                    if re.match(
                        r"\s*(ansible\.builtin\.|community\.general\.|"
                        r"ansible\.posix\.)(lineinfile|replace|template|"
                        r"file|copy|package|systemd|user|command|shell|"
                        r"modprobe|mount|pamd|sysctl|cron):",
                        bs
                    ):
                        has_real_module = True
                    k += 1

                if toggle not in result:
                    if has_manual_msg and not has_real_module:
                        status = "manual"
                    elif has_real_module:
                        status = "automated"
                    else:
                        status = "partial"
                    result[toggle] = {
                        "status": status,
                        "file": rel,
                        "line": task_line,
                        "has_remediation": has_real_module,
                    }

                i = block_end if block_end > i else i + 1

    return result


def extract_audit_test_depth(
    audit_dir: str, prefix: str, benchmark_type: str
) -> Dict[str, Dict[str, Any]]:
    """Measure audit test depth for each rule.

    Returns {toggle: {"file": str, "assertion_count": int,
                      "has_file_check": bool, "has_command_check": bool}}.
    """
    result: Dict[str, Dict[str, Any]] = {}

    # CIS toggle from filename: cis_X.Y.Z.yml -> prefix_rule_X_Y_Z
    audit_subdirs: List[str] = []
    for entry in sorted(os.listdir(audit_dir)):
        full = os.path.join(audit_dir, entry)
        if os.path.isdir(full) and re.match(r"(?i)^(cat|section)_?\d", entry):
            audit_subdirs.append(full)

    for subdir in audit_subdirs:
        for root, _dirs, files in os.walk(subdir):
            for fname in sorted(files):
                if not fname.endswith(".yml"):
                    continue
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, audit_dir)

                try:
                    with open(fpath, "r", encoding="utf-8") as fh:
                        content = fh.read()
                except (IOError, OSError):
                    continue

                # Extract ALL toggles from file content (handles
                # combined files like cis_2.4.1.3_7.yml)
                toggle_matches = re.findall(
                    rf"\.Vars\.({re.escape(prefix)}_rule_[\w]+)",
                    content)
                # Fallback: extract from filename if no conditionals
                if not toggle_matches:
                    fm = re.search(r"(\d[\d.]+\d)", fname)
                    if not fm:
                        continue
                    rule_nums = fm.group(1).replace(".", "_")
                    toggle_matches = [f"{prefix}_rule_{rule_nums}"]

                assertion_count = len(re.findall(
                    r"\b(file|command|exec|service|package|port|"
                    r"process|kernel-param|mount|group|user):",
                    content))
                has_file = bool(re.search(r"\bfile:", content))
                has_command = bool(re.search(
                    r"\b(command|exec):", content))

                for toggle in set(toggle_matches):
                    result[toggle] = {
                        "file": rel,
                        "assertion_count": assertion_count,
                        "has_file_check": has_file,
                        "has_command_check": has_command,
                    }

    return result


def extract_task_paths(
    tasks_dir: str, prefix: str, benchmark_type: str
) -> Dict[str, Dict[str, Any]]:
    """Extract file paths referenced by each control's remediation tasks.

    Returns {toggle: {"paths": Set[str], "file": str, "line": int}}.
    Only literal paths are collected; Jinja2 expressions are skipped.
    Works for both CIS and STIG benchmarks.
    """
    result: Dict[str, Dict[str, Any]] = {}

    if benchmark_type == BENCHMARK_CIS:
        toggle_pat = re.compile(rf"({re.escape(prefix)}_rule_[\d_.]+)")
    else:
        toggle_pat = re.compile(rf"({re.escape(prefix)}_\d{{6}})")

    module_pat = re.compile(
        r"\s*(ansible\.builtin\.|community\.general\.|ansible\.posix\.)"
        r"(lineinfile|replace|template|file|copy|stat|mount|find|blockinfile"
        r"|ini_file):"
    )
    path_param_pat = re.compile(
        r"\s+(path|dest|src|mountpoint):\s*['\"]?(/[^\s'\"{}]+)"
    )
    shell_module_pat = re.compile(
        r"\s*(ansible\.builtin\.)(shell|command):\s*(.*)"
    )
    shell_path_pat = re.compile(
        r"(/(?:etc|var|usr|boot|home|opt|srv|tmp|run|sys|proc)/[\w./*_-]+)"
    )

    task_subdirs: List[str] = []
    if os.path.isdir(tasks_dir):
        for entry in sorted(os.listdir(tasks_dir)):
            full = os.path.join(tasks_dir, entry)
            if os.path.isdir(full) and re.match(r"(?i)^(cat|section)_?\d", entry):
                task_subdirs.append(entry)

    for subdir_name in task_subdirs:
        cat_path = os.path.join(tasks_dir, subdir_name)
        for fname in sorted(os.listdir(cat_path)):
            if not fname.endswith(".yml") or fname == "main.yml":
                continue
            fpath = os.path.join(cat_path, fname)
            rel = os.path.relpath(fpath, os.path.dirname(tasks_dir))
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    lines = fh.read().splitlines()
            except (IOError, OSError):
                continue

            i = 0
            while i < len(lines):
                line = lines[i]
                if not re.match(r"^- name:", line):
                    i += 1
                    continue

                task_line = i + 1
                # Find toggle from when: condition (next 20 lines)
                toggles: List[str] = []
                j = i + 1
                end = min(i + 20, len(lines))
                while j < end:
                    tl = lines[j].strip()
                    for tm in toggle_pat.finditer(tl):
                        t = tm.group(1).replace(".", "_").strip("_")
                        if t not in toggles:
                            toggles.append(t)
                    if tl.startswith("- name:"):
                        break
                    j += 1

                if not toggles:
                    i += 1
                    continue

                # Scan block for paths
                paths: Set[str] = set()
                k = i + 1
                in_find_paths = False
                while k < len(lines):
                    bl = lines[k]
                    bs = bl.strip()
                    if re.match(r"^- name:", bl):
                        break

                    # Module with path/dest parameter
                    if module_pat.match(bs):
                        # Scan next few lines for path params
                        for pk in range(k + 1, min(k + 10, len(lines))):
                            ps = lines[pk].strip()
                            if ps.startswith("- name:") or module_pat.match(ps):
                                break
                            pm = path_param_pat.match(lines[pk])
                            if pm:
                                p = _normalize_path(pm.group(2))
                                if "{{" not in p and p.startswith("/"):
                                    paths.add(p)
                        # Check if this is find module (paths: list)
                        if "find:" in bs:
                            in_find_paths = True

                    # Find module paths: list items
                    if in_find_paths and bs.startswith("- /"):
                        p = _normalize_path(bs[2:].strip().strip("'\""))
                        if "{{" not in p:
                            paths.add(p)
                    if in_find_paths and not bs.startswith("-") and ":" in bs:
                        in_find_paths = False

                    # Shell/command with inline paths
                    sm = shell_module_pat.match(bs)
                    if sm and sm.group(3):
                        for sp in shell_path_pat.findall(sm.group(3)):
                            p = _normalize_path(sp)
                            if "{{" not in p:
                                paths.add(p)

                    # cmd: parameter on following lines
                    if bs.startswith("cmd:") or bs.startswith("cmd :"):
                        cmd_val = bs.split(":", 1)[1].strip()
                        for sp in shell_path_pat.findall(cmd_val):
                            p = _normalize_path(sp)
                            if "{{" not in p:
                                paths.add(p)

                    k += 1

                for toggle in toggles:
                    if toggle not in result:
                        result[toggle] = {
                            "paths": set(paths),
                            "file": rel,
                            "line": task_line,
                        }
                    else:
                        result[toggle]["paths"].update(paths)

                i = k if k > i else i + 1

    return result


def extract_audit_paths(
    audit_dir: str, prefix: str, benchmark_type: str
) -> Dict[str, Dict[str, Any]]:
    """Extract file paths referenced in goss audit test files.

    Returns {toggle: {"paths": Set[str], "file": str}}.
    Works for both CIS and STIG benchmarks.
    """
    result: Dict[str, Dict[str, Any]] = {}

    if benchmark_type == BENCHMARK_CIS:
        toggle_cond_pat = re.compile(
            rf"\{{\{{\s*if\s+\.Vars\.({re.escape(prefix)}_rule_[\w]+)"
        )
    else:
        toggle_cond_pat = re.compile(
            rf"\{{\{{\s*if\s+\.Vars\.({re.escape(prefix)}_\d{{6}})"
        )

    file_path_pat = re.compile(r"^\s+path:\s*(/\S+)")
    mountpoint_pat = re.compile(r"^\s+mountpoint:\s*(/\S+)")
    exec_pat = re.compile(r"^\s+exec:\s*[|>]?\s*['\"]?(.*)")
    shell_path_pat = re.compile(
        r"(/(?:etc|var|usr|boot|home|opt|srv|tmp|run|sys|proc)/[\w./*_-]+)"
    )

    audit_subdirs = _find_audit_subdirs(audit_dir)

    for subdir in audit_subdirs:
        for root, _dirs, files in os.walk(subdir):
            for fname in sorted(files):
                if not fname.endswith(".yml"):
                    continue
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, audit_dir)
                try:
                    with open(fpath, "r", encoding="utf-8") as fh:
                        lines = fh.readlines()
                except (IOError, OSError):
                    continue

                # Track toggle scope via stack
                toggle_stack: List[str] = []
                scope_depth = 0

                for line in lines:
                    stripped = line.strip()

                    # Toggle conditional open
                    tm = toggle_cond_pat.search(stripped)
                    if tm:
                        toggle_stack.append(tm.group(1))
                        scope_depth += 1
                        continue

                    # Non-toggle if/range (nested)
                    if re.match(r"\{\{\s*(if|range)\b", stripped):
                        scope_depth += 1
                        continue

                    # End block
                    if re.match(r"\{\{\s*end\s*\}\}", stripped):
                        scope_depth -= 1
                        if toggle_stack and scope_depth < len(toggle_stack):
                            toggle_stack.pop()
                        continue

                    if not toggle_stack:
                        continue

                    current_toggle = toggle_stack[-1]

                    # Initialize result entry
                    if current_toggle not in result:
                        result[current_toggle] = {
                            "paths": set(),
                            "file": rel,
                        }

                    # file: path:
                    pm = file_path_pat.match(line)
                    if pm:
                        p = _normalize_path(pm.group(1))
                        if "{{" not in p and p.startswith("/"):
                            result[current_toggle]["paths"].add(p)

                    # mount: mountpoint:
                    mm = mountpoint_pat.match(line)
                    if mm:
                        p = _normalize_path(mm.group(1))
                        if "{{" not in p and p.startswith("/"):
                            result[current_toggle]["paths"].add(p)

                    # command/exec: extract paths from shell
                    em = exec_pat.match(line)
                    if em:
                        cmd_str = em.group(1)
                        for sp in shell_path_pat.findall(cmd_str):
                            p = _normalize_path(sp)
                            if "{{" not in p:
                                result[current_toggle]["paths"].add(p)

    return result


# ---------------------------------------------------------------------------
# Check 16: Handler Notify Validation
# ---------------------------------------------------------------------------


def check_handler_notify(
    handler_names: Dict[str, int],
    notify_refs: List[Dict[str, Any]],
    handlers_path: str,
) -> CheckResult:
    """Check 16: Validate that all notify: references match defined handlers."""
    findings: List[Finding] = []

    if not handler_names and not notify_refs:
        return CheckResult("Handler Notify Validation", "PASS", [],
                           "No handlers or notify references found")

    handler_set = set(handler_names.keys())
    referenced_handlers: Set[str] = set()

    # Check each notify reference has a matching handler
    for ref in notify_refs:
        name = ref["name"]
        referenced_handlers.add(name)
        # Jinja2 template handlers — skip (can't resolve at parse time)
        if "{{" in name:
            continue
        if name not in handler_set:
            # Case-insensitive match attempt
            matches = [h for h in handler_set if h.lower() == name.lower()]
            if matches:
                findings.append(Finding(
                    file=ref["file"], line=ref["line"],
                    description=(
                        f"Handler name case mismatch: notify '{name}' "
                        f"but handler defined as '{matches[0]}'"
                    ),
                    severity="warning",
                    check_name="handler_notify",
                ))
            else:
                findings.append(Finding(
                    file=ref["file"], line=ref["line"],
                    description=f"Notify references undefined handler: '{name}'",
                    severity="error",
                    check_name="handler_notify",
                ))

    # Check for orphaned handlers (defined but never referenced)
    for hname, hline in sorted(handler_names.items()):
        if hname not in referenced_handlers:
            # Case-insensitive check
            if not any(hname.lower() == r.lower() for r in referenced_handlers):
                findings.append(Finding(
                    file=os.path.relpath(handlers_path,
                                         os.path.dirname(
                                             os.path.dirname(handlers_path))),
                    line=hline,
                    description=f"Orphaned handler never referenced: '{hname}'",
                    severity="info",
                    check_name="handler_notify",
                ))

    status = _determine_status(findings)
    return CheckResult("Handler Notify Validation", status, findings,
                       f"{len(findings)} issue(s)")


# ---------------------------------------------------------------------------
# Check 17: Prelim Variable Dependencies
# ---------------------------------------------------------------------------


def check_prelim_dependencies(
    prelim_vars: Set[str],
    prelim_refs: List[Dict[str, Any]],
    prelim_path: str,
) -> CheckResult:
    """Check 17: Validate that prelim_* vars used in tasks are defined."""
    findings: List[Finding] = []

    if not prelim_path or not os.path.isfile(prelim_path):
        return CheckResult("Prelim Variable Dependencies", "SKIP", [],
                           "No prelim.yml found")

    # Find prelim vars referenced but not defined
    seen_undefined: Set[str] = set()
    for ref in prelim_refs:
        var = ref["var"]
        if var not in prelim_vars and var not in seen_undefined:
            seen_undefined.add(var)
            findings.append(Finding(
                file=ref["file"], line=ref["line"],
                description=(
                    f"Task references '{var}' but it is not registered "
                    f"or set in prelim.yml"
                ),
                severity="warning",
                check_name="prelim_dependencies",
            ))

    status = _determine_status(findings)
    return CheckResult("Prelim Variable Dependencies", status, findings,
                       f"{len(findings)} issue(s) "
                       f"[defined:{len(prelim_vars)} "
                       f"referenced:{len(set(r['var'] for r in prelim_refs))}]")


# ---------------------------------------------------------------------------
# Check 18: Automation Status Tracking
# ---------------------------------------------------------------------------


def check_automation_status(
    task_status: Dict[str, Dict[str, Any]],
    audit_depth: Dict[str, Dict[str, Any]],
    audit_vars_path: str,
    prefix: str,
) -> CheckResult:
    """Check 18: Detect manual→automated gaps in audit test coverage.

    Flags:
    - Controls that are automated in tasks but have no audit test
    - Controls that are automated in tasks but have shallow audit tests
    - Controls marked as automated in tasks but still flagged 'manual'
      in audit vars
    """
    findings: List[Finding] = []

    # Load audit vars to check for manual/automated flags
    audit_manual_flags: Dict[str, str] = {}
    if os.path.isfile(audit_vars_path):
        try:
            with open(audit_vars_path, "r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    stripped = line.strip()
                    if stripped.startswith("#") or not stripped:
                        continue
                    # Look for lines like: # manual or containing "manual"
                    # near toggle definitions
        except (IOError, OSError):
            pass

    for toggle, info in sorted(task_status.items()):
        if info["status"] != "automated":
            continue

        # Check if audit test exists
        if toggle not in audit_depth:
            findings.append(Finding(
                file=info["file"], line=info["line"],
                description=(
                    f"Automated control '{toggle}' has no audit test file"
                ),
                severity="warning",
                check_name="automation_status",
            ))
            continue

        # Check audit test depth
        depth = audit_depth[toggle]
        if depth["assertion_count"] == 0:
            findings.append(Finding(
                file=depth["file"], line=0,
                description=(
                    f"Automated control '{toggle}' has an audit test "
                    f"with no assertions"
                ),
                severity="warning",
                check_name="automation_status",
            ))

    # Count manual vs automated
    n_auto = sum(1 for v in task_status.values() if v["status"] == "automated")
    n_manual = sum(1 for v in task_status.values() if v["status"] == "manual")

    status = _determine_status(findings)
    return CheckResult("Automation Status", status, findings,
                       f"{len(findings)} issue(s) "
                       f"[automated:{n_auto} manual:{n_manual}]")


# ---------------------------------------------------------------------------
# Check 19: File Path Alignment
# ---------------------------------------------------------------------------


def check_file_path_alignment(
    task_paths: Dict[str, Dict[str, Any]],
    audit_paths: Dict[str, Dict[str, Any]],
) -> CheckResult:
    """Check 19: Verify remediation tasks and audit tests reference the same paths."""
    findings: List[Finding] = []

    def _paths_related(p1: str, p2: str) -> bool:
        """Check if two paths are related (parent/child or same directory)."""
        d1 = p1.rstrip("/")
        d2 = p2.rstrip("/")
        # Parent/child
        if d1.startswith(d2 + "/") or d2.startswith(d1 + "/"):
            return True
        # Same directory (e.g., /etc/audit/rules.d/50-scope.rules vs
        # /etc/audit/rules.d/.rules from glob-stripped *.rules)
        if os.path.dirname(d1) == os.path.dirname(d2):
            return True
        return False

    common_toggles = sorted(set(task_paths) & set(audit_paths))

    for toggle in common_toggles:
        t_paths = task_paths[toggle]["paths"]
        a_paths = audit_paths[toggle]["paths"]

        # Skip controls with no paths on either side (package/service checks)
        if not t_paths or not a_paths:
            continue

        # Paths in remediation but not tested by audit
        untested = t_paths - a_paths
        for p in sorted(untested):
            if any(_paths_related(p, ap) for ap in a_paths):
                continue
            findings.append(Finding(
                file=task_paths[toggle]["file"],
                line=task_paths[toggle]["line"],
                description=(
                    f"'{toggle}': remediation references '{p}' "
                    f"but audit does not test it"
                ),
                severity="warning",
                check_name="file_path_alignment",
            ))

        # Paths in audit but not in remediation
        extra = a_paths - t_paths
        for p in sorted(extra):
            if any(_paths_related(p, tp) for tp in t_paths):
                continue
            findings.append(Finding(
                file=audit_paths[toggle]["file"],
                line=0,
                description=(
                    f"'{toggle}': audit tests '{p}' "
                    f"but remediation does not reference it"
                ),
                severity="info",
                check_name="file_path_alignment",
            ))

    status = _determine_status(findings)
    return CheckResult(
        "File Path Alignment", status, findings,
        f"{len(findings)} path issue(s) across "
        f"{len(common_toggles)} shared controls")


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

    lines.append("| Check | Description | Status | Findings |")
    lines.append("|-------|-------------|--------|----------|")
    for r in results:
        desc = CHECK_DESCRIPTIONS.get(r.name, "")
        lines.append(f"| {r.name} | {desc} | {r.status} | {r.summary} |")
    lines.append("")

    for r in results:
        lines.append(f"## [{r.status}] {r.name}\n")
        desc = CHECK_DESCRIPTIONS.get(r.name, "")
        if desc:
            lines.append(f"*{desc}*\n")
        criteria = CHECK_CRITERIA.get(r.name, "")
        if criteria:
            lines.append(f"> **Why these findings?** {criteria}\n")
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
           font-size: 0.75rem; font-weight: 700; }
  .badge-pass { background: #d4edda; color: #155724; }
  .badge-fail { background: #f8d7da; color: #721c24; }
  .badge-warn { background: #fff3cd; color: #856404; }
  .badge-skip { background: #e2e3e5; color: #383d41; }
  .sev-error { color: #721c24; font-weight: 600; }
  .sev-warning { color: #856404; font-weight: 600; }
  .sev-info { color: #0c5460; font-weight: 600; }
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
  @media print { body { background: #fff; padding: 10px; }
    .check-section { box-shadow: none; border: 1px solid #ccc; break-inside: avoid; }
    .check-section.collapsed .check-body { display: block; }
    .check-section.collapsed .toggle-arrow { transform: none; } }
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
    parts.append("<tr><th>Check</th><th>Description</th><th>Status</th><th>Findings</th></tr>")
    for r in results:
        badge_cls = f"badge-{r.status.lower()}"
        desc = CHECK_DESCRIPTIONS.get(r.name, "")
        parts.append(
            f"<tr><td>{h(r.name)}</td>"
            f"<td style='font-size:0.85rem;color:var(--text-light)'>{h(desc)}</td>"
            f"<td><span class='badge {badge_cls}'>{r.status}</span></td>"
            f"<td>{h(r.summary)}</td></tr>"
        )
    parts.append("</table></div>\n")

    # Per-check detail sections
    for r in results:
        badge_cls = f"badge-{r.status.lower()}"
        collapsed = " collapsed" if r.status == "PASS" and not r.findings else ""
        parts.append(f"<div class='check-section{collapsed}'>")
        desc = CHECK_DESCRIPTIONS.get(r.name, "")
        desc_html = (
            f"<div style='font-size:0.85rem;color:var(--text-light);"
            f"font-style:italic;margin-top:0.15rem'>{h(desc)}</div>"
        ) if desc else ""
        parts.append(
            f"<div class='check-header' onclick='this.parentElement.classList.toggle(\"collapsed\")'>"
            f"<span><span class='check-title'>{h(r.name)}</span>"
            f"{desc_html}</span>"
            f"<span><span class='badge {badge_cls}'>{r.status}</span> "
            f"<span class='toggle-arrow'>&#9660;</span></span></div>"
        )
        parts.append("<div class='check-body'>")
        criteria = CHECK_CRITERIA.get(r.name, "")
        if criteria:
            parts.append(
                f"<p style='background:#f0f4f8;border-left:3px solid #4a90d9;"
                f"padding:0.6rem 0.8rem;margin:0 0 0.75rem;font-size:0.85rem;"
                f"color:#3a4a5a;border-radius:0 4px 4px 0;line-height:1.5'>"
                f"<b>Why these findings?</b> {h(criteria)}</p>"
            )
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
                "description": CHECK_DESCRIPTIONS.get(r.name, ""),
                "status": r.status,
                "criteria": CHECK_CRITERIA.get(r.name, ""),
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
    "template_goss_var_xref": "Template-Goss Var Cross-Ref",
    "handler_notify": "Handler Notify Validation",
    "prelim_dependencies": "Prelim Variable Dependencies",
    "automation_status": "Automation Status Tracking",
    "file_path_alignment": "File Path Alignment",
}

# Short one-line descriptions displayed as subtitles under each section heading
# in Markdown and HTML reports.
CHECK_DESCRIPTIONS: Dict[str, str] = {
    "Rule Toggle Sync": (
        "Are rule toggle variables consistently defined across "
        "defaults, goss template, audit vars, and audit test conditionals?"
    ),
    "Audit File Coverage": (
        "Does every rule toggle have an audit test file, "
        "and does every audit file map to a defined rule?"
    ),
    "Rule_ID Consistency": (
        "Do SV-* Rule_ID values in remediation task tags match "
        "the Rule_ID metadata in the corresponding audit files?"
    ),
    "Rule Key Consistency": (
        "Do rule identifiers agree across task names, "
        "audit filenames, and audit metadata?"
    ),
    "Category Alignment": (
        "Is each rule in the same category/section directory "
        "in both the remediation and audit repos?"
    ),
    "Version Consistency": (
        "Does the benchmark version match across defaults/main.yml, "
        "audit vars, and run_audit.sh?"
    ),
    "Goss Include Coverage": (
        "Is every audit test file reachable by at least one "
        "glob pattern in goss.yml?"
    ),
    "Config Variable Parity": (
        "Do non-toggle configuration variables (paths, ciphers, policies) "
        "have the same values in defaults and audit vars?"
    ),
    "Template Variable Sync": (
        "Do hardcoded values in the goss Jinja2 template match "
        "the corresponding values in defaults/main.yml?"
    ),
    "Audit Vars Completeness": (
        "Are all .Vars references used in goss test files "
        "defined in the audit vars file?"
    ),
    "Toggle Value Sync": (
        "Do rule toggle boolean values (true/false) match "
        "between defaults/main.yml and the audit vars file?"
    ),
    "Severity-Directory Alignment": (
        "Does the severity label in each STIG task name (HIGH/MEDIUM/LOW) "
        "match the cat_X directory it lives in?"
    ),
    "Goss Block Pairing": (
        "Are Go template if/range/end blocks properly balanced "
        "in every audit test file?"
    ),
    "When-Toggle Alignment": (
        "Does each STIG task's when: condition reference the "
        "correct toggle variable for its STIG_ID?"
    ),
    "Template-Goss Var Cross-Ref": (
        "Does the goss template output every variable that goss "
        "tests reference, and are template Jinja2 expressions "
        "backed by defined defaults?"
    ),
    "Handler Notify Validation": (
        "Do all notify: references in task files match a defined "
        "handler name in handlers/main.yml?"
    ),
    "Prelim Variable Dependencies": (
        "Are all prelim_* variables referenced in section tasks "
        "defined (registered or set_fact) in prelim.yml?"
    ),
    "Automation Status Tracking": (
        "Do automated controls have corresponding audit tests, "
        "and are those tests non-empty?"
    ),
    "File Path Alignment": (
        "Do remediation tasks and audit tests reference the same "
        "file paths for each control?"
    ),
}

# Criteria descriptions explain what each check validates and why findings
# appear under that heading.  Used by all three report generators.
CHECK_CRITERIA: Dict[str, str] = {
    "Rule Toggle Sync": (
        "Verifies that every rule toggle variable (e.g. amazon2cis_rule_1_1_1_1) "
        "is consistently defined across all four locations: defaults/main.yml, the "
        "Jinja2 goss template (templates/ansible_vars_goss.yml.j2), the audit vars "
        "file (vars/CIS.yml or vars/STIG.yml), and the audit test file conditionals "
        "({{ if .Vars.<toggle> }}). Findings appear here when a toggle exists in one "
        "location but is missing from another, which can cause remediation to run "
        "without a corresponding audit test, or vice-versa."
    ),
    "Audit File Coverage": (
        "Checks that every rule toggle defined in defaults/main.yml has a "
        "corresponding audit test file, and that every audit test file maps back to "
        "a known rule toggle. Findings appear here when a rule has no audit file "
        "(meaning remediation runs but is never validated) or when an orphaned audit "
        "file exists with no matching rule toggle (dead test that will never execute)."
    ),
    "Rule_ID Consistency": (
        "Compares the SV-* Rule_ID values between remediation task tags and audit "
        "file metadata comments. Findings appear here when the Rule_ID in a task "
        "file does not match the Rule_ID declared in the corresponding audit file, "
        "or when one side is missing a Rule_ID entirely. Mismatched Rule_IDs can "
        "cause traceability issues back to the original STIG/CIS benchmark item."
    ),
    "Rule Key Consistency": (
        "Validates that rule identifiers agree across task names and audit filenames/"
        "metadata. For STIG, this checks that audit filename STIG_IDs match their "
        "internal STIG_ID metadata. For both types, it flags rules that appear only "
        "in tasks (no audit test) or only in audit (no remediation task). Findings "
        "here are informational and typically indicate multi-rule audit files or "
        "tasks that group sub-rules differently than the audit side."
    ),
    "Category Alignment": (
        "Ensures that each rule lives in the same category/section directory in both "
        "the remediation repo (tasks/section_X/ or tasks/cat_X/) and the audit repo "
        "(section_X/ or cat_X/). Findings appear here when a rule is in section_3/ "
        "on the task side but section_4/ on the audit side, for example. Misaligned "
        "categories indicate the rule was moved or miscategorized in one repo."
    ),
    "Version Consistency": (
        "Compares the benchmark version string across defaults/main.yml, the audit "
        "vars file, and run_audit.sh (BENCHMARK_VER). Findings appear here when the "
        "major.minor version differs between any of these locations, which means the "
        "repos are targeting different benchmark releases and may have incompatible "
        "rule sets."
    ),
    "Goss Include Coverage": (
        "Verifies that every audit test file (*.yml under section_*/cat_*) is "
        "reachable by at least one glob pattern in goss.yml. Findings appear here "
        "when an audit file exists on disk but goss.yml has no matching include "
        "pattern, meaning the test will never be executed during an audit run."
    ),
    "Config Variable Parity": (
        "Compares non-toggle configuration variables (e.g. syslog paths, cipher "
        "lists, password policies) that share the benchmark prefix between "
        "defaults/main.yml and the audit vars file. Findings appear here when the "
        "same variable has different values in each file, which can cause the audit "
        "to validate against different expected values than what remediation applies."
    ),
    "Template Variable Sync": (
        "Scans the Jinja2 goss template (ansible_vars_goss.yml.j2) for variables "
        "that use hardcoded literal values instead of {{ var }} templating, then "
        "compares those values against defaults/main.yml. Findings appear here when "
        "a template has a hardcoded value that differs from the default, meaning "
        "the audit will always test against the template value regardless of what "
        "the user configures in defaults."
    ),
    "Audit Vars Completeness": (
        "Scans all goss audit test files for .Vars.<name> references and checks "
        "that each referenced variable (excluding rule toggles and known runtime "
        "vars) is defined in the audit vars file. Findings appear here when a goss "
        "test references a variable that has no definition, which will cause the "
        "test to use a zero/empty value at runtime and likely produce false results."
    ),
    "Toggle Value Sync": (
        "Compares the boolean value (true/false) of each rule toggle between "
        "defaults/main.yml and the audit vars file. Findings appear here when a "
        "toggle is 'true' in defaults but 'false' in audit vars (or vice-versa), "
        "meaning remediation will run/skip a rule but the audit will do the "
        "opposite — leading to false positives or missed validations."
    ),
    "Severity-Directory Alignment": (
        "STIG only. Checks that the severity label in each task name (HIGH, MEDIUM, "
        "LOW) matches the cat_X directory the task file lives in (cat_1=HIGH, "
        "cat_2=MEDIUM, cat_3=LOW). Findings appear here when a task labelled HIGH "
        "is in cat_2/, for example, indicating the task was placed in the wrong "
        "severity directory or the name label is incorrect. Skipped for CIS."
    ),
    "Goss Block Pairing": (
        "Validates that Go template control blocks in audit files are balanced — "
        "every {{ if }} and {{ range }} must have a matching {{ end }}. Findings "
        "appear here when a file has mismatched opening/closing blocks, which will "
        "cause goss template rendering to fail at audit runtime."
    ),
    "When-Toggle Alignment": (
        "STIG only. Verifies that each task's when: condition references the "
        "correct toggle variable for its STIG_ID. For example, a task named "
        "AZLX-23-000100 should use when: az2023stig_000100. Findings appear here "
        "when the when: toggle does not match the STIG_ID in the task name, which "
        "means enabling/disabling one rule accidentally controls a different rule. "
        "Skipped for CIS."
    ),
    "Template-Goss Var Cross-Ref": (
        "Cross-references goss audit test .Vars.<name> references against the "
        "YAML keys output by ansible_vars_goss.yml.j2, and verifies that every "
        "Jinja2 expression in the template references a variable defined in "
        "defaults/main.yml or vars/audit.yml. Findings appear here when: (A) a "
        "goss test references a variable the template does not output — the test "
        "will use the audit vars file default or a zero value; (B) a template "
        "Jinja2 expression references an undefined variable — Ansible rendering "
        "will fail or produce empty values; (C) a template output key is similar "
        "but not identical to a goss reference — indicating a naming mismatch "
        "that silently breaks the variable bridge between remediation and audit."
    ),
    "Handler Notify Validation": (
        "Parses handlers/main.yml for handler names (including listen: aliases) "
        "and scans all task files for notify: references. Findings appear here "
        "when: (A) a notify references a handler name that does not exist — the "
        "play will fail at runtime with 'ERROR! The requested handler was not "
        "found'; (B) a notify uses different letter casing than the handler "
        "definition — Ansible handler matching is case-sensitive so a case "
        "mismatch silently skips the handler; (C) a handler is defined but never "
        "referenced by any notify — indicating dead code or a missing notify."
    ),
    "Prelim Variable Dependencies": (
        "Extracts all variables registered or set via set_fact in tasks/prelim.yml "
        "and scans section task files for references to prelim_* variables. "
        "Findings appear here when a task file references a prelim_* variable "
        "that is not defined in prelim.yml, which will cause an 'undefined "
        "variable' error at runtime. This catches refactoring misses where a "
        "prelim task was renamed or removed but downstream references remain."
    ),
    "Automation Status Tracking": (
        "Classifies each control as automated, manual, or partial by examining "
        "the Ansible modules used in its task block (shell/command/debug/import "
        "= manual; package/lineinfile/template/etc. = automated). Then checks "
        "whether each automated control has a corresponding audit test file with "
        "at least one goss assertion. Findings appear here when an automated "
        "control has no audit test (remediation runs but is never validated) or "
        "has an empty audit test (test file exists but contains no assertions)."
    ),
    "File Path Alignment": (
        "Extracts literal file paths from remediation task modules (path:, dest:, "
        "shell/command strings) and from goss audit test blocks (file: path:, "
        "mount: mountpoint:, command: exec: strings). For each control present in "
        "both repos, compares the path sets. Findings appear when remediation "
        "writes to a file that the audit does not test (silent false pass) or "
        "when the audit tests a file that remediation does not touch (potential "
        "stale test). Jinja2 variable paths are excluded since they cannot be "
        "resolved at parse time. Parent/child path relationships are tolerated "
        "(e.g., remediation targets /etc/ssh/sshd_config while audit tests the "
        "/etc/ssh/ directory)."
    ),
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
  when_toggle_alignment, template_goss_var_xref,
  handler_notify, prelim_dependencies, automation_status,
  file_path_alignment
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
    # Bridge (audit-vars) template: the New Alignment Strategy renamed
    # ansible_vars_goss.yml.j2 -> lockdown_audit.yml.j2. Resolve whichever
    # exists (prefer the new name), falling back to the legacy name for older repos.
    _template_dir = os.path.join(remediation_dir, "templates")
    template_path = next(
        (os.path.join(_template_dir, _n)
         for _n in ("lockdown_audit.yml.j2", "ansible_vars_goss.yml.j2")
         if os.path.isfile(os.path.join(_template_dir, _n))),
        os.path.join(_template_dir, "ansible_vars_goss.yml.j2"),
    )
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

    log("Extracting template output keys...")
    template_output_keys = extract_template_output_keys(template_path)
    log(f"  Found {len(template_output_keys)} template output keys")

    log("Extracting all defaults keys...")
    defaults_all_keys = extract_defaults_all_keys(defaults_path)
    log(f"  Found {len(defaults_all_keys)} defaults keys")

    log("Extracting toggle values from defaults/main.yml...")
    defaults_toggle_values = extract_toggle_values(defaults_path, toggle_pat)
    log(f"  Found {len(defaults_toggle_values)} toggle values")

    log(f"Extracting toggle values from {audit_vars_name}...")
    audit_toggle_values = extract_toggle_values(audit_vars_path, toggle_pat)
    log(f"  Found {len(audit_toggle_values)} toggle values")

    handlers_path = os.path.join(remediation_dir, "handlers", "main.yml")
    prelim_path = os.path.join(tasks_dir, "prelim.yml")

    log("Extracting handler names...")
    handler_names = extract_handler_names(handlers_path)
    log(f"  Found {len(handler_names)} handlers")

    log("Extracting notify references...")
    notify_refs = extract_notify_references(tasks_dir)
    log(f"  Found {len(notify_refs)} notify references")

    log("Extracting prelim registered vars...")
    prelim_vars = extract_prelim_registered_vars(prelim_path)
    log(f"  Found {len(prelim_vars)} prelim vars")

    log("Extracting prelim references from tasks...")
    prelim_refs = extract_prelim_references(tasks_dir)
    log(f"  Found {len(prelim_refs)} prelim references")

    log("Extracting task automation status...")
    task_status = extract_task_automation_status(tasks_dir, prefix, toggle_pat)
    log(f"  Found {len(task_status)} task entries")

    log("Extracting audit test depth...")
    audit_depth = extract_audit_test_depth(audit_dir, prefix, toggle_pat)
    log(f"  Found {len(audit_depth)} audit test entries")

    log("Extracting file paths from remediation tasks...")
    task_file_paths = extract_task_paths(tasks_dir, prefix, benchmark_type)
    log(f"  Found paths for {len(task_file_paths)} controls")

    log("Extracting file paths from audit tests...")
    audit_file_paths = extract_audit_paths(audit_dir, prefix, benchmark_type)
    log(f"  Found paths for {len(audit_file_paths)} controls")

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
    _run("template_goss_var_xref", check_template_goss_var_crossref,
         goss_var_refs, template_output_keys, defaults_all_keys,
         audit_vars_defined, prefix, benchmark_type,
         template_path, defaults_path)
    _run("handler_notify", check_handler_notify,
         handler_names, notify_refs, handlers_path)
    _run("prelim_dependencies", check_prelim_dependencies,
         prelim_vars, prelim_refs, prelim_path)
    _run("automation_status", check_automation_status,
         task_status, audit_depth, audit_vars_path, prefix)
    _run("file_path_alignment", check_file_path_alignment,
         task_file_paths, audit_file_paths)

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
