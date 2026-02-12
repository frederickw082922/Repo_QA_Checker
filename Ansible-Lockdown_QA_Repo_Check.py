#!/usr/bin/env python3
"""Ansible-Lockdown QA Repository Check Tool.

Comprehensive quality assurance tool for Ansible-Lockdown CIS/STIG
hardening roles.  Checks linting, spelling, grammar, variable usage,
file modes, naming conventions, FQCN consistency, rule coverage, and
audit templates.

Generates reports in Markdown (.md), HTML (.html), or JSON (.json) format.

Zero external Python dependencies -- uses only stdlib plus subprocess
calls to yamllint and ansible-lint.
"""

import argparse
import collections
import datetime
import html as html_mod
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

TOOL_VERSION = "2.1.0"

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    file: str
    line: int
    description: str
    severity: str        # error, warning, info
    check_name: str


@dataclass
class CheckResult:
    name: str
    status: str          # PASS, FAIL, WARN, SKIP
    findings: List[Finding] = field(default_factory=list)
    summary: str = ""
    elapsed: float = 0.0  # seconds


@dataclass
class ReportMetadata:
    repo_name: str
    branch: str
    date: str
    tool_version: str
    benchmark_prefix: str

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_LEVELS: Dict[str, int] = {"info": 0, "warning": 1, "error": 2}

ANSI = {
    "red":    "\033[0;31m",
    "green":  "\033[0;32m",
    "yellow": "\033[0;33m",
    "blue":   "\033[0;34m",
    "cyan":   "\033[0;36m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

MISSPELLING_DICT: Dict[str, str] = {
    # Common English
    "teh": "the", "taht": "that", "adn": "and", "hte": "the",
    "recieve": "receive", "acheive": "achieve", "occurence": "occurrence",
    "occured": "occurred", "occuring": "occurring", "seperate": "separate",
    "definately": "definitely", "neccessary": "necessary", "necesary": "necessary",
    "accomodate": "accommodate", "wich": "which", "untill": "until",
    "sucessful": "successful", "successfull": "successful",
    "enviroment": "environment", "enviroments": "environments",
    "managment": "management", "arguement": "argument", "arguements": "arguments",
    "begining": "beginning", "calender": "calendar", "collegue": "colleague",
    "comming": "coming", "commited": "committed", "committment": "commitment",
    "comparision": "comparison", "completly": "completely", "concious": "conscious",
    "consistant": "consistent", "dependant": "dependent", "desireable": "desirable",
    "diffrent": "different", "dissapear": "disappear", "dissapoint": "disappoint",
    "embarass": "embarrass", "explaination": "explanation", "familar": "familiar",
    "finaly": "finally", "goverment": "government", "grammer": "grammar",
    "gaurd": "guard", "happend": "happened", "harrass": "harass",
    "immediatly": "immediately", "independant": "independent",
    "intresting": "interesting", "knowlege": "knowledge", "liason": "liaison",
    "maintainance": "maintenance", "millenium": "millennium", "mispell": "misspell",
    "noticable": "noticeable", "occassion": "occasion", "persistant": "persistent",
    "posession": "possession", "priviledge": "privilege", "profesional": "professional",
    "publically": "publicly", "realy": "really", "refered": "referred",
    "referance": "reference", "relevent": "relevant", "rember": "remember",
    "resistence": "resistance", "saftey": "safety", "similiar": "similar",
    "speach": "speech", "strenght": "strength", "supercede": "supersede",
    "surprize": "surprise", "tendancy": "tendency", "therefor": "therefore",
    "threshhold": "threshold", "tommorow": "tomorrow", "truely": "truly",
    "unforseen": "unforeseen", "unfortunatly": "unfortunately", "wierd": "weird",
    "writting": "writing",
    # Technical / Ansible specific
    "playbok": "playbook", "plabook": "playbook",
    "varaible": "variable", "varaiable": "variable", "variabel": "variable",
    "configuartion": "configuration", "configurtion": "configuration",
    "configration": "configuration", "deamon": "daemon",
    "directroy": "directory", "direcotry": "directory",
    "excutable": "executable", "exectuable": "executable",
    "filesytem": "filesystem", "filesystme": "filesystem",
    "firwall": "firewall", "firewal": "firewall",
    "implemntation": "implementation", "implementaton": "implementation",
    "paramter": "parameter", "paramater": "parameter", "paramerter": "parameter",
    "premission": "permission", "permision": "permission",
    "repostory": "repository", "repositry": "repository", "repsository": "repository",
    "remdiation": "remediation", "remediaton": "remediation",
    "sevrity": "severity", "serivce": "service", "servcie": "service",
    "tempalte": "template", "templte": "template",
    "authentcation": "authentication", "authnetication": "authentication",
    "atuhentication": "authentication", "authorizaton": "authorization",
    "certifcate": "certificate", "certificte": "certificate",
    "encrpytion": "encryption", "encyption": "encryption",
    "vulnerabilty": "vulnerability", "vulnerablity": "vulnerability",
    "benckmark": "benchmark", "benchamrk": "benchmark",
    "compliane": "compliance", "compiance": "compliance",
    "hardning": "hardening", "hardenning": "hardening",
}

# Words that look like misspelling-dict hits but are valid in this context.
# Merged into SpellCheck at runtime alongside config spelling_exceptions.
SPELL_EXCEPTIONS: Set[str] = set()  # add entries here to suppress globally

# Compiled grammar patterns: (regex, description_template, severity)
GRAMMAR_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"\b(\w+)\s+\1\b", re.IGNORECASE),
     "Repeated word: '{0} {0}'", "warning"),
    (re.compile(r"(?<!\#)  (?! )"),
     "Multiple consecutive spaces", "info"),
    (re.compile(r"\bwont\b", re.IGNORECASE),
     "Missing apostrophe: 'wont' -> 'won't'", "info"),
    (re.compile(r"\bcant\b", re.IGNORECASE),
     "Missing apostrophe: 'cant' -> 'can't'", "info"),
    (re.compile(r"\bdont\b", re.IGNORECASE),
     "Missing apostrophe: 'dont' -> 'don't'", "info"),
    (re.compile(r"\bisnt\b", re.IGNORECASE),
     "Missing apostrophe: 'isnt' -> 'isn't'", "info"),
    (re.compile(r"\bdoesnt\b", re.IGNORECASE),
     "Missing apostrophe: 'doesnt' -> 'doesn't'", "info"),
    (re.compile(r"\bhasnt\b", re.IGNORECASE),
     "Missing apostrophe: 'hasnt' -> 'hasn't'", "info"),
    (re.compile(r"\bshouldnt\b", re.IGNORECASE),
     "Missing apostrophe: 'shouldnt' -> 'shouldn't'", "info"),
    (re.compile(r"\bwouldnt\b", re.IGNORECASE),
     "Missing apostrophe: 'wouldnt' -> 'wouldn't'", "info"),
    (re.compile(r"\bcouldnt\b", re.IGNORECASE),
     "Missing apostrophe: 'couldnt' -> 'couldn't'", "info"),
    (re.compile(
        r"\b(?:values|variables|files|settings|options|parameters|packages|modules"
        r"|controls|rules|entries|changes|updates|directories)\s+is\b",
        re.IGNORECASE),
     "Subject-verb disagreement: plural noun + 'is'", "warning"),
    (re.compile(
        r"\b(?:variable|value|file|setting|option|parameter|package|module"
        r"|control|rule|entry|change|update|directory)\s+are\b",
        re.IGNORECASE),
     "Subject-verb disagreement: singular noun + 'are'", "warning"),
]

# Register variable prefixes accepted by Ansible-Lockdown convention
VALID_REGISTER_PREFIXES = ("discovered_", "prelim_", "pre_audit_", "post_audit_", "set_")

# Ansible built-in / magic variables to exclude from "undefined" warnings
ANSIBLE_BUILTINS: Set[str] = {
    "item", "ansible_facts", "ansible_env", "ansible_check_mode",
    "ansible_diff_mode", "ansible_version", "ansible_play_hosts",
    "ansible_play_batch", "ansible_playbook_python", "ansible_connection",
    "ansible_host", "ansible_port", "ansible_user", "ansible_forks",
    "inventory_hostname", "inventory_hostname_short", "group_names",
    "groups", "hostvars", "play_hosts", "role_path", "playbook_dir",
    "omit", "true", "false", "none", "ansible_local",
    "ansible_facts_path",
}

# Known ansible.builtin module short names (for FQCN check)
ANSIBLE_BUILTIN_MODULES: Set[str] = {
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

# Ansible task-level keywords (NOT module names)
TASK_KEYWORDS: Set[str] = {
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
}

# Directories / patterns to skip when walking the repo
SKIP_DIRS: Set[str] = {".git", "__pycache__", ".github", "collections"}

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _relpath(filepath: str, base: str) -> str:
    """Return a clean relative path for display."""
    try:
        return os.path.relpath(filepath, base)
    except ValueError:
        return filepath


def _extract_comment(line: str, file_ext: str) -> Optional[str]:
    """Return the comment text from *line*, or None if not a comment."""
    stripped = line.lstrip()
    if file_ext in (".yml", ".yaml", ".j2"):
        m = re.search(r"(?:^|\s)#\s*(.*)", line)
        if m:
            return m.group(1)
    elif file_ext == ".md":
        return line.rstrip("\n")
    return None


def _extract_task_name(line: str, file_ext: str) -> Optional[str]:
    """Return the task name text from a ``- name:`` or ``name:`` line."""
    if file_ext not in (".yml", ".yaml"):
        return None
    m = re.match(r"\s*-?\s*name:\s*(.+)", line)
    if m:
        val = m.group(1).strip().strip("'\"")
        # Skip Jinja expressions
        if "{{" in val:
            return None
        return val
    return None


def _parse_simple_yaml(filepath: str) -> Dict[str, Any]:
    """Parse a flat YAML config file (scalars, lists, inline lists).

    Limitations:
    - No nested mappings (only top-level keys).
    - No multi-line strings (``|``, ``>``).
    - All values are returned as strings or list-of-strings.
    """
    result: Dict[str, Any] = {}
    current_key: Optional[str] = None
    current_list: Optional[List[str]] = None
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.startswith("- ") and current_key is not None and current_list is not None:
                    current_list.append(stripped[2:].strip().strip("'\""))
                    continue
                m = re.match(r"^([a-zA-Z_]\w*):\s*(.*)", stripped)
                if m:
                    if current_key is not None and current_list is not None:
                        result[current_key] = current_list
                    key, value = m.group(1), m.group(2).strip()
                    # Inline list: key: [a, b, c]
                    if value.startswith("[") and value.endswith("]"):
                        items = [
                            v.strip().strip("'\"")
                            for v in value[1:-1].split(",")
                            if v.strip()
                        ]
                        result[key] = items
                        current_key = None
                        current_list = None
                    elif value:
                        result[key] = value.strip("'\"")
                        current_key = None
                        current_list = None
                    else:
                        current_key = key
                        current_list = []
        if current_key is not None and current_list is not None:
            result[current_key] = current_list
    except OSError:
        pass
    return result

# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

class ConfigLoader:
    """Load per-repo configuration from .qa_config.yml."""

    DEFAULTS: Dict[str, Any] = {
        "skip_checks": [],
        "spelling_exceptions": [],
        "register_prefixes": list(VALID_REGISTER_PREFIXES),
        "fqcn_exclude_paths": ["molecule/"],
        "company_old_names": ["mindpoint"],
        "company_exclude_patterns": ["tyto", "project", "author",
                                     "company:", "namespace",
                                     "company_title"],
        "min_severity": "info",
    }

    @classmethod
    def load(cls, directory: str) -> Dict[str, Any]:
        config: Dict[str, Any] = dict(cls.DEFAULTS)
        for name in (".qa_config.yml", ".qa_config.yaml", ".qa_config.json"):
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            if name.endswith(".json"):
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        loaded = json.load(fh)
                except (OSError, json.JSONDecodeError):
                    continue
            else:
                loaded = _parse_simple_yaml(path)
            for key in cls.DEFAULTS:
                if key in loaded:
                    config[key] = loaded[key]
            break
        return config

# ---------------------------------------------------------------------------
# RepoScanner -- shared context with file cache
# ---------------------------------------------------------------------------

class RepoScanner:
    """Central scanner holding repo metadata, file cache, and shared helpers."""

    def __init__(self, directory: str, benchmark_prefix: Optional[str],
                 skip_checks: Set[str], verbose: bool,
                 config: Dict[str, Any],
                 exclude_paths: Optional[Set[str]] = None):
        self.directory = directory
        self.verbose = verbose
        self.skip_checks = skip_checks
        self.config = config
        self.exclude_paths = exclude_paths or set()  # absolute paths
        self._file_cache: Dict[str, List[str]] = {}
        self._files_cache: Dict[str, List[str]] = {}
        self.benchmark_prefix = benchmark_prefix or self._auto_detect_prefix()

    # -- file cache ---------------------------------------------------------

    def read_lines(self, filepath: str) -> List[str]:
        """Read a file and return lines (cached)."""
        if filepath not in self._file_cache:
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                    self._file_cache[filepath] = fh.readlines()
            except OSError:
                self._file_cache[filepath] = []
        return self._file_cache[filepath]

    def collect_files(self, directory: str, extensions: Set[str],
                      exclude_dirs: Optional[Set[str]] = None) -> List[str]:
        """Walk *directory* and return files with matching suffix (cached)."""
        cache_key = f"{directory}|{'|'.join(sorted(extensions))}"
        if cache_key not in self._files_cache:
            if exclude_dirs is None:
                exclude_dirs = SKIP_DIRS
            result: List[str] = []
            for root, dirs, files in os.walk(directory):
                dirs[:] = [d for d in dirs if d not in exclude_dirs]
                for fname in files:
                    if any(fname.endswith(ext) for ext in extensions):
                        fp = os.path.join(root, fname)
                        if os.path.abspath(fp) not in self.exclude_paths:
                            result.append(fp)
            self._files_cache[cache_key] = sorted(result)
        return self._files_cache[cache_key]

    # -- metadata helpers ---------------------------------------------------

    def _auto_detect_prefix(self) -> str:
        """Auto-detect the benchmark variable prefix from defaults/main.yml.

        Strategy: for each top-level variable, generate candidate prefixes
        of 1-3 underscore-delimited parts and vote for each. Shorter prefixes
        naturally accumulate more votes, producing the common root prefix.
        """
        defaults = os.path.join(self.directory, "defaults", "main.yml")
        counter: collections.Counter = collections.Counter()
        for line in self.read_lines(defaults):
            s = line.rstrip()
            if not s or s.startswith("#") or s[0] in (" ", "\t"):
                continue
            m = re.match(r"^([a-zA-Z_]\w*):", s)
            if m:
                parts = m.group(1).split("_")
                for i in range(1, min(4, len(parts))):
                    counter["_".join(parts[:i])] += 1
        if counter:
            return counter.most_common(1)[0][0]
        return ""

    def get_git_branch(self) -> str:
        try:
            r = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True, cwd=self.directory)
            return r.stdout.strip() if r.returncode == 0 else "unknown"
        except FileNotFoundError:
            return "unknown"

    def get_repo_name(self) -> str:
        return os.path.basename(os.path.abspath(self.directory))

    # -- run all checks -----------------------------------------------------

    # Checks that shell out to external tools and can run in parallel.
    _SUBPROCESS_CHECKS = {"yamllint", "ansiblelint"}

    def run_all_checks(self) -> List[CheckResult]:
        checks = [
            ("yamllint",        YamlLintCheck),
            ("ansiblelint",     AnsibleLintCheck),
            ("spelling",        SpellCheck),
            ("grammar",         GrammarCheck),
            ("unused_vars",     UnusedVarCheck),
            ("var_naming",      VarNamingCheck),
            ("file_mode",       FileModeCheck),
            ("company_naming",  CompanyNamingCheck),
            ("audit_template",  AuditTemplateCheck),
            ("fqcn",            FQCNCheck),
            ("rule_coverage",   RuleCoverageCheck),
        ]

        # Phase 1: launch subprocess-based checks in parallel
        parallel_results = self._run_parallel_checks(checks)

        # Phase 2: run remaining checks sequentially
        results: List[CheckResult] = []
        for name, cls in checks:
            if name in parallel_results:
                results.append(parallel_results[name])
                continue
            if name in self.skip_checks:
                results.append(CheckResult(name=cls.display_name,
                                           status="SKIP",
                                           summary="Skipped by user"))
                continue
            if self.verbose:
                print(f"  Running {name} ...", file=sys.stderr)
            t0 = time.monotonic()
            try:
                result = cls(self).run()
                result.elapsed = time.monotonic() - t0
                results.append(result)
            except Exception as exc:  # noqa: BLE001
                results.append(CheckResult(
                    name=cls.display_name, status="FAIL",
                    findings=[Finding("N/A", 0, f"Check crashed: {exc}",
                                      "error", name)],
                    summary=f"Internal error: {exc}",
                    elapsed=time.monotonic() - t0))
            if self.verbose:
                print(f"    {name} completed in "
                      f"{results[-1].elapsed:.2f}s", file=sys.stderr)
        return results

    def _run_parallel_checks(
        self, checks: List[Tuple[str, type]],
    ) -> Dict[str, CheckResult]:
        """Run subprocess-based checks concurrently using threads."""
        import concurrent.futures

        eligible = [
            (name, cls) for name, cls in checks
            if name in self._SUBPROCESS_CHECKS and name not in self.skip_checks
        ]
        if not eligible:
            return {}

        result_map: Dict[str, CheckResult] = {}

        def _run_one(name: str, cls: type) -> Tuple[str, CheckResult]:
            if self.verbose:
                print(f"  Running {name} (parallel) ...", file=sys.stderr)
            t0 = time.monotonic()
            try:
                r = cls(self).run()
                r.elapsed = time.monotonic() - t0
            except Exception as exc:  # noqa: BLE001
                r = CheckResult(
                    name=cls.display_name, status="FAIL",
                    findings=[Finding("N/A", 0, f"Check crashed: {exc}",
                                      "error", name)],
                    summary=f"Internal error: {exc}",
                    elapsed=time.monotonic() - t0)
            if self.verbose:
                print(f"    {name} completed in {r.elapsed:.2f}s",
                      file=sys.stderr)
            return name, r

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(eligible)) as pool:
            futures = {
                pool.submit(_run_one, name, cls): name
                for name, cls in eligible
            }
            for fut in concurrent.futures.as_completed(futures):
                name, result = fut.result()
                result_map[name] = result

        return result_map

# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

class YamlLintCheck:
    display_name = "YAML Lint"

    def __init__(self, scanner: RepoScanner):
        self.scanner = scanner

    def run(self) -> CheckResult:
        if not shutil.which("yamllint"):
            return CheckResult(self.display_name, "SKIP",
                               summary="yamllint not installed")
        try:
            r = subprocess.run(
                ["yamllint", "-f", "parsable", "."],
                capture_output=True, text=True,
                cwd=self.scanner.directory, timeout=120)
        except subprocess.TimeoutExpired:
            return CheckResult(self.display_name, "SKIP",
                               summary="yamllint timed out")
        findings = self._parse(r.stdout + r.stderr)
        status = "PASS" if not findings else "FAIL"
        return CheckResult(self.display_name, status, findings,
                           f"{len(findings)} issue(s)")

    def _parse(self, output: str) -> List[Finding]:
        findings: List[Finding] = []
        pat = re.compile(r"^(.+):(\d+):\d+: \[(error|warning)\] (.+)$")
        for line in output.splitlines():
            m = pat.match(line)
            if m:
                findings.append(Finding(
                    file=_relpath(
                        os.path.join(self.scanner.directory, m.group(1)),
                        self.scanner.directory),
                    line=int(m.group(2)),
                    description=m.group(4),
                    severity=m.group(3),
                    check_name="yamllint"))
        return findings


class AnsibleLintCheck:
    display_name = "Ansible Lint"

    def __init__(self, scanner: RepoScanner):
        self.scanner = scanner

    def run(self) -> CheckResult:
        if not shutil.which("ansible-lint"):
            return CheckResult(self.display_name, "SKIP",
                               summary="ansible-lint not installed")
        try:
            r = subprocess.run(
                ["ansible-lint", "-f", "parsable"],
                capture_output=True, text=True,
                cwd=self.scanner.directory, timeout=300)
        except subprocess.TimeoutExpired:
            return CheckResult(self.display_name, "SKIP",
                               summary="ansible-lint timed out")
        findings = self._parse(r.stdout + r.stderr)
        status = "PASS" if not findings else "FAIL"
        return CheckResult(self.display_name, status, findings,
                           f"{len(findings)} issue(s)")

    def _parse(self, output: str) -> List[Finding]:
        findings: List[Finding] = []
        pat = re.compile(r"^(.+?):(\d+)(?::\d+)?: \[([^\]]+)\] (.+)$")
        for line in output.splitlines():
            m = pat.match(line)
            if m:
                findings.append(Finding(
                    file=m.group(1),
                    line=int(m.group(2)),
                    description=f"[{m.group(3)}] {m.group(4)}",
                    severity="warning",
                    check_name="ansiblelint"))
        return findings


class SpellCheck:
    display_name = "Spell Check"

    def __init__(self, scanner: RepoScanner):
        self.scanner = scanner

    def run(self) -> CheckResult:
        findings: List[Finding] = []
        exceptions = SPELL_EXCEPTIONS | set(
            self.scanner.config.get("spelling_exceptions", []))
        files = self.scanner.collect_files(self.scanner.directory,
                                           {".yml", ".yaml", ".j2", ".md"})
        for fp in files:
            ext = os.path.splitext(fp)[1]
            rel = _relpath(fp, self.scanner.directory)
            for num, raw_line in enumerate(self.scanner.read_lines(fp), 1):
                # Check both comments and task name: values
                texts = []
                c = _extract_comment(raw_line, ext)
                if c:
                    texts.append(c)
                tn = _extract_task_name(raw_line, ext)
                if tn:
                    texts.append(tn)
                if not texts:
                    continue
                for text in texts:
                    if re.search(r"https?://", text):
                        continue
                    words = re.findall(r"[a-zA-Z']+", text)
                    for word in words:
                        low = word.lower().strip("'")
                        if low in exceptions:
                            continue
                        if low in MISSPELLING_DICT:
                            findings.append(Finding(
                                rel, num,
                                f"Misspelling: '{word}' -> '{MISSPELLING_DICT[low]}'",
                                "info", "spelling"))
        status = "PASS" if not findings else "WARN"
        return CheckResult(self.display_name, status, findings,
                           f"{len(findings)} issue(s)")


class GrammarCheck:
    display_name = "Grammar Check"

    _MD_SKIP_PATTERNS = {"Multiple consecutive spaces"}

    def __init__(self, scanner: RepoScanner):
        self.scanner = scanner

    def run(self) -> CheckResult:
        findings: List[Finding] = []
        files = self.scanner.collect_files(self.scanner.directory,
                                           {".yml", ".yaml", ".j2", ".md"})
        for fp in files:
            ext = os.path.splitext(fp)[1]
            rel = _relpath(fp, self.scanner.directory)
            is_md = ext == ".md"
            for num, raw_line in enumerate(self.scanner.read_lines(fp), 1):
                # Check both comments and task name: values
                texts = []
                c = _extract_comment(raw_line, ext)
                if c:
                    texts.append(c)
                tn = _extract_task_name(raw_line, ext)
                if tn:
                    texts.append(tn)
                if not texts:
                    continue
                for text in texts:
                    if re.search(r"https?://", text):
                        continue
                    for pat, desc_tmpl, sev in GRAMMAR_PATTERNS:
                        if is_md and desc_tmpl in self._MD_SKIP_PATTERNS:
                            continue
                        m = pat.search(text)
                        if m:
                            desc = desc_tmpl.format(m.group(1)
                                                    if m.lastindex else "")
                            findings.append(Finding(rel, num, desc, sev,
                                                    "grammar"))
        status = "PASS" if not findings else "WARN"
        return CheckResult(self.display_name, status, findings,
                           f"{len(findings)} issue(s)")


class UnusedVarCheck:
    display_name = "Unused Variables"

    def __init__(self, scanner: RepoScanner):
        self.scanner = scanner
        self.d = scanner.directory

    def run(self) -> CheckResult:
        findings: List[Finding] = []
        defined = self._defined_vars()
        findings.extend(self._forward_check(defined))
        findings.extend(self._reverse_check(defined))
        status = "PASS" if not findings else "WARN"
        return CheckResult(self.display_name, status, findings,
                           f"{len(findings)} issue(s)")

    def _defined_vars(self) -> Dict[str, Tuple[str, int]]:
        """Return {var_name: (relative_file, line)} from all var sources."""
        result: Dict[str, Tuple[str, int]] = {}
        sources = [
            os.path.join(self.d, "defaults", "main.yml"),
            os.path.join(self.d, "vars", "main.yml"),
            os.path.join(self.d, "vars", "audit.yml"),
        ]
        for src in sources:
            if not os.path.isfile(src):
                continue
            rel = _relpath(src, self.d)
            for num, line in enumerate(self.scanner.read_lines(src), 1):
                s = line.rstrip()
                if not s or s.startswith("#") or s[0] in (" ", "\t"):
                    continue
                m = re.match(r"^([a-zA-Z_]\w*):", s)
                if m:
                    result[m.group(1)] = (rel, num)
        return result

    def _forward_check(self, defined: Dict[str, Tuple[str, int]],
                       ) -> List[Finding]:
        """Variables defined in defaults/vars but never referenced.

        Uses an inverted single-pass approach: read every usage file once,
        collect all word tokens, then diff against defined vars.
        """
        findings: List[Finding] = []

        # Phase 1: collect all tokens from usage directories
        usage_tokens: Set[str] = set()
        search_dirs = ["tasks", "templates", "handlers", "molecule",
                       "meta", "filter_plugins"]
        for sd in search_dirs:
            sp = os.path.join(self.d, sd)
            if not os.path.isdir(sp):
                continue
            for fp in self.scanner.collect_files(sp, {".yml", ".yaml", ".j2", ".py"}):
                for raw in self.scanner.read_lines(fp):
                    usage_tokens.update(re.findall(r"[a-zA-Z_]\w*", raw))

        # Phase 2: collect tokens from var files (excluding definition lines)
        var_files = [
            os.path.join(self.d, "defaults", "main.yml"),
            os.path.join(self.d, "vars", "main.yml"),
            os.path.join(self.d, "vars", "audit.yml"),
        ]
        var_cross_tokens: Set[str] = set()
        for vf in var_files:
            if not os.path.isfile(vf):
                continue
            for raw in self.scanner.read_lines(vf):
                s = raw.rstrip()
                tokens = set(re.findall(r"[a-zA-Z_]\w*", raw))
                # If this is a definition line, exclude the variable being defined
                if s and not s.startswith("#") and s[0] not in (" ", "\t"):
                    dm = re.match(r"^([a-zA-Z_]\w*):", s)
                    if dm:
                        tokens.discard(dm.group(1))
                var_cross_tokens.update(tokens)

        all_referenced = usage_tokens | var_cross_tokens
        for var, (vfile, vline) in sorted(defined.items()):
            if var not in all_referenced:
                findings.append(Finding(
                    vfile, vline,
                    f"Defined but never referenced: '{var}'",
                    "warning", "unused_vars"))
        return findings

    def _reverse_check(self, defined: Dict[str, Tuple[str, int]],
                       ) -> List[Finding]:
        """Variables referenced in tasks/templates/handlers but not defined."""
        findings: List[Finding] = []
        prefix = self.scanner.benchmark_prefix + "_"
        search_dirs = ["tasks", "templates", "handlers"]
        refs: Dict[str, Tuple[str, int]] = {}
        for sd in search_dirs:
            sp = os.path.join(self.d, sd)
            if not os.path.isdir(sp):
                continue
            for fp in self.scanner.collect_files(sp, {".yml", ".yaml", ".j2"}):
                rel = _relpath(fp, self.d)
                for num, raw in enumerate(self.scanner.read_lines(fp), 1):
                    stripped = raw.lstrip()
                    if stripped.startswith("#"):
                        continue
                    for m in re.finditer(
                            r"\b(" + re.escape(prefix) + r"[a-zA-Z0-9_]+)\b",
                            raw):
                        vname = m.group(1)
                        if vname not in refs:
                            refs[vname] = (rel, num)

        # Collect dynamic vars (register/set_fact/vars blocks)
        dynamic_vars: Set[str] = set()
        tasks_dir = os.path.join(self.d, "tasks")
        handlers_file = os.path.join(self.d, "handlers", "main.yml")
        scan_files = (self.scanner.collect_files(tasks_dir, {".yml", ".yaml"})
                      if os.path.isdir(tasks_dir) else [])
        if os.path.isfile(handlers_file):
            scan_files.append(handlers_file)
        for fp in scan_files:
            in_vars_block = False
            block_indent = 0
            for raw in self.scanner.read_lines(fp):
                rm = re.match(r"\s*register:\s*(\S+)", raw)
                if rm:
                    dynamic_vars.add(rm.group(1))
                vars_m = re.match(
                    r"(\s*)(?:ansible\.(?:builtin|legacy)\.)?"
                    r"(vars|set_fact):\s*$", raw)
                if vars_m:
                    in_vars_block = True
                    block_indent = len(vars_m.group(1))
                    continue
                if in_vars_block:
                    if raw.strip() == "":
                        continue
                    curr_indent = len(raw) - len(raw.lstrip())
                    if curr_indent > block_indent:
                        vm = re.match(r"\s+(\w+):", raw)
                        if vm:
                            dynamic_vars.add(vm.group(1))
                    else:
                        in_vars_block = False

        all_defined = set(defined.keys()) | dynamic_vars | ANSIBLE_BUILTINS
        defaults_path = os.path.join(self.d, "defaults", "main.yml")
        for raw in self.scanner.read_lines(defaults_path):
            cm = re.match(r"^#\s*(" + re.escape(prefix) + r"\w+):", raw)
            if cm:
                all_defined.add(cm.group(1))

        for vname, (rfile, rline) in refs.items():
            if vname in all_defined:
                continue
            is_substr = any(vname in dv and vname != dv
                            for dv in dynamic_vars)
            if is_substr:
                continue
            findings.append(Finding(
                rfile, rline,
                f"Referenced but not defined: '{vname}'",
                "warning", "unused_vars"))
        return findings


class VarNamingCheck:
    display_name = "Variable Naming"

    def __init__(self, scanner: RepoScanner):
        self.scanner = scanner
        self.d = scanner.directory

    def run(self) -> CheckResult:
        findings: List[Finding] = []
        findings.extend(self._register_naming())
        findings.extend(self._duplicate_discovered())
        findings.extend(self._duplicate_defaults())
        status = "PASS" if not findings else "WARN"
        return CheckResult(self.display_name, status, findings,
                           f"{len(findings)} issue(s)")

    def _register_naming(self) -> List[Finding]:
        findings: List[Finding] = []
        prefixes = tuple(self.scanner.config.get(
            "register_prefixes", VALID_REGISTER_PREFIXES))
        tasks_dir = os.path.join(self.d, "tasks")
        if not os.path.isdir(tasks_dir):
            return findings
        for fp in self.scanner.collect_files(tasks_dir, {".yml", ".yaml"}):
            rel = _relpath(fp, self.d)
            for num, raw in enumerate(self.scanner.read_lines(fp), 1):
                m = re.match(r"\s*register:\s*(\S+)", raw)
                if m:
                    var = m.group(1)
                    if not any(var.startswith(p) for p in prefixes):
                        findings.append(Finding(
                            rel, num,
                            f"Non-standard register name: '{var}' "
                            f"(expected prefixes: {', '.join(prefixes)})",
                            "warning", "var_naming"))
        return findings

    def _find_task_when(self, lines: List[str], register_line_idx: int,
                        ) -> Optional[str]:
        """Find the when: condition for the task containing register_line_idx.

        Searches at the same indentation level as the register: line,
        and also checks parent block when: conditions.
        Returns task-level when: if found; falls back to block-level.
        """
        reg_indent = len(lines[register_line_idx]) - len(
            lines[register_line_idx].lstrip())

        task_when: Optional[str] = None
        block_when: Optional[str] = None

        # Search backward within the task
        for i in range(register_line_idx - 1,
                       max(register_line_idx - 40, -1), -1):
            line = lines[i]
            stripped = line.lstrip()
            if not stripped:
                continue
            indent = len(line) - len(stripped)
            # Hit a less-indented list item boundary = different task
            if indent < reg_indent and stripped.startswith("- "):
                # Check if this parent has a when: (block-level when)
                for j in range(i + 1, min(i + 10, len(lines))):
                    pline = lines[j]
                    pstripped = pline.lstrip()
                    pindent = len(pline) - len(pstripped)
                    if pindent == indent + 2:
                        wm = re.match(r"\s*when:\s*(.*)", pline)
                        if wm:
                            block_when = wm.group(1).strip()
                    elif pindent <= indent:
                        break
                break
            if indent == reg_indent:
                wm = re.match(r"\s*when:\s*(.*)", line)
                if wm:
                    task_when = wm.group(1).strip()
                    break  # found at task level, no need to keep looking

        # Search forward within the task (only if not found backward)
        if task_when is None:
            for i in range(register_line_idx + 1,
                           min(register_line_idx + 20, len(lines))):
                line = lines[i]
                stripped = line.lstrip()
                if not stripped:
                    continue
                indent = len(line) - len(stripped)
                if indent < reg_indent:
                    break
                if stripped.startswith("- ") and indent <= reg_indent:
                    break
                if indent == reg_indent:
                    wm = re.match(r"\s*when:\s*(.*)", line)
                    if wm:
                        task_when = wm.group(1).strip()
                        break

        return task_when or block_when

    def _duplicate_discovered(self) -> List[Finding]:
        findings: List[Finding] = []
        # {var_name: (file, line, when_condition)}
        seen: Dict[str, Tuple[str, int, Optional[str]]] = {}
        tasks_dir = os.path.join(self.d, "tasks")
        if not os.path.isdir(tasks_dir):
            return findings
        for fp in self.scanner.collect_files(tasks_dir, {".yml", ".yaml"}):
            rel = _relpath(fp, self.d)
            lines = self.scanner.read_lines(fp)
            for num, raw in enumerate(lines, 1):
                m = re.match(r"\s*register:\s*(\S+)", raw)
                if m:
                    var = m.group(1)
                    when_cond = self._find_task_when(lines, num - 1)
                    if var in seen:
                        prev_file, prev_line, prev_when = seen[var]
                        # Suppress if both have different when: conditions
                        if (prev_when is not None
                                and when_cond is not None
                                and prev_when != when_cond):
                            continue
                        findings.append(Finding(
                            rel, num,
                            f"Duplicate register variable '{var}' "
                            f"(first seen in {prev_file}:{prev_line})",
                            "warning", "var_naming"))
                    else:
                        seen[var] = (rel, num, when_cond)
        return findings

    def _duplicate_defaults(self) -> List[Finding]:
        findings: List[Finding] = []
        defaults = os.path.join(self.d, "defaults", "main.yml")
        seen: Dict[str, int] = {}
        for num, raw in enumerate(self.scanner.read_lines(defaults), 1):
            s = raw.rstrip()
            if not s or s.startswith("#") or s[0] in (" ", "\t"):
                continue
            m = re.match(r"^([a-zA-Z_]\w*):", s)
            if m:
                var = m.group(1)
                if var in seen:
                    findings.append(Finding(
                        "defaults/main.yml", num,
                        f"Duplicate default variable '{var}' "
                        f"(first defined at line {seen[var]})",
                        "warning", "var_naming"))
                else:
                    seen[var] = num
        return findings


class FileModeCheck:
    display_name = "File Mode Quoting"

    def __init__(self, scanner: RepoScanner):
        self.scanner = scanner

    def run(self) -> CheckResult:
        findings: List[Finding] = []
        files = self.scanner.collect_files(self.scanner.directory,
                                           {".yml", ".yaml"})
        pat = re.compile(r"^\s*mode:\s+(.+)", re.IGNORECASE)
        for fp in files:
            rel = _relpath(fp, self.scanner.directory)
            for num, raw in enumerate(self.scanner.read_lines(fp), 1):
                m = pat.match(raw)
                if not m:
                    continue
                val = m.group(1).strip()
                if (val.startswith("'") or val.startswith('"')
                        or val.startswith("{") or "preserve" in val
                        or "item" in val):
                    continue
                if re.match(r"^0?\d{3,4}$", val):
                    findings.append(Finding(
                        rel, num,
                        f"Unquoted file mode: '{val}' "
                        "(should be quoted, e.g. '0644', or use symbolic mode)",
                        "warning", "file_mode"))
        status = "PASS" if not findings else "FAIL"
        return CheckResult(self.display_name, status, findings,
                           f"{len(findings)} issue(s)")


class CompanyNamingCheck:
    display_name = "Company Naming"

    def __init__(self, scanner: RepoScanner):
        self.scanner = scanner

    def run(self) -> CheckResult:
        findings: List[Finding] = []
        old_names = self.scanner.config.get("company_old_names", ["mindpoint"])
        if not old_names:
            return CheckResult(self.display_name, "SKIP",
                               summary="No company names configured")
        exclude_pats = self.scanner.config.get(
            "company_exclude_patterns",
            ["tyto", "project", "author", "company:", "namespace",
             "company_title"])
        exclude_in_line = re.compile(
            "|".join(re.escape(p) for p in exclude_pats),
            re.IGNORECASE) if exclude_pats else None
        search_pat = re.compile(
            "|".join(re.escape(n) for n in old_names),
            re.IGNORECASE)
        exclude_files = {"README.md", "CONTRIBUTING.rst", "LICENSE",
                         "Ansible-Lockdown_QA_Repo_Check.py"}
        files = self.scanner.collect_files(self.scanner.directory,
                                           {".yml", ".yaml", ".j2", ".md", ".py", ".sh"})
        for fp in files:
            rel = _relpath(fp, self.scanner.directory)
            if os.path.basename(fp) in exclude_files:
                continue
            if "meta/" in rel:
                continue
            for num, raw in enumerate(self.scanner.read_lines(fp), 1):
                m = search_pat.search(raw)
                if m:
                    if exclude_in_line and exclude_in_line.search(raw):
                        continue
                    findings.append(Finding(
                        rel, num,
                        f"Outdated company name '{m.group()}' found",
                        "warning", "company_naming"))
        status = "PASS" if not findings else "FAIL"
        return CheckResult(self.display_name, status, findings,
                           f"{len(findings)} issue(s)")


class AuditTemplateCheck:
    display_name = "Audit Template"

    def __init__(self, scanner: RepoScanner):
        self.scanner = scanner

    def run(self) -> CheckResult:
        findings: List[Finding] = []
        tmpl = os.path.join(self.scanner.directory, "templates",
                            "ansible_vars_goss.yml.j2")
        if not os.path.isfile(tmpl):
            return CheckResult(self.display_name, "SKIP",
                               summary="Goss audit template not found")
        lines = self.scanner.read_lines(tmpl)
        seen: Dict[str, int] = {}
        for num, raw in enumerate(lines, 1):
            s = raw.strip()
            if not s or s.startswith("{%") or s.startswith("#"):
                continue
            key_m = re.match(r"^(\w[\w.]*)\s*:", s)
            if key_m:
                key = key_m.group(1)
                if key in seen:
                    findings.append(Finding(
                        "templates/ansible_vars_goss.yml.j2", num,
                        f"Duplicate audit key '{key}' "
                        f"(first at line {seen[key]})",
                        "warning", "audit_template"))
                else:
                    seen[key] = num
        status = "PASS" if not findings else "FAIL"
        return CheckResult(self.display_name, status, findings,
                           f"{len(findings)} issue(s)")


class FQCNCheck:
    """Check for non-FQCN (bare) module names in task files."""
    display_name = "FQCN Usage"

    def __init__(self, scanner: RepoScanner):
        self.scanner = scanner
        self.d = scanner.directory

    def run(self) -> CheckResult:
        findings: List[Finding] = []
        exclude_paths = self.scanner.config.get("fqcn_exclude_paths", ["molecule/"])
        search_dirs = ["tasks", "handlers"]
        for sd in search_dirs:
            sp = os.path.join(self.d, sd)
            if not os.path.isdir(sp):
                continue
            for fp in self.scanner.collect_files(sp, {".yml", ".yaml"}):
                rel = _relpath(fp, self.d)
                if any(rel.startswith(ep) for ep in exclude_paths):
                    continue
                lines = self.scanner.read_lines(fp)
                task_indent = None
                for num, raw in enumerate(lines, 1):
                    stripped = raw.lstrip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    indent = len(raw) - len(stripped)

                    # Detect task item start: "  - name:" or unnamed "  - module:"
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
                            findings.append(Finding(
                                rel, num,
                                f"Non-FQCN module: '{key}' -> "
                                f"'ansible.builtin.{key}'",
                                "warning", "fqcn"))
                        continue

                    if task_indent is None:
                        continue

                    # Reset task_indent if we leave the task block
                    if indent < task_indent and stripped.startswith("- "):
                        task_indent = None
                        continue

                    # Check for bare module at task level
                    km = re.match(r"^(\s+)([a-z][a-z0-9_]*):\s", raw)
                    if km and len(km.group(1)) == task_indent:
                        key = km.group(2)
                        if key in ANSIBLE_BUILTIN_MODULES and key not in TASK_KEYWORDS:
                            findings.append(Finding(
                                rel, num,
                                f"Non-FQCN module: '{key}' -> "
                                f"'ansible.builtin.{key}'",
                                "warning", "fqcn"))
        status = "PASS" if not findings else "WARN"
        return CheckResult(self.display_name, status, findings,
                           f"{len(findings)} issue(s)")


class RuleCoverageCheck:
    """Check that every rule toggle in defaults has a matching task and vice versa."""
    display_name = "Rule Coverage"

    def __init__(self, scanner: RepoScanner):
        self.scanner = scanner
        self.d = scanner.directory

    def run(self) -> CheckResult:
        findings: List[Finding] = []
        prefix = self.scanner.benchmark_prefix
        if not prefix:
            return CheckResult(self.display_name, "SKIP",
                               summary="No benchmark prefix detected")

        rule_pat = re.compile(rf"^({re.escape(prefix)}_rule_\w+):")

        # Collect defined rule vars from defaults/main.yml
        defined_rules: Dict[str, int] = {}
        defaults = os.path.join(self.d, "defaults", "main.yml")
        for num, line in enumerate(self.scanner.read_lines(defaults), 1):
            m = rule_pat.match(line.rstrip())
            if m:
                defined_rules[m.group(1)] = num

        # Collect referenced rule vars in task when: conditions
        referenced_rules: Dict[str, Tuple[str, int]] = {}
        tasks_dir = os.path.join(self.d, "tasks")
        if not os.path.isdir(tasks_dir):
            return CheckResult(self.display_name, "SKIP",
                               summary="No tasks directory found")

        ref_pat = re.compile(rf"\b({re.escape(prefix)}_rule_\w+)\b")
        for fp in self.scanner.collect_files(tasks_dir, {".yml", ".yaml"}):
            rel = _relpath(fp, self.d)
            for num, raw in enumerate(self.scanner.read_lines(fp), 1):
                for rm in ref_pat.finditer(raw):
                    rule = rm.group(1)
                    if rule not in referenced_rules:
                        referenced_rules[rule] = (rel, num)

        # Orphaned: defined but never used in tasks
        for rule in sorted(defined_rules):
            if rule not in referenced_rules:
                findings.append(Finding(
                    "defaults/main.yml", defined_rules[rule],
                    f"Rule defined but not used in tasks: '{rule}'",
                    "warning", "rule_coverage"))

        # Missing: used in tasks but not defined
        for rule in sorted(referenced_rules):
            if rule not in defined_rules:
                rfile, rline = referenced_rules[rule]
                findings.append(Finding(
                    rfile, rline,
                    f"Rule used in tasks but not defined: '{rule}'",
                    "error", "rule_coverage"))

        status = "PASS" if not findings else (
            "FAIL" if any(f.severity == "error" for f in findings) else "WARN")
        return CheckResult(self.display_name, status, findings,
                           f"{len(findings)} issue(s)")

# ---------------------------------------------------------------------------
# Report generators
# ---------------------------------------------------------------------------

def _filter_findings(findings: List[Finding], min_severity: str,
                     ) -> List[Finding]:
    """Filter findings to only include those at or above min_severity."""
    min_level = SEVERITY_LEVELS.get(min_severity, 0)
    return [f for f in findings
            if SEVERITY_LEVELS.get(f.severity, 0) >= min_level]


class ReportGenerator:
    """Generate Markdown, HTML, or JSON reports from check results."""

    def __init__(self, metadata: ReportMetadata,
                 results: List[CheckResult], fmt: str,
                 min_severity: str = "info"):
        self.meta = metadata
        self.results = results
        self.fmt = fmt
        self.min_severity = min_severity

    def generate(self) -> str:
        if self.fmt == "html":
            return self._html()
        if self.fmt == "json":
            return self._json()
        return self._markdown()

    def _stats(self) -> Dict[str, int]:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.status == "PASS")
        failed = sum(1 for r in self.results if r.status == "FAIL")
        warned = sum(1 for r in self.results if r.status == "WARN")
        skipped = sum(1 for r in self.results if r.status == "SKIP")
        return {"total": total, "passed": passed, "failed": failed,
                "warnings": warned, "skipped": skipped}

    # -- Markdown -----------------------------------------------------------

    def _markdown(self) -> str:
        s = self._stats()
        lines = [
            f"# QA Report: {self.meta.repo_name}\n",
            f"**Date:** {self.meta.date}  ",
            f"**Branch:** {self.meta.branch}  ",
            f"**Tool Version:** {self.meta.tool_version}  ",
            f"**Benchmark Prefix:** {self.meta.benchmark_prefix}\n",
            "---\n",
            "## Summary\n",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Total Checks | {s['total']} |",
            f"| Passed | {s['passed']} |",
            f"| Failed | {s['failed']} |",
            f"| Warnings | {s['warnings']} |",
            f"| Skipped | {s['skipped']} |",
            "",
            "---\n",
        ]
        for r in self.results:
            icon = {"PASS": "[PASS]", "FAIL": "[FAIL]",
                    "WARN": "[WARN]", "SKIP": "[SKIP]"}[r.status]
            lines.append(f"## {icon} {r.name}\n")
            lines.append(f"**Status:** {r.status}  ")
            if r.summary:
                lines.append(f"**Summary:** {r.summary}\n")
            filtered = _filter_findings(r.findings, self.min_severity)
            if filtered:
                lines.append("")
                lines.append("| Severity | File | Line | Description |")
                lines.append("|----------|------|------|-------------|")
                for f in filtered[:200]:
                    desc = f.description.replace("|", "\\|")
                    lines.append(
                        f"| {f.severity} | `{f.file}` | {f.line} | {desc} |")
                if len(filtered) > 200:
                    lines.append(
                        f"| ... | ... | ... | "
                        f"*{len(filtered) - 200} more findings omitted* |")
            lines.append("")
            lines.append("---\n")
        return "\n".join(lines) + "\n"

    # -- HTML ---------------------------------------------------------------

    def _html(self) -> str:
        s = self._stats()
        sections = []
        for r in self.results:
            badge_cls = {"PASS": "badge-pass", "FAIL": "badge-fail",
                         "WARN": "badge-warn", "SKIP": "badge-skip"
                         }[r.status]
            filtered = _filter_findings(r.findings, self.min_severity)
            rows = ""
            for f in filtered[:200]:
                sev_cls = f"severity-{f.severity}"
                rows += (
                    f"<tr><td><span class='{sev_cls}'>{esc(f.severity)}"
                    f"</span></td>"
                    f"<td><code>{esc(f.file)}</code></td>"
                    f"<td>{f.line}</td>"
                    f"<td>{esc(f.description)}</td></tr>\n")
            if len(filtered) > 200:
                rows += (
                    f"<tr><td colspan='4'><em>"
                    f"{len(filtered) - 200} more findings omitted"
                    f"</em></td></tr>\n")
            table = ""
            if filtered:
                table = (
                    "<table><tr><th>Severity</th><th>File</th>"
                    "<th>Line</th><th>Description</th></tr>\n"
                    f"{rows}</table>")
            sections.append(
                f"<div class='section'>"
                f"<div class='section-header'>"
                f"<h2>{esc(r.name)}</h2>"
                f"<span class='badge {badge_cls}'>{r.status}</span></div>"
                f"<p>{esc(r.summary)}</p>{table}</div>\n")

        return HTML_TEMPLATE.format(
            repo_name=esc(self.meta.repo_name),
            date=esc(self.meta.date),
            branch=esc(self.meta.branch),
            tool_version=esc(self.meta.tool_version),
            benchmark_prefix=esc(self.meta.benchmark_prefix),
            total=s["total"], passed=s["passed"], failed=s["failed"],
            warnings=s["warnings"], skipped=s["skipped"],
            sections="\n".join(sections))

    # -- JSON ---------------------------------------------------------------

    def _json(self) -> str:
        s = self._stats()
        data = {
            "metadata": {
                "repo_name": self.meta.repo_name,
                "branch": self.meta.branch,
                "date": self.meta.date,
                "tool_version": self.meta.tool_version,
                "benchmark_prefix": self.meta.benchmark_prefix,
            },
            "summary": s,
            "checks": [
                {
                    "name": r.name,
                    "status": r.status,
                    "summary": r.summary,
                    "elapsed_seconds": round(r.elapsed, 3),
                    "findings": [
                        {
                            "severity": f.severity,
                            "file": f.file,
                            "line": f.line,
                            "description": f.description,
                            "check": f.check_name,
                        }
                        for f in _filter_findings(r.findings, self.min_severity)
                    ],
                }
                for r in self.results
            ],
        }
        return json.dumps(data, indent=2) + "\n"


def esc(text: str) -> str:
    """HTML-escape."""
    return html_mod.escape(str(text))


HTML_TEMPLATE = textwrap.dedent("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QA Report: {repo_name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
         sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px;
         background: #f5f5f5; color: #1a1a2e; }}
  h1 {{ border-bottom: 3px solid #16213e; padding-bottom: 10px; }}
  h2 {{ margin-top: 0; }}
  .metadata {{ background: #fff; padding: 15px; border-radius: 8px;
               box-shadow: 0 2px 4px rgba(0,0,0,.1); margin-bottom: 20px; }}
  .metadata span {{ margin-right: 20px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 15px 0;
           background: #fff; border-radius: 8px; overflow: hidden;
           box-shadow: 0 2px 4px rgba(0,0,0,.1); }}
  th {{ background: #16213e; color: #fff; padding: 12px 15px;
       text-align: left; }}
  td {{ padding: 10px 15px; border-bottom: 1px solid #eee; }}
  tr:hover {{ background: #f8f9fa; }}
  .section {{ background: #fff; padding: 20px; border-radius: 8px;
              box-shadow: 0 2px 4px rgba(0,0,0,.1); margin-bottom: 20px; }}
  .section-header {{ display: flex; justify-content: space-between;
                     align-items: center; }}
  .badge {{ padding: 4px 12px; border-radius: 12px; font-size: .85em;
            font-weight: bold; }}
  .badge-pass {{ background: #d4edda; color: #155724; }}
  .badge-fail {{ background: #f8d7da; color: #721c24; }}
  .badge-warn {{ background: #fff3cd; color: #856404; }}
  .badge-skip {{ background: #e2e3e5; color: #383d41; }}
  code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px;
          font-size: .9em; }}
  .severity-error {{ background: #f8d7da; color: #721c24; padding: 2px 8px;
                     border-radius: 4px; font-size: .85em; }}
  .severity-warning {{ background: #fff3cd; color: #856404; padding: 2px 8px;
                       border-radius: 4px; font-size: .85em; }}
  .severity-info {{ background: #d1ecf1; color: #0c5460; padding: 2px 8px;
                    border-radius: 4px; font-size: .85em; }}
  .summary-table td:first-child {{ font-weight: bold; }}
</style>
</head>
<body>
<h1>QA Report: {repo_name}</h1>
<div class="metadata">
  <span><strong>Date:</strong> {date}</span>
  <span><strong>Branch:</strong> {branch}</span>
  <span><strong>Version:</strong> {tool_version}</span>
  <span><strong>Prefix:</strong> {benchmark_prefix}</span>
</div>
<div class="section">
<h2>Summary</h2>
<table class="summary-table">
<tr><th>Metric</th><th>Count</th></tr>
<tr><td>Total Checks</td><td>{total}</td></tr>
<tr><td>Passed</td><td>{passed}</td></tr>
<tr><td>Failed</td><td>{failed}</td></tr>
<tr><td>Warnings</td><td>{warnings}</td></tr>
<tr><td>Skipped</td><td>{skipped}</td></tr>
</table>
</div>
{sections}
</body>
</html>
""")

# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

class ConsoleOutput:
    """Print colored results to the terminal."""

    def __init__(self, results: List[CheckResult], use_color: bool,
                 min_severity: str = "info"):
        self.results = results
        self.c = ANSI if use_color else {k: "" for k in ANSI}
        self.min_severity = min_severity

    def print_results(self) -> None:
        c = self.c
        print(f"\n{c['cyan']}{'=' * 60}")
        print("  Ansible-Lockdown QA Report")
        print(f"{'=' * 60}{c['reset']}\n")
        for r in self.results:
            color = {"PASS": c["green"], "FAIL": c["red"],
                     "WARN": c["yellow"], "SKIP": c["blue"]}[r.status]
            timing = f"  [{r.elapsed:.2f}s]" if r.elapsed > 0 else ""
            print(f"  {color}{r.status:4s}{c['reset']}  {r.name}"
                  f"  ({r.summary}){timing}")
            if r.status != "PASS":
                filtered = _filter_findings(r.findings, self.min_severity)
                for f in filtered[:20]:
                    sev_c = {"error": c["red"], "warning": c["yellow"],
                             "info": c["blue"]}.get(f.severity, "")
                    print(f"        {sev_c}{f.severity:7s}{c['reset']} "
                          f"{f.file}:{f.line}  {f.description}")
                if len(filtered) > 20:
                    print(f"        ... and {len(filtered) - 20} more")
        print(f"\n{c['cyan']}{'=' * 60}{c['reset']}\n")

# ---------------------------------------------------------------------------
# Auto-fixer
# ---------------------------------------------------------------------------

class AutoFixer:
    """Apply automatic fixes for spelling, file mode quoting, and FQCN."""

    FIXABLE_CHECKS = {"spelling", "file_mode", "fqcn"}

    def __init__(self, scanner: RepoScanner, results: List[CheckResult]):
        self.scanner = scanner
        self.results = results

    def fix_all(self) -> int:
        """Apply all auto-fixes. Returns count of fixes applied."""
        # Group fixable findings by absolute file path
        by_file: Dict[str, List[Finding]] = defaultdict(list)
        for r in self.results:
            for f in r.findings:
                if f.check_name in self.FIXABLE_CHECKS:
                    abs_path = os.path.join(self.scanner.directory, f.file)
                    by_file[abs_path].append(f)

        fixes_applied = 0
        for abs_path, findings in by_file.items():
            try:
                with open(abs_path, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except OSError:
                continue

            modified = False
            fixed_lines: Set[int] = set()
            # Sort by line number descending to avoid index shifts
            for finding in sorted(findings, key=lambda f: f.line, reverse=True):
                idx = finding.line - 1
                if idx < 0 or idx >= len(lines) or idx in fixed_lines:
                    continue
                new_line = self._apply_fix(lines[idx], finding)
                if new_line != lines[idx]:
                    lines[idx] = new_line
                    modified = True
                    fixes_applied += 1
                    fixed_lines.add(idx)

            if modified:
                with open(abs_path, "w", encoding="utf-8") as fh:
                    fh.writelines(lines)
                # Invalidate cache for this file
                if abs_path in self.scanner._file_cache:
                    del self.scanner._file_cache[abs_path]

        return fixes_applied

    def _apply_fix(self, line: str, finding: Finding) -> str:
        if finding.check_name == "spelling":
            return self._fix_spelling(line, finding)
        if finding.check_name == "file_mode":
            return self._fix_file_mode(line, finding)
        if finding.check_name == "fqcn":
            return self._fix_fqcn(line, finding)
        return line

    def _fix_spelling(self, line: str, finding: Finding) -> str:
        m = re.search(r"Misspelling: '(\w+)' -> '(\w+)'",
                       finding.description)
        if not m:
            return line
        wrong, right = m.group(1), m.group(2)

        def _replacer(match: re.Match) -> str:
            original = match.group(0)
            if original.isupper():
                return right.upper()
            if original[0].isupper():
                return right.capitalize()
            return right

        return re.sub(r"\b" + re.escape(wrong) + r"\b", _replacer, line,
                       count=1, flags=re.IGNORECASE)

    def _fix_file_mode(self, line: str, finding: Finding) -> str:
        m = re.search(r"Unquoted file mode: '(\d+)'", finding.description)
        if not m:
            return line
        mode = m.group(1)
        return line.replace(f"mode: {mode}", f"mode: '{mode}'", 1)

    def _fix_fqcn(self, line: str, finding: Finding) -> str:
        m = re.search(r"Non-FQCN module: '(\w+)'", finding.description)
        if not m:
            return line
        module = m.group(1)
        fqcn = f"ansible.builtin.{module}"
        # Replace at the correct position (task-level key)
        return re.sub(
            r"^(\s+)" + re.escape(module) + r":",
            r"\1" + fqcn + ":",
            line, count=1)

# ---------------------------------------------------------------------------
# Baseline manager
# ---------------------------------------------------------------------------

class BaselineManager:
    """Save / load / compare baselines for delta reporting."""

    @staticmethod
    def save(results: List[CheckResult], filepath: str) -> None:
        data = {
            "tool_version": TOOL_VERSION,
            "date": datetime.datetime.now().isoformat(),
            "findings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "description": f.description,
                    "severity": f.severity,
                    "check": f.check_name,
                }
                for r in results for f in r.findings
            ],
        }
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    @staticmethod
    def load(filepath: str) -> Dict[str, Any]:
        with open(filepath, "r", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def delta(results: List[CheckResult],
              baseline_data: Dict[str, Any]) -> List[CheckResult]:
        """Return new CheckResults containing only findings not in baseline."""
        baseline_keys: Set[Tuple[str, str]] = {
            (f["file"], f["description"])
            for f in baseline_data.get("findings", [])
        }
        new_results: List[CheckResult] = []
        for r in results:
            new_findings = [
                f for f in r.findings
                if (f.file, f.description) not in baseline_keys
            ]
            if new_findings:
                new_results.append(CheckResult(
                    name=r.name, status=r.status,
                    findings=new_findings,
                    summary=f"{len(new_findings)} new issue(s)"))
            else:
                new_results.append(CheckResult(
                    name=r.name, status=r.status,
                    findings=[],
                    summary=r.summary if r.status in ("PASS", "SKIP")
                            else "0 new issue(s)"))
        return new_results

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _resolve_directory(user_dir: Optional[str]) -> str:
    """Resolve the role directory.

    Priority:
      1. Explicit ``-d`` / ``--directory`` from the user.
      2. The directory containing this script (covers ``python3 /path/to/tool``).
      3. The current working directory.
    """
    if user_dir is not None:
        return os.path.abspath(user_dir)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.isfile(os.path.join(script_dir, "defaults", "main.yml")):
        return script_dir
    return os.path.abspath(os.getcwd())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Ansible-Lockdown_QA_Repo_Check",
        description="Comprehensive QA tool for Ansible-Lockdown repositories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              python3 Ansible-Lockdown_QA_Repo_Check.py
              python3 Ansible-Lockdown_QA_Repo_Check.py -b rhel9cis -f html
              python3 Ansible-Lockdown_QA_Repo_Check.py --skip spelling,grammar --console
              python3 Ansible-Lockdown_QA_Repo_Check.py -d /path/to/role --verbose
              python3 Ansible-Lockdown_QA_Repo_Check.py --fix --console
              python3 Ansible-Lockdown_QA_Repo_Check.py --save-baseline baseline.json
              python3 Ansible-Lockdown_QA_Repo_Check.py --baseline baseline.json --console
              python3 Ansible-Lockdown_QA_Repo_Check.py --min-severity warning -f json
              python3 Ansible-Lockdown_QA_Repo_Check.py --console --no-report
              python3 Ansible-Lockdown_QA_Repo_Check.py --strict

            check names for --skip:
              yamllint, ansiblelint, spelling, grammar, unused_vars,
              var_naming, file_mode, company_naming, audit_template,
              fqcn, rule_coverage

            exit codes:
              0  All checks passed (or only warnings without --strict)
              1  Warnings found with --strict
              2  Errors found (FAIL status)
        """))
    parser.add_argument("-b", "--benchmark", default=None,
                        help="Benchmark variable prefix (auto-detected)")
    parser.add_argument("-f", "--format", choices=["md", "html", "json"],
                        default="md", help="Report format (default: md)")
    parser.add_argument("-o", "--output", default=None,
                        help="Output file (default: qa_report.{format})")
    parser.add_argument("-d", "--directory", default=None,
                        help="Repository directory (default: script location or cwd)")
    parser.add_argument("--skip", default="",
                        help="Comma-separated checks to skip")
    parser.add_argument("--min-severity",
                        choices=["info", "warning", "error"],
                        default=None,
                        help="Minimum severity to include in reports (default: info)")
    parser.add_argument("--fix", action="store_true",
                        help="Auto-fix spelling, file mode quoting, and FQCN issues")
    parser.add_argument("--save-baseline", default=None, metavar="FILE",
                        help="Save current findings as a baseline JSON file")
    parser.add_argument("--baseline", default=None, metavar="FILE",
                        help="Compare against baseline, only show new findings")
    parser.add_argument("--no-report", action="store_true",
                        help="Skip writing a report file (console-only mode)")
    parser.add_argument("--strict", action="store_true",
                        help="Exit 1 on warnings (WARN), exit 2 on errors (FAIL)")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose output during run")
    parser.add_argument("--console", action="store_true",
                        help="Print colored results to terminal")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {TOOL_VERSION}")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    directory = _resolve_directory(args.directory)
    defaults = os.path.join(directory, "defaults", "main.yml")
    if not os.path.isfile(defaults):
        print(f"Error: '{defaults}' not found. "
              "Are you in an Ansible role directory?\n"
              "Use -d /path/to/role to specify the role directory.",
              file=sys.stderr)
        sys.exit(1)

    # Load per-repo config
    config = ConfigLoader.load(directory)

    # Merge CLI overrides
    skip = {s.strip().lower() for s in args.skip.split(",") if s.strip()}
    skip |= set(config.get("skip_checks", []))

    min_severity = args.min_severity or config.get("min_severity", "info")

    # Determine output file to exclude from scanning
    output_ext = args.format
    if args.no_report:
        output_path = None
    else:
        output_path = args.output or f"qa_report.{output_ext}"
        if not os.path.isabs(output_path):
            output_path = os.path.join(directory, output_path)
    exclude_paths = {os.path.abspath(output_path)} if output_path else set()

    scanner = RepoScanner(directory, args.benchmark, skip, args.verbose,
                          config, exclude_paths)

    metadata = ReportMetadata(
        repo_name=scanner.get_repo_name(),
        branch=scanner.get_git_branch(),
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        tool_version=TOOL_VERSION,
        benchmark_prefix=scanner.benchmark_prefix,
    )

    if args.verbose:
        print(f"Scanning: {directory}", file=sys.stderr)
        print(f"Detected prefix: {scanner.benchmark_prefix}", file=sys.stderr)

    results = scanner.run_all_checks()

    # Auto-fix
    if args.fix:
        fixer = AutoFixer(scanner, results)
        count = fixer.fix_all()
        print(f"Auto-fix: {count} issue(s) fixed.", file=sys.stderr)
        if count > 0:
            print("Re-run the tool to verify fixes.", file=sys.stderr)

    # Save baseline before delta filtering
    if args.save_baseline:
        bl_path = args.save_baseline
        if not os.path.isabs(bl_path):
            bl_path = os.path.join(directory, bl_path)
        BaselineManager.save(results, bl_path)
        print(f"Baseline saved to: {bl_path}", file=sys.stderr)

    # Apply baseline delta if requested
    display_results = results
    if args.baseline:
        bl_path = args.baseline
        if not os.path.isabs(bl_path):
            bl_path = os.path.join(directory, bl_path)
        try:
            baseline_data = BaselineManager.load(bl_path)
            display_results = BaselineManager.delta(results, baseline_data)
            if args.verbose:
                print(f"Baseline loaded from: {bl_path}", file=sys.stderr)
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            print(f"Warning: Could not load baseline '{bl_path}': {exc}",
                  file=sys.stderr)

    # Console output
    if args.console:
        ConsoleOutput(display_results, sys.stdout.isatty(),
                      min_severity).print_results()

    # Write report
    if output_path is not None:
        report = ReportGenerator(metadata, display_results, args.format,
                                 min_severity).generate()
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Report written to: {output_path}")

    has_errors = any(r.status == "FAIL" for r in display_results)
    has_warnings = any(r.status == "WARN" for r in display_results)
    if has_errors:
        sys.exit(2)
    if has_warnings and args.strict:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
