#!/usr/bin/env python3
"""Find and optionally fix common misspellings in Ansible-Lockdown role files.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Uses a built-in dictionary of common English and Ansible-specific
misspellings. Checks task names, comments, and documentation.
Strips Jinja2 {{ expressions }} before analysis to avoid false positives.

Usage:
    python fix_spelling.py <repo_path> [--fix] [--skip-dir DIR ...]
"""

import argparse
import os
import re
import sys

# ---------------------------------------------------------------------------
# Misspelling dictionary (from Ansible_Lockdown_QA_Repo_Check.py)
# ---------------------------------------------------------------------------

MISSPELLING_DICT = {
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
    "benckmark": "benchmark", "benchamrk": "benchmark", "benmarks": "benchmarks",
    "compliane": "compliance", "compiance": "compliance",
    "hardning": "hardening", "hardenning": "hardening",
}

# Known valid words that look like misspellings
SPELL_EXCEPTIONS = {
    "nftables", "tmpfiles", "logrotate", "systemctl", "chrony",
    "sshd", "grub", "auditd", "rsyslog", "journald", "coredump",
    "sudo", "polkit", "fstab", "sysctl", "modprobe",
}

EXTENSIONS = {".yml", ".yaml", ".j2", ".md"}
DEFAULT_SKIP_DIRS = {".git", ".github", "molecule", "__pycache__", ".ansible", "collections"}
JINJA2_RE = re.compile(r"\{\{.*?\}\}")


def find_files(repo_path, skip_dirs):
    """Find all eligible files."""
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in filenames:
            if any(fname.endswith(ext) for ext in EXTENSIONS):
                files.append(os.path.join(root, fname))
    return sorted(files)


def extract_text(line, ext):
    """Extract checkable text from a line (comments and task names)."""
    texts = []
    stripped = line.lstrip()

    # Comments
    if ext in (".yml", ".yaml", ".j2"):
        m = re.search(r"(?:^|\s)#\s*(.*)", line)
        if m:
            texts.append(m.group(1))

    # Task names
    if ext in (".yml", ".yaml"):
        m = re.match(r"\s*-?\s*name:\s*(.+)", line)
        if m:
            val = m.group(1).strip().strip("'\"")
            texts.append(val)

    # Markdown content
    if ext == ".md":
        texts.append(line.rstrip("\n"))

    return texts


def scan_file(filepath, repo_path, extra_exceptions=None):
    """Scan a file for misspellings."""
    issues = []
    exceptions = SPELL_EXCEPTIONS | (extra_exceptions or set())
    rel = os.path.relpath(filepath, repo_path)
    ext = os.path.splitext(filepath)[1]

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for num, line in enumerate(f, 1):
                texts = extract_text(line, ext)
                for text in texts:
                    if re.search(r"https?://", text):
                        continue
                    text = JINJA2_RE.sub("", text)
                    words = re.findall(r"[a-zA-Z']+", text)
                    for word in words:
                        low = word.lower().strip("'")
                        if low in exceptions:
                            continue
                        if low in MISSPELLING_DICT:
                            issues.append({
                                "file": rel,
                                "line": num,
                                "word": word,
                                "fix": MISSPELLING_DICT[low],
                                "raw": line.rstrip(),
                            })
    except (IOError, OSError) as e:
        print(f"  Error reading {filepath}: {e}", file=sys.stderr)

    return issues


def apply_fixes(filepath, issues):
    """Apply spelling fixes to a file."""
    if not issues:
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    modified = False
    for issue in issues:
        word = issue["word"]
        fix = issue["fix"]
        # Preserve case: if original was capitalized, capitalize fix
        if word[0].isupper():
            fix = fix[0].upper() + fix[1:]
        if word.isupper():
            fix = fix.upper()

        # Use word boundary replacement to avoid partial matches
        new_content = re.sub(
            rf"\b{re.escape(word)}\b", fix, content, count=1)
        if new_content != content:
            content = new_content
            modified = True

    if modified:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

    return modified


def main():
    parser = argparse.ArgumentParser(
        description="Find and fix misspellings in Ansible-Lockdown roles")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--fix", action="store_true", help="Apply fixes automatically")
    parser.add_argument("--skip-dir", nargs="*", default=[],
                        help="Additional directories to skip")
    parser.add_argument("--exception", nargs="*", default=[],
                        help="Additional words to allow")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    skip_dirs = DEFAULT_SKIP_DIRS | set(args.skip_dir)
    extra_exceptions = set(args.exception)

    # Load .qa_config.yml spelling_exceptions if present
    qa_config = os.path.join(args.repo_path, ".qa_config.yml")
    if os.path.isfile(qa_config):
        try:
            with open(qa_config, "r") as f:
                for line in f:
                    m = re.match(r"\s*-\s*(\S+)", line)
                    if m:
                        extra_exceptions.add(m.group(1).lower())
        except (IOError, OSError):
            pass

    files = find_files(args.repo_path, skip_dirs)
    total_issues = 0
    files_with_issues = 0

    for filepath in files:
        issues = scan_file(filepath, args.repo_path, extra_exceptions)
        if issues:
            files_with_issues += 1
            for issue in issues:
                total_issues += 1
                print(f"  [info] {issue['file']}:{issue['line']} "
                      f"- '{issue['word']}' -> '{issue['fix']}'")

            if args.fix:
                if apply_fixes(filepath, issues):
                    rel = os.path.relpath(filepath, args.repo_path)
                    print(f"  FIXED: {rel}")

    print(f"\n{'='*60}")
    print(f"Total misspellings: {total_issues} in {files_with_issues} file(s)")
    if not args.fix and total_issues > 0:
        print("Run with --fix to apply automatic fixes")

    sys.exit(1 if total_issues > 0 else 0)


if __name__ == "__main__":
    main()
