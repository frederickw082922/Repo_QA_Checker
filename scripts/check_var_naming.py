#!/usr/bin/env python3
"""Check register variable naming and detect duplicate defaults/registers.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Validates:
- Register variable names use accepted prefixes (discovered_, prelim_,
  pre_audit_, post_audit_, set_)
- No duplicate register variable names across task files
- No duplicate top-level keys in defaults/main.yml
- Forward/reverse variable coverage (defined but unused, used but undefined)

Handles both CIS and STIG naming patterns:
- CIS:  config prefix = rule prefix (e.g. ubtu20cis_rule_1_1_1_1)
- STIG: config prefix differs from rule prefix
        (e.g. config: rhel8stig_*, rules: rhel_08_010000)

Usage:
    python check_var_naming.py <repo_path> [--prefix PREFIX] [--type cis|stig]
"""

import argparse
import os
import tempfile
import re
import sys
from collections import Counter

SKIP_DIRS = {".git", "__pycache__", ".github", "collections"}

VALID_REGISTER_PREFIXES = ("discovered_", "prelim_", "pre_audit_", "post_audit_", "set_")

ANSIBLE_BUILTINS = {
    "item", "ansible_facts", "ansible_env", "ansible_check_mode",
    "ansible_diff_mode", "ansible_version", "ansible_play_hosts",
    "ansible_play_batch", "ansible_playbook_python", "ansible_connection",
    "ansible_host", "ansible_port", "ansible_user", "ansible_forks",
    "inventory_hostname", "inventory_hostname_short", "group_names",
    "groups", "hostvars", "play_hosts", "role_path", "playbook_dir",
    "omit", "true", "false", "none", "ansible_local",
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


def extract_bridge_template_output_keys(repo_path):
    """Extract output key names from the goss bridge template.

    In ansible_vars_goss.yml.j2, lines like 'some_key: {{ some_var }}'
    define output keys (left-hand side) that are NOT variable references.
    These should not be flagged as 'referenced but not defined'.
    """
    output_keys = set()
    template_path = os.path.join(repo_path, "templates",
                                 "ansible_vars_goss.yml.j2")
    if not os.path.isfile(template_path):
        return output_keys

    with open(template_path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.rstrip()
            # Skip comments, Jinja2 control, empty lines, indented (list items)
            if not s or s.startswith("#") or s.startswith("{%"):
                continue
            # Match top-level YAML keys: 'key_name: ...' (not indented or 2-space indented for nested)
            m = re.match(r"^(\s*)([a-zA-Z_]\w*)\s*:", s)
            if m:
                output_keys.add(m.group(2))
    return output_keys


def extract_set_fact_vars(repo_path):
    """Extract variables created by set_fact tasks in task and handler files.

    These are runtime-created variables, not expected in defaults/main.yml.
    Scans both tasks/ and handlers/ because handlers can also use set_fact.
    """
    fact_vars = set()
    scan_dirs = [
        os.path.join(repo_path, "tasks"),
        os.path.join(repo_path, "handlers"),
    ]
    for scan_dir in scan_dirs:
        if not os.path.isdir(scan_dir):
            continue
        for root, dirs, filenames in os.walk(scan_dir):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                if not fname.endswith((".yml", ".yaml")):
                    continue
                filepath = os.path.join(root, fname)
                in_set_fact = False
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        s = line.rstrip()
                        if re.search(r"set_fact:", s):
                            in_set_fact = True
                            continue
                        if in_set_fact:
                            fm = re.match(r"\s+([a-zA-Z_]\w*):", s)
                            if fm:
                                fact_vars.add(fm.group(1))
                            elif s and not s.startswith("#") and not s.startswith(" "):
                                in_set_fact = False
    return fact_vars


def extract_handler_register_vars(repo_path):
    """Extract register variables from handler files."""
    handler_vars = set()
    handlers_dir = os.path.join(repo_path, "handlers")
    if not os.path.isdir(handlers_dir):
        return handler_vars

    for root, dirs, filenames in os.walk(handlers_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if not fname.endswith((".yml", ".yaml")):
                continue
            filepath = os.path.join(root, fname)
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    rm = re.match(r"\s*register:\s*(\S+)", line)
                    if rm:
                        handler_vars.add(rm.group(1))
    return handler_vars


def detect_prefixes(repo_path):
    """Auto-detect benchmark variable prefixes from defaults/main.yml.

    Returns (config_prefix, rule_prefix, benchmark_type).

    CIS repos have a single prefix for both config and rules:
        ubtu20cis_rule_1_1_1_1, ubtu20cis_syslog_target, etc.

    STIG repos have two distinct prefixes:
        Config: rhel8stig_cat1, rhel8stig_gui, etc.
        Rules:  rhel_08_010000, rhel_08_020235, etc.
    """
    defaults = _defaults_view(repo_path)
    if not os.path.isfile(defaults):
        return None, None, None

    cis_rule_counter = Counter()
    stig_rule_counter = Counter()
    # For STIG config prefix, count prefixes of non-rule variables
    # (vars that don't match the {xx}_\d{6} pattern)
    stig_config_counter = Counter()

    cis_pat = re.compile(r"^(\w+)_rule_\d")
    # STIG pattern A: prefix with 2-digit numeric segment (e.g. rhel_08_010000)
    stig_pat_a = re.compile(r"^(\w+_\d{2})_(\d{6})\s*:")
    # STIG pattern B: prefix ending in "stig" + _6digits (e.g. az2023stig_001010)
    stig_pat_b = re.compile(r"^(\w*stig)_(\d{6})\s*:", re.IGNORECASE)
    # Non-rule var: starts with letters, no 6-digit suffix
    nonrule_pat = re.compile(r"^([a-zA-Z]\w*?)_[a-zA-Z]")

    with open(defaults, "r", encoding="utf-8") as f:
        for line in f:
            s = line.rstrip()
            if not s or s.startswith("#") or s[0] in (" ", "\t"):
                continue

            m_cis = cis_pat.match(s)
            if m_cis:
                cis_rule_counter[m_cis.group(1)] += 1
                continue

            m_stig = stig_pat_a.match(s)
            if not m_stig:
                m_stig = stig_pat_b.match(s)
            if m_stig:
                stig_rule_counter[m_stig.group(1)] += 1
                continue

            # Non-rule variable — extract config prefix
            m_nr = nonrule_pat.match(s)
            if m_nr:
                stig_config_counter[m_nr.group(1)] += 1

    # Determine benchmark type
    cis_count = cis_rule_counter.most_common(1)[0][1] if cis_rule_counter else 0
    stig_count = stig_rule_counter.most_common(1)[0][1] if stig_rule_counter else 0

    if cis_count >= stig_count and cis_count > 0:
        prefix = cis_rule_counter.most_common(1)[0][0]
        return prefix, prefix, "cis"
    elif stig_count > 0:
        rule_prefix = stig_rule_counter.most_common(1)[0][0]
        # Config prefix: most common prefix among non-rule variables
        config_prefix = (stig_config_counter.most_common(1)[0][0]
                         if stig_config_counter else rule_prefix)
        return config_prefix, rule_prefix, "stig"
    elif stig_config_counter:
        prefix = stig_config_counter.most_common(1)[0][0]
        return prefix, prefix, "cis"

    return None, None, None


def check_register_naming(repo_path, valid_prefixes):
    """Check that register variables use accepted prefixes."""
    issues = []
    tasks_dir = os.path.join(repo_path, "tasks")
    if not os.path.isdir(tasks_dir):
        return issues

    for root, dirs, filenames in os.walk(tasks_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if not fname.endswith((".yml", ".yaml")):
                continue
            filepath = os.path.join(root, fname)
            rel = os.path.relpath(filepath, repo_path)
            with open(filepath, "r", encoding="utf-8") as f:
                for num, line in enumerate(f, 1):
                    m = re.match(r"\s*register:\s*(\S+)", line)
                    if m:
                        var = m.group(1)
                        if not any(var.startswith(p) for p in valid_prefixes):
                            issues.append({
                                "file": rel, "line": num,
                                "var": var, "type": "register_prefix",
                                "severity": "warning",
                                "description": (
                                    f"Non-standard register name: '{var}' "
                                    f"(expected: {', '.join(valid_prefixes)})"),
                            })
    return issues


def check_duplicate_registers(repo_path):
    """Check for duplicate register variable names across task files."""
    issues = []
    seen = {}  # var -> (file, line)
    tasks_dir = os.path.join(repo_path, "tasks")
    if not os.path.isdir(tasks_dir):
        return issues

    for root, dirs, filenames in os.walk(tasks_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in sorted(filenames):
            if not fname.endswith((".yml", ".yaml")):
                continue
            filepath = os.path.join(root, fname)
            rel = os.path.relpath(filepath, repo_path)
            with open(filepath, "r", encoding="utf-8") as f:
                for num, line in enumerate(f, 1):
                    m = re.match(r"\s*register:\s*(\S+)", line)
                    if m:
                        var = m.group(1)
                        if var in seen:
                            prev_file, prev_line = seen[var]
                            issues.append({
                                "file": rel, "line": num,
                                "var": var, "type": "dup_register",
                                "severity": "warning",
                                "description": (
                                    f"Duplicate register '{var}' "
                                    f"(first at {prev_file}:{prev_line})"),
                            })
                        else:
                            seen[var] = (rel, num)
    return issues


def check_duplicate_defaults(repo_path):
    """Check for duplicate top-level keys in defaults/main.yml."""
    issues = []
    defaults = _defaults_view(repo_path)
    if not os.path.isfile(defaults):
        return issues

    seen = {}  # var -> line
    with open(defaults, "r", encoding="utf-8") as f:
        for num, line in enumerate(f, 1):
            s = line.rstrip()
            if not s or s.startswith("#") or s[0] in (" ", "\t"):
                continue
            m = re.match(r"^([a-zA-Z_]\w*):", s)
            if m:
                var = m.group(1)
                if var in seen:
                    issues.append({
                        "file": "defaults/main.yml", "line": num,
                        "var": var, "type": "dup_default",
                        "severity": "warning",
                        "description": (
                            f"Duplicate default '{var}' "
                            f"(first at line {seen[var]})"),
                    })
                else:
                    seen[var] = num
    return issues


def collect_deployed_templates(repo_path):
    """Return set of template src paths actually deployed by task files.

    Paths are normalised relative to the templates/ directory so they can be
    matched against os.path.relpath(filepath, templates_dir).  Basenames are
    also added to support simple filename-only references.
    """
    deployed = set()
    tasks_dir = os.path.join(repo_path, "tasks")
    if not os.path.isdir(tasks_dir):
        return deployed

    src_pat = re.compile(r"src:\s*['\"]?(.+?\.j2)['\"]?\s*(?:#.*)?$")
    for root, dirs, filenames in os.walk(tasks_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if not fname.endswith((".yml", ".yaml")):
                continue
            filepath = os.path.join(root, fname)
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    m = src_pat.search(line.rstrip())
                    if not m:
                        continue
                    src = m.group(1).strip("'\" ")
                    # Dynamic paths with Jinja2 expressions cannot be resolved statically;
                    # treat them as always-deployed so we do not suppress real errors.
                    if "{{" in src:
                        continue
                    # Normalise: strip spurious leading templates/ prefix if present
                    src = re.sub(r"^templates/", "", src)
                    deployed.add(src)
                    deployed.add(os.path.basename(src))
    return deployed


def check_forward_reverse(repo_path, config_prefix, rule_prefix, benchmark_type):
    """Check forward (defined->used) and reverse (used->defined) coverage.

    For STIG repos, checks both config prefix (rhel8stig_*) and rule prefix
    (rhel_08_*) variables. For CIS repos, both prefixes are the same.
    """
    issues = []
    if not config_prefix:
        return issues

    # Build set of all prefixes to track for reverse checks
    prefixes = {config_prefix}
    if rule_prefix and rule_prefix != config_prefix:
        prefixes.add(rule_prefix)

    # Collect defined variables
    defined = {}
    defaults = _defaults_view(repo_path)
    if os.path.isfile(defaults):
        with open(defaults, "r", encoding="utf-8") as f:
            for num, line in enumerate(f, 1):
                s = line.rstrip()
                if not s or s.startswith("#") or s[0] in (" ", "\t"):
                    continue
                m = re.match(r"^([a-zA-Z_]\w*):", s)
                if m:
                    defined[m.group(1)] = num

    # Also collect vars from vars/main.yml
    for varfile in ("vars/main.yml", "vars/audit.yml"):
        vpath = os.path.join(repo_path, varfile)
        if os.path.isfile(vpath):
            with open(vpath, "r", encoding="utf-8") as f:
                for num, line in enumerate(f, 1):
                    s = line.rstrip()
                    if not s or s.startswith("#") or s[0] in (" ", "\t"):
                        continue
                    m = re.match(r"^([a-zA-Z_]\w*):", s)
                    if m:
                        defined[m.group(1)] = num

    # Build deployed template set once; used by both forward and reverse scans
    deployed_templates = collect_deployed_templates(repo_path)
    templates_dir = os.path.join(repo_path, "templates")

    # Collect all tokens from tasks/templates/handlers for forward check
    usage_tokens = set()
    for subdir in ("tasks", "templates", "handlers"):
        dirpath = os.path.join(repo_path, subdir)
        if not os.path.isdir(dirpath):
            continue
        for root, dirs, filenames in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                if not fname.endswith((".yml", ".yaml", ".j2")):
                    continue
                filepath = os.path.join(root, fname)
                # Skip orphaned templates — only scan templates actually deployed
                # by a 'template: src:' task to avoid false positives from stale drafts
                if fname.endswith(".j2") and os.path.isdir(templates_dir):
                    rel_to_templates = os.path.relpath(filepath, templates_dir)
                    if (rel_to_templates not in deployed_templates
                            and os.path.basename(fname) not in deployed_templates):
                        continue
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        usage_tokens.update(re.findall(r"[a-zA-Z_]\w*", line))

    # Also collect cross-references within defaults/vars (values referencing other vars)
    var_cross_tokens = set()
    for varfile in ("defaults/main.yml", "vars/main.yml", "vars/audit.yml"):
        vpath = os.path.join(repo_path, varfile)
        if not os.path.isfile(vpath):
            continue
        with open(vpath, "r", encoding="utf-8") as f:
            for line in f:
                s = line.rstrip()
                tokens = set(re.findall(r"[a-zA-Z_]\w*", line))
                # Exclude the key being defined on definition lines
                if s and not s.startswith("#") and s[0] not in (" ", "\t"):
                    dm = re.match(r"^([a-zA-Z_]\w*):", s)
                    if dm:
                        tokens.discard(dm.group(1))
                var_cross_tokens.update(tokens)

    all_referenced = usage_tokens | var_cross_tokens

    # Forward: defined but not used (only check prefix-matching vars)
    for var, line_num in sorted(defined.items()):
        if var not in all_referenced:
            # Only flag vars matching one of our prefixes
            if any(var.startswith(p) for p in prefixes):
                issues.append({
                    "file": "defaults/main.yml", "line": line_num,
                    "var": var, "type": "unused_var",
                    "severity": "warning",
                    "description": f"Defined but never referenced: '{var}'",
                })

    # Reverse: used but not defined
    # Build regex for all prefixes
    prefix_patterns = [re.escape(p) + r"_[a-zA-Z0-9_]+" for p in prefixes]
    combined_pat = re.compile(r"\b(" + "|".join(prefix_patterns) + r")\b")

    # Regex to detect template src/dest lines where tokens are file paths, not vars
    template_path_pat = re.compile(
        r"^\s*(src|dest|path|creates|removes):\s")

    referenced = {}
    for subdir in ("tasks", "templates", "handlers"):
        dirpath = os.path.join(repo_path, subdir)
        if not os.path.isdir(dirpath):
            continue
        for root, dirs, filenames in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                if not fname.endswith((".yml", ".yaml", ".j2")):
                    continue
                filepath = os.path.join(root, fname)
                # Skip orphaned templates — variables in undeployed templates are
                # not real runtime references; they produce false-positive errors
                if fname.endswith(".j2") and os.path.isdir(templates_dir):
                    rel_to_templates = os.path.relpath(filepath, templates_dir)
                    if (rel_to_templates not in deployed_templates
                            and os.path.basename(fname) not in deployed_templates):
                        continue
                rel = os.path.relpath(filepath, repo_path)
                with open(filepath, "r", encoding="utf-8") as f:
                    for num, line in enumerate(f, 1):
                        if line.lstrip().startswith("#"):
                            continue
                        # Skip template src/dest lines — tokens there are
                        # file paths (e.g. audit/ubtu20cis_6_3_3_1_scope.rules.j2)
                        # not variable references
                        if template_path_pat.match(line):
                            continue
                        for m in combined_pat.finditer(line):
                            vname = m.group(1)
                            if vname not in referenced:
                                referenced[vname] = (rel, num)

    # Collect dynamic vars (registers, set_fact, handler registers)
    dynamic_vars = set()
    tasks_dir = os.path.join(repo_path, "tasks")
    if os.path.isdir(tasks_dir):
        for root, dirs, filenames in os.walk(tasks_dir):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                if not fname.endswith((".yml", ".yaml")):
                    continue
                filepath = os.path.join(root, fname)
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        rm = re.match(r"\s*register:\s*(\S+)", line)
                        if rm:
                            dynamic_vars.add(rm.group(1))

    # Collect set_fact vars, handler register vars, and bridge template output keys
    set_fact_vars = extract_set_fact_vars(repo_path)
    handler_reg_vars = extract_handler_register_vars(repo_path)
    bridge_output_keys = extract_bridge_template_output_keys(repo_path)

    # Also pick up commented-out defaults
    all_defined = (set(defined.keys()) | dynamic_vars | set_fact_vars
                   | handler_reg_vars | bridge_output_keys | ANSIBLE_BUILTINS)
    if os.path.isfile(defaults):
        with open(defaults, "r", encoding="utf-8") as f:
            for line in f:
                for p in prefixes:
                    cm = re.match(r"^#\s*(" + re.escape(p) + r"_\w+):", line)
                    if cm:
                        all_defined.add(cm.group(1))

    for vname, (rfile, rline) in referenced.items():
        if vname in all_defined:
            continue
        # Check if it's a substring of a dynamic var
        is_substr = any(dv.startswith(vname + "_") for dv in dynamic_vars)
        if is_substr:
            continue
        issues.append({
            "file": rfile, "line": rline,
            "var": vname, "type": "undefined_var",
            "severity": "error",
            "description": f"Referenced but not defined: '{vname}'",
        })

    return issues


def main():
    parser = argparse.ArgumentParser(
        description="Check variable naming and detect duplicates")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--prefix", help="Config prefix (auto-detected if omitted)")
    parser.add_argument("--type", choices=["cis", "stig"], default=None,
                        help="Benchmark type (auto-detected if omitted)")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    if args.prefix:
        config_prefix = args.prefix
        rule_prefix = args.prefix
        bm_type = args.type or "cis"
    else:
        config_prefix, rule_prefix, bm_type = detect_prefixes(args.repo_path)
        if args.type:
            bm_type = args.type

    print(f"Benchmark type:   {bm_type or '(not detected)'}")
    print(f"Config prefix:    {config_prefix or '(not detected)'}")
    if rule_prefix and rule_prefix != config_prefix:
        print(f"Rule prefix:      {rule_prefix}")

    all_issues = []

    # Run all checks
    print("\nChecking register naming conventions...")
    register_issues = check_register_naming(args.repo_path, VALID_REGISTER_PREFIXES)
    all_issues.extend(register_issues)

    print("Checking duplicate register variables...")
    dup_reg_issues = check_duplicate_registers(args.repo_path)
    all_issues.extend(dup_reg_issues)

    print("Checking duplicate defaults...")
    dup_def_issues = check_duplicate_defaults(args.repo_path)
    all_issues.extend(dup_def_issues)

    print("Checking forward/reverse variable coverage...")
    fwd_rev_issues = check_forward_reverse(
        args.repo_path, config_prefix, rule_prefix, bm_type)
    all_issues.extend(fwd_rev_issues)

    # Print issues grouped by severity
    if all_issues:
        errors = [i for i in all_issues if i["severity"] == "error"]
        warnings = [i for i in all_issues if i["severity"] == "warning"]

        if errors:
            print(f"\nErrors ({len(errors)}):")
            for issue in errors:
                print(f"  [error] {issue['file']}:{issue['line']} "
                      f"- {issue['description']}")

        if warnings:
            print(f"\nWarnings ({len(warnings)}):")
            for issue in warnings:
                print(f"  [warning] {issue['file']}:{issue['line']} "
                      f"- {issue['description']}")

    # Summary
    print(f"\n{'='*60}")
    print(f"Register prefix violations: {len(register_issues)}")
    print(f"Duplicate registers:        {len(dup_reg_issues)}")
    print(f"Duplicate defaults:         {len(dup_def_issues)}")
    print(f"Forward/reverse issues:     {len(fwd_rev_issues)}")
    print(f"Total issues:               {len(all_issues)}")

    has_errors = any(i["severity"] == "error" for i in all_issues)
    sys.exit(1 if has_errors else 0)


if __name__ == "__main__":
    main()
