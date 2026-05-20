#!/usr/bin/env python3
"""Build a variable dependency graph for Ansible Lockdown roles.

Maps every register: and set_fact: variable to all files+lines that
define or reference it. Useful for safe renames, dead code detection,
and understanding cross-file dependencies.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Output modes:
  --format table   Human-readable table (default)
  --format json    Machine-readable JSON
  --format dot     Graphviz DOT for visualization

Filters:
  --var NAME       Show graph for a single variable
  --prefix PREFIX  Only show variables matching prefix
  --orphans        Only show variables with no references
  --file PATH      Only show variables defined in or referenced by PATH

Usage:
    python dependency_graph.py <repo_path>
    python dependency_graph.py <repo_path> --var discovered_ssh_host_priv_keys
    python dependency_graph.py <repo_path> --orphans
    python dependency_graph.py <repo_path> --format json > graph.json
    python dependency_graph.py <repo_path> --format dot | dot -Tpng -o graph.png
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", ".tox", "node_modules"}

SCAN_EXTENSIONS = (".yml", ".yaml", ".j2")

SCAN_DIRS = ("tasks", "templates", "handlers", "defaults", "vars", "meta")

# Patterns for variable definitions
REGISTER_PAT = re.compile(r"^\s*register:\s*\"?(\w+)\"?")
SET_FACT_KEY_PAT = re.compile(r"^\s+(\w+):\s*\S")
SET_FACT_START_PAT = re.compile(r"^\s*ansible\.builtin\.set_fact:|^\s*set_fact:")

# Pattern for Jinja2 variable references: {{ var }}, {{ var.attr }}, {{ var | filter }}
JINJA2_PAT = re.compile(r"\{\{[^}]*\}\}|\{%[^%]*%\}")
WORD_PAT = re.compile(r"\b([a-zA-Z_]\w*)\b")


def walk_role_files(repo_path):
    """Yield (rel_path, abs_path) for all scannable files in the role."""
    for subdir in SCAN_DIRS:
        dirpath = os.path.join(repo_path, subdir)
        if not os.path.isdir(dirpath):
            continue
        for root, dirs, filenames in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in sorted(filenames):
                if not fname.endswith(SCAN_EXTENSIONS):
                    continue
                abs_path = os.path.join(root, fname)
                rel_path = os.path.relpath(abs_path, repo_path)
                yield rel_path, abs_path


def find_definitions(repo_path):
    """Find all variable definitions (register: and set_fact:).

    Returns dict: var_name -> list of {file, line, type}
    """
    definitions = defaultdict(list)

    for rel_path, abs_path in walk_role_files(repo_path):
        with open(abs_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        in_set_fact = False
        set_fact_indent = 0

        for num, line in enumerate(lines, 1):
            stripped = line.rstrip()

            # Check for register:
            m = REGISTER_PAT.match(stripped)
            if m:
                var_name = m.group(1)
                definitions[var_name].append({
                    "file": rel_path, "line": num, "type": "register"
                })
                continue

            # Track set_fact blocks
            if SET_FACT_START_PAT.match(stripped):
                in_set_fact = True
                set_fact_indent = len(line) - len(line.lstrip())
                continue

            if in_set_fact:
                current_indent = len(line) - len(line.lstrip())
                if stripped and current_indent <= set_fact_indent:
                    in_set_fact = False
                elif stripped and current_indent > set_fact_indent:
                    m = SET_FACT_KEY_PAT.match(stripped)
                    if m:
                        var_name = m.group(1)
                        # Skip Jinja2 filters and YAML noise
                        if var_name not in ("cacheable", "when", "tags", "name",
                                            "block", "rescue", "always", "notify",
                                            "changed_when", "failed_when", "no_log"):
                            definitions[var_name].append({
                                "file": rel_path, "line": num, "type": "set_fact"
                            })

        # Also collect top-level defaults definitions
        if rel_path.startswith("defaults/") or rel_path.startswith("vars/"):
            with open(abs_path, "r", encoding="utf-8") as f:
                for num, line in enumerate(f.readlines(), 1):
                    s = line.rstrip()
                    if not s or s.startswith("#") or s[0] in (" ", "\t"):
                        continue
                    m = re.match(r"^([a-zA-Z_]\w*):", s)
                    if m:
                        definitions[m.group(1)].append({
                            "file": rel_path, "line": num, "type": "default"
                        })

    return definitions


def find_references(repo_path, variables):
    """Find all references to the given variables across the role.

    Returns dict: var_name -> list of {file, line, context}
    where context is 'when', 'jinja2', 'module_param', or 'other'.
    """
    references = defaultdict(list)
    var_set = set(variables)

    for rel_path, abs_path in walk_role_files(repo_path):
        with open(abs_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip pure comment lines. Lines that look like comments but
            # contain a Jinja2 expression are template content inside a
            # YAML block scalar (e.g. `file_managed_by_ansible: |-` body
            # with `# Provided by {{ company_title }}`) — not a YAML
            # comment. Keep those for reference detection.
            if stripped.startswith("#") and "{{" not in line:
                continue

            # Skip definition lines (register: var, set_fact key definitions)
            if REGISTER_PAT.match(stripped):
                continue

            # Determine context
            context = "other"
            if re.match(r"when:", stripped) or re.match(r"- ", stripped):
                context = "when"
            elif "{{" in line or "{%" in line:
                context = "jinja2"

            # Find all word tokens in the line
            tokens = set(WORD_PAT.findall(line))
            matched = tokens & var_set

            for var_name in matched:
                # Avoid self-references on definition lines for defaults
                if rel_path.startswith(("defaults/", "vars/")):
                    key_m = re.match(r"^([a-zA-Z_]\w*):", stripped)
                    if key_m and key_m.group(1) == var_name:
                        continue

                references[var_name].append({
                    "file": rel_path, "line": num, "context": context
                })

    return references


def build_graph(repo_path):
    """Build complete dependency graph.

    Returns dict: var_name -> {definitions: [...], references: [...]}
    """
    definitions = find_definitions(repo_path)
    all_vars = set(definitions.keys())
    references = find_references(repo_path, all_vars)

    graph = {}
    for var_name in sorted(all_vars):
        # Deduplicate references (same file:line can appear for multiple tokens)
        seen_refs = set()
        unique_refs = []
        for ref in references.get(var_name, []):
            key = (ref["file"], ref["line"])
            if key not in seen_refs:
                seen_refs.add(key)
                unique_refs.append(ref)

        graph[var_name] = {
            "definitions": definitions[var_name],
            "references": unique_refs,
        }

    return graph


def format_table(graph, repo_path):
    """Format graph as human-readable table."""
    lines = []
    lines.append(f"Variable Dependency Graph: {os.path.basename(repo_path)}")
    lines.append("=" * 70)
    lines.append(f"Total variables tracked: {len(graph)}")

    orphans = {v: d for v, d in graph.items() if not d["references"]}
    if orphans:
        lines.append(f"Orphaned (no references): {len(orphans)}")
    lines.append("")

    for var_name, data in graph.items():
        defs = data["definitions"]
        refs = data["references"]
        def_types = ", ".join(f"{d['type']}" for d in defs)
        ref_files = set(r["file"] for r in refs)

        status = "ORPHAN" if not refs else f"{len(refs)} refs in {len(ref_files)} files"
        lines.append(f"  {var_name}  ({def_types})  [{status}]")

        # Definitions
        for d in defs:
            lines.append(f"    DEF  {d['file']}:{d['line']}  ({d['type']})")

        # References (grouped by file)
        if refs:
            by_file = defaultdict(list)
            for r in refs:
                by_file[r["file"]].append(r)
            for rfile in sorted(by_file.keys()):
                file_refs = by_file[rfile]
                line_nums = ", ".join(str(r["line"]) for r in file_refs[:10])
                extra = f" +{len(file_refs) - 10} more" if len(file_refs) > 10 else ""
                lines.append(f"    REF  {rfile}:{line_nums}{extra}")
        lines.append("")

    return "\n".join(lines)


def format_json(graph):
    """Format graph as JSON."""
    return json.dumps(graph, indent=2, sort_keys=True)


def format_dot(graph, repo_path):
    """Format graph as Graphviz DOT."""
    lines = [f'digraph "{os.path.basename(repo_path)}" {{']
    lines.append('  rankdir=LR;')
    lines.append('  node [shape=box, fontsize=10];')

    # Collect unique files
    files = set()
    for data in graph.values():
        for d in data["definitions"]:
            files.add(d["file"])
        for r in data["references"]:
            files.add(r["file"])

    # File nodes
    for f in sorted(files):
        safe = f.replace("/", "_").replace(".", "_").replace("-", "_")
        lines.append(f'  {safe} [label="{f}", shape=note];')

    # Variable nodes and edges
    for var_name, data in graph.items():
        safe_var = var_name.replace(".", "_")
        color = "red" if not data["references"] else "black"
        lines.append(f'  {safe_var} [label="{var_name}", color={color}];')

        for d in data["definitions"]:
            safe_file = d["file"].replace("/", "_").replace(".", "_").replace("-", "_")
            lines.append(f'  {safe_file} -> {safe_var} [label="def:{d["line"]}", style=dashed];')

        for r in data["references"]:
            safe_file = r["file"].replace("/", "_").replace(".", "_").replace("-", "_")
            lines.append(f'  {safe_var} -> {safe_file} [label="ref:{r["line"]}"];')

    lines.append("}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Build variable dependency graph for Ansible Lockdown roles")
    parser.add_argument("repo_path", help="Path to the repo root")
    parser.add_argument("--format", choices=["table", "json", "dot"],
                        default="table", help="Output format (default: table)")
    parser.add_argument("--var", help="Show graph for a single variable")
    parser.add_argument("--prefix", help="Only show variables matching prefix")
    parser.add_argument("--orphans", action="store_true",
                        help="Only show variables with no references")
    parser.add_argument("--file", dest="filter_file",
                        help="Only show variables defined in or referenced by PATH")

    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    print("Building dependency graph...", file=sys.stderr)
    graph = build_graph(args.repo_path)
    print(f"Found {len(graph)} variables", file=sys.stderr)

    # Apply filters
    if args.var:
        if args.var in graph:
            graph = {args.var: graph[args.var]}
        else:
            print(f"Variable '{args.var}' not found", file=sys.stderr)
            sys.exit(1)

    if args.prefix:
        graph = {v: d for v, d in graph.items() if v.startswith(args.prefix)}

    if args.orphans:
        graph = {v: d for v, d in graph.items() if not d["references"]}

    if args.filter_file:
        filtered = {}
        for v, d in graph.items():
            in_file = any(x["file"] == args.filter_file for x in d["definitions"])
            ref_file = any(x["file"] == args.filter_file for x in d["references"])
            if in_file or ref_file:
                filtered[v] = d
        graph = filtered

    # Output
    if args.format == "table":
        print(format_table(graph, args.repo_path))
    elif args.format == "json":
        print(format_json(graph))
    elif args.format == "dot":
        print(format_dot(graph, args.repo_path))

    # Summary stats to stderr
    total_defs = sum(len(d["definitions"]) for d in graph.values())
    total_refs = sum(len(d["references"]) for d in graph.values())
    orphan_count = sum(1 for d in graph.values() if not d["references"])
    print(f"\nSummary: {len(graph)} variables, {total_defs} definitions, "
          f"{total_refs} references, {orphan_count} orphans", file=sys.stderr)


if __name__ == "__main__":
    main()
