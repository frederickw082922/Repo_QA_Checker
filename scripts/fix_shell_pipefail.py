#!/usr/bin/env python3
"""Find and fix ansible.builtin.shell tasks missing 'set -o pipefail' or args: executable:.

Every ansible.builtin.shell task should have BOTH:
  1. set -o pipefail as the first line of the shell block
  2. args: executable: "{{ <exec_var> }}" (default variable: default_shell_executable)

Without the executable arg, Ansible falls back to /bin/sh (which on SUSE/Alpine may be
dash), causing set -o pipefail to either fail silently or not apply to piped commands.

The script handles three fix cases:

  Case A -- block format, missing pipefail, has args:
    Insert set -o pipefail as first content line, at the same indent as existing content.

  Case B -- inline format, missing pipefail (with or without args):
    Convert to block scalar, add set -o pipefail, add args block if also missing.

  Case C -- block format, has pipefail, missing args:
    Insert args: executable: block after the shell block content.

  Trailing '# noqa' comments on inline lines are preserved on the | indicator:
    ansible.builtin.shell: "cmd"  # noqa foo
  ->
    ansible.builtin.shell: |  # noqa foo
      set -o pipefail
      cmd

Usage:
    fix_shell_pipefail.py [--dry-run] [--exec-var NAME] [--no-ansible-check] <tasks_dir>

Options:
  --dry-run             Print what would change without writing files
  --exec-var NAME       Variable name for args: executable: (default: default_shell_executable)
  --no-ansible-check    Skip ansible-playbook --syntax-check (for CI without Ansible)

Warnings (not auto-fixed):
  WARN  file:line  set -o pipefail present but not first content line
    pipefail must be the first command for it to apply to all piped commands.

Exit codes:
  0  No changes needed (or dry-run with 0 findings)
  1  Changes applied (or dry-run with N findings)
  2  Error
"""

import argparse
import os
import re
import subprocess
import sys

SKIP_DIRS = {".git", "__pycache__", ".github", "collections", "molecule"}
DEFAULT_EXEC_VAR = "default_shell_executable"

# Block scalar indicator, optionally followed by a trailing YAML comment
BLOCK_RE = re.compile(
    r"^(\s+)ansible\.builtin\.shell:\s*(\|[-+]?|>[-+]?)?(\s+#.*)?\s*$"
)
# Inline with a value after the colon
INLINE_RE = re.compile(r"^(\s+)ansible\.builtin\.shell:\s+(.+)$")
# Bare block scalar indicators (with optional trailing comment)
BLOCK_INDICATOR_RE = re.compile(r"^[|>][-+]?(\s+#.*)?\s*$")


def find_yaml_files(tasks_dir):
    files = []
    for root, dirs, filenames in os.walk(tasks_dir):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for fname in sorted(filenames):
            if fname.endswith((".yml", ".yaml")):
                files.append(os.path.join(root, fname))
    return files


def leading_spaces(line):
    return len(line) - len(line.lstrip())


def parse_inline_value(value):
    """Split inline shell value into (command, trailing_comment).

    Handles:
        "cmd | pipe"                          -> ('cmd | pipe', '')
        "cmd"  # noqa foo                     -> ('cmd', '# noqa foo')
        'cmd | pipe'                          -> ('cmd | pipe', '')
        unquoted cmd | pipe                   -> ('unquoted cmd | pipe', '')
        "awk '$4==\"0\"' /etc/passwd"         -> ("awk '$4==\"0\"' /etc/passwd", '')

    Double-quoted YAML strings: backslash-escaped characters (\\", \\', \\\\)
    are skipped when scanning for the closing quote, then unescaped in the
    extracted command so the block scalar receives the literal characters.
    """
    value = value.strip()
    if not value:
        return "", ""
    if value[0] in ('"', "'"):
        quote = value[0]
        i = 1
        while i < len(value):
            if value[i] == "\\" and quote == '"' and i + 1 < len(value):
                i += 2  # skip YAML escape sequence
                continue
            if value[i] == quote:
                break
            i += 1
        cmd = value[1:i]
        rest = value[i + 1:].strip() if i < len(value) else ""
        comment = rest if rest.startswith("#") else ""
        if quote == '"':
            # Unescape YAML double-quoted escape sequences for block scalar output
            unescaped = []
            j = 0
            while j < len(cmd):
                if cmd[j] == "\\" and j + 1 < len(cmd):
                    nc = cmd[j + 1]
                    unescaped.append(
                        {"\\": "\\", '"': '"', "'": "'", "n": "\n", "t": "\t"}.get(
                            nc, "\\" + nc
                        )
                    )
                    j += 2
                else:
                    unescaped.append(cmd[j])
                    j += 1
            cmd = "".join(unescaped)
        return cmd, comment
    return value, ""


def task_has_args_executable(lines, shell_line_idx):
    """Return True if the task containing the shell line has args: executable:."""
    for j in range(shell_line_idx + 1, len(lines)):
        line = lines[j]
        if re.match(r"\s*- name:", line):
            break
        if "executable:" in line:
            return True
    return False


def find_block_end(lines, shell_line_idx, shell_indent):
    """Return index of first non-empty line at indent <= shell_indent after block content.

    This is where args: should be inserted (right before that line).
    Returns len(lines) if the block runs to end of file.
    """
    j = shell_line_idx + 1
    found_content = False
    while j < len(lines):
        l = lines[j].rstrip()
        if l == "":
            j += 1
            continue
        lind = leading_spaces(lines[j])
        if lind > shell_indent:
            found_content = True
            j += 1
        else:
            # Back at shell level or less
            if found_content:
                return j
            else:
                # No content found -- block is empty; insert here
                return j
    return j


def scan_file(filepath, exec_var=DEFAULT_EXEC_VAR):
    """Return (lines, fixes, warnings) for tasks needing pipefail and/or args: executable:.

    Each fix dict:
      type            : 'A', 'B', or 'C'
      line_idx        : index of the ansible.builtin.shell: line
      shell_indent    : leading spaces on that line
      trailing_comment: trailing YAML comment on the shell: line, e.g. '  # noqa foo' (may be '')
      needs_pipefail  : bool
      has_args        : bool
      -- When type == 'A' (needs_pipefail, block format):
        content_indent  : actual indent of first block content line
        insert_idx      : line index before which to insert pipefail
      -- When type == 'B' (needs_pipefail, inline format):
        inline_cmd      : bare command string
        noqa_comment    : trailing comment string, e.g. '# noqa foo'
        content_indent  : shell_indent + 2
      -- When has_args == False:
        args_idx        : line index where args: block should be inserted

    Each warning dict:
      type     : 'pipefail_misplaced'
      line_idx : index of the ansible.builtin.shell: line
    """
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    fixes = []
    warnings = []
    i = 0
    while i < len(lines):
        line = lines[i]

        # Case A / C: block format
        m = BLOCK_RE.match(line)
        if m:
            shell_indent = len(m.group(1))
            has_block_indicator = bool(m.group(2))
            trailing_comment = m.group(3) or ""
            # Scan forward for block content
            j = i + 1
            content_start = None
            content_indent = shell_indent + 2
            has_pipefail = False
            pipefail_misplaced = False
            while j < len(lines):
                cline = lines[j]
                if cline.rstrip() == "":
                    j += 1
                    continue
                cind = leading_spaces(cline)
                if cind <= shell_indent:
                    break
                if content_start is None:
                    content_start = j
                    content_indent = cind
                if cline.lstrip().startswith("set -o pipefail"):
                    has_pipefail = True
                    if content_start != j:
                        pipefail_misplaced = True
                    break
                j += 1

            has_args = task_has_args_executable(lines, i)

            if pipefail_misplaced:
                warnings.append({"type": "pipefail_misplaced", "line_idx": i})

            # Skip only when everything is already correct
            if has_block_indicator and has_pipefail and has_args:
                i += 1
                continue

            fix = {
                "type": "A",
                "line_idx": i,
                "shell_indent": shell_indent,
                "trailing_comment": trailing_comment,
                "needs_block_indicator": not has_block_indicator,
                "needs_pipefail": not has_pipefail,
                "has_args": has_args,
                "content_indent": content_indent,
                "insert_idx": content_start if content_start is not None else i + 1,
            }
            if not has_args:
                fix["args_idx"] = find_block_end(lines, i, shell_indent)
            if has_block_indicator and has_pipefail and not has_args:
                fix["type"] = "C"
            fixes.append(fix)
            i += 1
            continue

        # Case B: inline format
        m = INLINE_RE.match(line)
        if m:
            shell_indent = len(m.group(1))
            value = m.group(2).strip()
            # Skip if it's actually a block scalar indicator
            if BLOCK_INDICATOR_RE.match(value):
                i += 1
                continue
            cmd, noqa = parse_inline_value(value)
            # Skip if already has pipefail inline
            if "set -o pipefail" in cmd:
                i += 1
                continue

            has_args = task_has_args_executable(lines, i)

            fix = {
                "type": "B",
                "line_idx": i,
                "shell_indent": shell_indent,
                "trailing_comment": "",
                "needs_pipefail": True,
                "has_args": has_args,
                "inline_cmd": cmd,
                "noqa_comment": noqa,
                "content_indent": shell_indent + 2,
            }
            if not has_args:
                fix["args_idx"] = i + 1
            fixes.append(fix)
            i += 1
            continue

        i += 1

    return lines, fixes, warnings


def apply_fixes(lines, fixes, exec_var=DEFAULT_EXEC_VAR):
    """Apply all fixes in reverse order to preserve line indices."""
    for fix in sorted(fixes, key=lambda f: f["line_idx"], reverse=True):
        ind = fix["shell_indent"]
        prefix = " " * ind

        # --- Insert args: executable: block ---
        # Process this FIRST (higher index) before pipefail (lower index).
        if not fix["has_args"]:
            args_idx = fix["args_idx"]
            args_lines = [
                prefix + "args:\n",
                prefix + "  " + f'executable: "{{{{ {exec_var} }}}}"\n',
            ]
            for line in reversed(args_lines):
                lines.insert(args_idx, line)

        # --- Add missing | block scalar indicator (in-place, no index shift) ---
        if fix.get("needs_block_indicator"):
            prefix = " " * fix["shell_indent"]
            comment = fix.get("trailing_comment", "")
            lines[fix["line_idx"]] = prefix + "ansible.builtin.shell: |" + comment + "\n"

        # --- Insert / convert for pipefail ---
        if fix.get("needs_pipefail"):
            if fix["type"] == "A":
                insert_line = " " * fix["content_indent"] + "set -o pipefail\n"
                lines.insert(fix["insert_idx"], insert_line)

            elif fix["type"] == "B":
                cmd = fix["inline_cmd"]
                noqa = fix.get("noqa_comment", "")
                content_prefix = " " * (ind + 2)
                block_header = prefix + "ansible.builtin.shell: |"
                if noqa:
                    block_header += "  " + noqa
                block_header += "\n"
                replacement = [
                    block_header,
                    content_prefix + "set -o pipefail\n",
                    content_prefix + cmd + "\n",
                ]
                lines[fix["line_idx"]: fix["line_idx"] + 1] = replacement

    return lines


def yamllint_check(filepath):
    """Run yamllint in relaxed mode. Return (ok, output)."""
    result = subprocess.run(
        [sys.executable, "-m", "yamllint", "-d", "relaxed", filepath],
        capture_output=True,
        text=True,
    )
    errors = [l for l in result.stdout.splitlines() if "[error]" in l]
    return (len(errors) == 0), result.stdout


def ansible_syntax_check(filepath, exec_var=DEFAULT_EXEC_VAR):
    """Run ansible-playbook --syntax-check via a temp playbook. Return (ok, output).

    Validates Ansible task structure (module names, required keys, etc.).
    Does NOT validate shell command syntax inside ansible.builtin.shell tasks.
    Returns (True, '(skipped)') if ansible-playbook is not installed.
    """
    import tempfile

    abs_path = os.path.abspath(filepath)
    playbook = (
        "---\n"
        "- hosts: localhost\n"
        "  gather_facts: false\n"
        "  tasks:\n"
        f"    - ansible.builtin.import_tasks: {abs_path}\n"
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", prefix="pipefail_syntaxcheck_", delete=False
    ) as f:
        f.write(playbook)
        tmp_path = f.name
    try:
        result = subprocess.run(
            [
                "ansible-playbook",
                "--syntax-check",
                tmp_path,
                "-e", f"{exec_var}=/bin/bash",
            ],
            capture_output=True,
            text=True,
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output
    except FileNotFoundError:
        return True, "(ansible-playbook not found -- skipped)"
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Add 'set -o pipefail' and args: executable: to ansible.builtin.shell tasks."
    )
    parser.add_argument("tasks_dir", help="Path to tasks/ directory (recurses *.yml)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would change without writing files",
    )
    parser.add_argument(
        "--exec-var",
        default=DEFAULT_EXEC_VAR,
        metavar="NAME",
        help=f"Variable name for args: executable: (default: {DEFAULT_EXEC_VAR})",
    )
    parser.add_argument(
        "--no-ansible-check",
        action="store_true",
        help="Skip ansible-playbook --syntax-check (useful in CI without Ansible installed)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.tasks_dir):
        print(f"ERROR: {args.tasks_dir} is not a directory", file=sys.stderr)
        sys.exit(2)

    yaml_files = find_yaml_files(args.tasks_dir)
    if not yaml_files:
        print("No YAML files found.", file=sys.stderr)
        sys.exit(2)

    total_pipefail = 0
    total_args = 0
    error_files = []

    for filepath in yaml_files:
        rel = os.path.relpath(filepath, args.tasks_dir)
        try:
            lines, fixes, warnings = scan_file(filepath, exec_var=args.exec_var)
        except Exception as e:
            print(f"ERROR reading {rel}: {e}", file=sys.stderr)
            error_files.append(rel)
            continue

        for w in warnings:
            print(
                f"  WARN  {rel}:{w['line_idx'] + 1}  "
                "set -o pipefail present but not first content line (manual fix needed)"
            )

        if not fixes:
            continue

        file_indicator = sum(1 for f in fixes if f.get("needs_block_indicator"))
        file_pipefail = sum(1 for f in fixes if f.get("needs_pipefail"))
        file_args = sum(1 for f in fixes if not f["has_args"])
        total_pipefail += file_pipefail + file_indicator
        total_args += file_args

        if args.dry_run:
            for fix in fixes:
                parts = []
                if fix.get("needs_block_indicator"):
                    parts.append("add | indicator")
                if fix.get("needs_pipefail"):
                    if fix["type"] == "A":
                        parts.append("insert pipefail")
                    else:
                        parts.append(f"convert inline ({fix['inline_cmd'][:50]!r})")
                if not fix["has_args"]:
                    parts.append("add args:executable:")
                print(f"  {rel}:{fix['line_idx'] + 1}  {' + '.join(parts)}")
            continue

        new_lines = apply_fixes(list(lines), fixes, exec_var=args.exec_var)
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        ok, lint_out = yamllint_check(filepath)
        if not ok:
            print(
                f"ERROR: yamllint errors after fixing {rel}:\n{lint_out}",
                file=sys.stderr,
            )
            with open(filepath, "w", encoding="utf-8") as f:
                f.writelines(lines)
            error_files.append(rel)
            continue

        if not args.no_ansible_check:
            ok, ansible_out = ansible_syntax_check(filepath, exec_var=args.exec_var)
            if not ok:
                print(
                    f"ERROR: ansible syntax errors after fixing {rel}:\n{ansible_out}",
                    file=sys.stderr,
                )
                with open(filepath, "w", encoding="utf-8") as f:
                    f.writelines(lines)
                error_files.append(rel)
                continue

        parts = []
        if file_indicator:
            parts.append(f"{file_indicator} | indicator")
        if file_pipefail:
            parts.append(f"{file_pipefail} pipefail")
        if file_args:
            parts.append(f"{file_args} args:executable:")
        print(f"  Fixed {', '.join(parts)} in {rel}")

    if args.dry_run:
        if total_pipefail or total_args:
            print(
                f"\n{total_pipefail} task(s) need pipefail, "
                f"{total_args} task(s) need args:executable:."
            )
        else:
            print("No tasks need fixing -- all shell tasks already aligned.")
    else:
        if (total_pipefail or total_args) and not error_files:
            checks = "yamllint" + ("" if args.no_ansible_check else "+ansible")
            print(
                f"\nApplied fixes: {total_pipefail} pipefail, "
                f"{total_args} args:executable:. {checks}: PASS."
            )
        elif error_files:
            print(
                f"\nApplied fixes with {len(error_files)} error(s). See above.",
                file=sys.stderr,
            )

    if error_files:
        sys.exit(2)
    sys.exit(1 if (total_pipefail or total_args) else 0)


if __name__ == "__main__":
    main()
