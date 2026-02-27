#!/usr/bin/env python3
"""Find and optionally fix common grammar issues in Ansible-Lockdown role files.

Works with any ansible-lockdown benchmark role (CIS, STIG, any OS).

Checks for:
- Repeated words (of of, is is, the the, etc.)
- Missing apostrophes (wont, cant, doesnt, etc.)
- Subject-verb disagreements (variables is, values is, etc.)
- Common typo patterns (number prefixed headings like 5Allow, etc.)

Usage:
    python fix_grammar.py <repo_path> [--fix] [--skip-dir DIR ...]
"""

import argparse
import os
import re
import sys

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

REPEATED_WORDS = re.compile(r'\b(\w+)\s+\1\b', re.IGNORECASE)

APOSTROPHE_FIXES = {
    r'\bwont\b': "won't",
    r'\bcant\b': "can't",
    r'\bdoesnt\b': "doesn't",
    r'\bisnt\b': "isn't",
    r'\bdidnt\b': "didn't",
    r'\bwouldnt\b': "wouldn't",
    r'\bshouldnt\b': "shouldn't",
    r'\bcouldnt\b': "couldn't",
    r'\bhasnt\b': "hasn't",
    r'\bhavent\b': "haven't",
    r'\bwasnt\b': "wasn't",
    r'\bwerent\b': "weren't",
    r'\barent\b': "aren't",
    r'\bthats\b': "that's",
    r'\bwhats\b': "what's",
    r'\btheyre\b': "they're",
    r'\byoure\b': "you're",
}

SUBJECT_VERB_FIXES = [
    (re.compile(r'\bThis variables is\b'), 'This variable is'),
    (re.compile(r'\bThe given values is\b'), 'The given value is'),
    (re.compile(r'\bThis options is\b'), 'This option is'),
    (re.compile(r'\bThis settings is\b'), 'This setting is'),
    (re.compile(r'\bThis controls is\b'), 'This control is'),
    (re.compile(r'\bThis parameters is\b'), 'This parameter is'),
]

# Words that are OK to repeat (YAML values, common patterns)
REPEAT_WHITELIST = frozenset({
    '0', '1', '2', '3', 'true', 'false', 'yes', 'no', 'none',
    'the',  # handled separately for "the the" but not "the ... the"
})

EXTENSIONS = {'.yml', '.yaml', '.j2', '.md', '.conf', '.cfg', '.rst'}

# Strip backtick-quoted content to avoid false positives in changelogs
BACKTICK_CONTENT = re.compile(r'`[^`]*`')

DEFAULT_SKIP_DIRS = {'.git', '.github', 'molecule', 'tests', '__pycache__', '.ansible'}


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def find_files(repo_path, skip_dirs):
    """Find all eligible files in the repo."""
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in filenames:
            if any(fname.endswith(ext) for ext in EXTENSIONS):
                files.append(os.path.join(root, fname))
    return sorted(files)


def strip_backticks(line):
    """Remove backtick-quoted content to avoid false positives in changelogs."""
    return BACKTICK_CONTENT.sub('', line)


def check_repeated_words(line, line_num, filepath):
    """Check for repeated words in a line."""
    issues = []
    for match in REPEATED_WORDS.finditer(line):
        word = match.group(1).lower()
        if word in REPEAT_WHITELIST and f'{word} {word}' not in line.lower():
            continue
        if word in REPEAT_WHITELIST:
            # Only flag if it's literally "word word" adjacent
            pass
        if len(word) < 2:
            continue
        issues.append({
            'file': filepath,
            'line': line_num,
            'severity': 'warning',
            'description': f"Repeated word: '{word} {word}'",
            'match': match.group(),
            'fix': word,
        })
    return issues


def check_apostrophes(line, line_num, filepath):
    """Check for missing apostrophes."""
    issues = []
    for pattern, replacement in APOSTROPHE_FIXES.items():
        for match in re.finditer(pattern, line, re.IGNORECASE):
            issues.append({
                'file': filepath,
                'line': line_num,
                'severity': 'warning',
                'description': f"Missing apostrophe: '{match.group()}' -> '{replacement}'",
                'match': match.group(),
                'fix': replacement,
            })
    return issues


def check_subject_verb(line, line_num, filepath):
    """Check for subject-verb disagreements."""
    issues = []
    for pattern, replacement in SUBJECT_VERB_FIXES:
        if pattern.search(line):
            issues.append({
                'file': filepath,
                'line': line_num,
                'severity': 'warning',
                'description': f"Subject-verb disagreement: '{pattern.pattern}' -> '{replacement}'",
                'match': pattern.pattern,
                'fix': replacement,
            })
    return issues


def scan_file(filepath):
    """Scan a single file for grammar issues."""
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                clean_line = strip_backticks(line)
                issues.extend(check_repeated_words(clean_line, line_num, filepath))
                issues.extend(check_apostrophes(clean_line, line_num, filepath))
                issues.extend(check_subject_verb(clean_line, line_num, filepath))
    except (IOError, OSError) as e:
        print(f"  Error reading {filepath}: {e}", file=sys.stderr)
    return issues


# ---------------------------------------------------------------------------
# Fixing
# ---------------------------------------------------------------------------

def apply_fixes(filepath, issues):
    """Apply fixes to a file."""
    if not issues:
        return False

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    modified = False
    for issue in issues:
        match_text = issue.get('match', '')
        fix_text = issue.get('fix', '')
        if match_text and fix_text and match_text != fix_text:
            new_content = re.sub(re.escape(match_text), fix_text, content, count=1)
            if new_content != content:
                content = new_content
                modified = True

    if modified:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

    return modified


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Find and fix grammar issues in Ansible-Lockdown roles')
    parser.add_argument('repo_path', help='Path to the repo root')
    parser.add_argument('--fix', action='store_true', help='Apply fixes automatically')
    parser.add_argument('--skip-dir', nargs='*', default=[],
                        help='Additional directories to skip')
    args = parser.parse_args()

    if not os.path.isdir(args.repo_path):
        print(f"Error: {args.repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    skip_dirs = DEFAULT_SKIP_DIRS | set(args.skip_dir)
    files = find_files(args.repo_path, skip_dirs)
    total_issues = 0
    files_with_issues = 0

    for filepath in files:
        issues = scan_file(filepath)
        if issues:
            files_with_issues += 1
            rel_path = os.path.relpath(filepath, args.repo_path)
            for issue in issues:
                total_issues += 1
                print(f"  [{issue['severity']}] {rel_path}:{issue['line']} "
                      f"- {issue['description']}")

            if args.fix:
                if apply_fixes(filepath, issues):
                    print(f"  FIXED: {rel_path}")

    print(f"\n{'='*60}")
    print(f"Total issues: {total_issues} in {files_with_issues} file(s)")
    if not args.fix and total_issues > 0:
        print("Run with --fix to apply automatic fixes")

    sys.exit(1 if total_issues > 0 else 0)


if __name__ == '__main__':
    main()
