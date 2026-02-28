#!/usr/bin/env python3
"""
Goss Audit Comparison Tool

Compares pre and post remediation Goss audit results to show:
- Controls that were fixed (failed -> passed)
- Controls that regressed (passed -> failed)
- Controls that remain failed
- Overall compliance improvement

Usage:
    ./audit_compare.py <pre_audit.json> <post_audit.json>
    ./audit_compare.py <pre_audit.json> <post_audit.json> --output report.html
    ./audit_compare.py <pre_audit.json> <post_audit.json> --format markdown
"""

import argparse
import html as html_mod
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def detect_benchmark_name(pre_file, post_file):
    """Detect benchmark name from audit filenames.

    Looks for patterns like 'rhel10cis', 'ubuntu2204stig', 'amazon2023stig'
    in the filenames. Falls back to 'Goss Audit' if no match.
    """
    # Common benchmark prefixes in Ansible-Lockdown audit filenames
    pattern = re.compile(
        r'((?:rhel|ubuntu|amazon|debian|suse)\d+(?:cis|stig))',
        re.IGNORECASE
    )
    for filepath in (pre_file, post_file):
        basename = Path(filepath).name
        match = pattern.search(basename)
        if match:
            raw = match.group(1)
            # Format nicely: "RHEL10 CIS", "Ubuntu2204 STIG", etc.
            inner = re.match(r'([a-zA-Z]+)(\d+)(cis|stig)', raw, re.IGNORECASE)
            if inner:
                os_name = inner.group(1).upper()
                version = inner.group(2)
                bench_type = inner.group(3).upper()
                return f"{os_name}{version} {bench_type}"
            return raw.upper()
    return "Goss Audit"


def detect_benchmark_version(pre_file, post_file):
    """Detect benchmark version from audit filenames.

    Looks for version patterns like 'v1_0_0', 'v1.2.0', 'v1r2' in filenames.
    Falls back to 'unknown' if no match.
    """
    # Match common version patterns: v1_0_0, v1.2.0, v1r2
    pattern = re.compile(r'(v\d+[\._]\d+[\._]\d+|v\d+r\d+)', re.IGNORECASE)
    for filepath in (pre_file, post_file):
        basename = Path(filepath).name
        match = pattern.search(basename)
        if match:
            return match.group(1)
    return 'unknown'


def load_audit_file(filepath):
    """Load and parse a Goss audit JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {filepath}: {e}", file=sys.stderr)
        sys.exit(2)


def extract_results(audit_data):
    """Extract test results from Goss audit data."""
    results = {}

    if 'results' not in audit_data:
        print("Warning: No 'results' key found in audit data", file=sys.stderr)
        return results

    for result in audit_data['results']:
        # Build a unique key for each test
        resource_type = result.get('resource-type', 'unknown')
        resource_id = result.get('resource-id', 'unknown')
        property_name = result.get('property', 'unknown')
        title = result.get('title', '')

        # Extract control ID from title if present
        # Supports CIS (e.g., "1.1.1.1") and STIG (e.g., "RHEL-09-123456") formats
        control_id = ''
        if title:
            # STIG format: XXXX-XX-XXXXXX (e.g., RHEL-09-123456, UBTU-22-654321)
            stig_match = re.match(r'([A-Z]+-\d+-\d+)', title)
            # CIS format: digits separated by dots (e.g., 1.1.1.1, 5.2.3)
            cis_match = re.match(r'(\d+(?:\.\d+)+)', title)
            if stig_match:
                control_id = stig_match.group(1)
            elif cis_match:
                control_id = cis_match.group(1)
            else:
                # Fallback: first token before pipe delimiter
                parts = title.split('|')
                if parts:
                    control_id = parts[0].strip()

        key = f"{resource_type}::{resource_id}::{property_name}"

        results[key] = {
            'title': title,
            'control_id': control_id,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'property': property_name,
            'successful': result.get('successful', False),
            'skipped': result.get('skipped', False),
            'summary_line': result.get('summary-line', ''),
            'expected': result.get('expected', []),
            'found': result.get('found', []),
        }

    return results


def extract_summary(audit_data):
    """Extract summary statistics from audit data."""
    summary = audit_data.get('summary', {})
    return {
        'total': summary.get('test-count', 0),
        'failed': summary.get('failed-count', 0),
        'skipped': summary.get('skipped-count', 0),
        'passed': summary.get('test-count', 0) - summary.get('failed-count', 0) - summary.get('skipped-count', 0),
        'duration': summary.get('total-duration', 0),
    }


def compare_audits(pre_results, post_results):
    """Compare pre and post audit results."""
    comparison = {
        'fixed': [],      # Failed -> Passed
        'regressed': [],  # Passed -> Failed
        'still_failed': [],  # Failed -> Failed
        'still_passed': [],  # Passed -> Passed
        'new_tests': [],     # Not in pre, in post
        'removed_tests': [], # In pre, not in post
        'skipped': [],       # Skipped in either
    }

    all_keys = set(pre_results.keys()) | set(post_results.keys())

    for key in all_keys:
        pre = pre_results.get(key)
        post = post_results.get(key)

        if pre is None:
            comparison['new_tests'].append({
                'key': key,
                'post': post
            })
            continue

        if post is None:
            comparison['removed_tests'].append({
                'key': key,
                'pre': pre
            })
            continue

        # Skip if either is skipped
        if pre.get('skipped') or post.get('skipped'):
            comparison['skipped'].append({
                'key': key,
                'pre': pre,
                'post': post
            })
            continue

        pre_passed = pre.get('successful', False)
        post_passed = post.get('successful', False)

        if not pre_passed and post_passed:
            comparison['fixed'].append({
                'key': key,
                'pre': pre,
                'post': post
            })
        elif pre_passed and not post_passed:
            comparison['regressed'].append({
                'key': key,
                'pre': pre,
                'post': post
            })
        elif not pre_passed and not post_passed:
            comparison['still_failed'].append({
                'key': key,
                'pre': pre,
                'post': post
            })
        else:
            comparison['still_passed'].append({
                'key': key,
                'pre': pre,
                'post': post
            })

    return comparison


def group_by_control(items):
    """Group comparison items by CIS control ID."""
    grouped = defaultdict(list)
    for item in items:
        # Get control_id from pre or post
        control_id = ''
        if 'pre' in item and item['pre']:
            control_id = item['pre'].get('control_id', '')
        elif 'post' in item and item['post']:
            control_id = item['post'].get('control_id', '')

        if not control_id:
            control_id = 'Unknown'

        grouped[control_id].append(item)

    return dict(sorted(grouped.items()))


def format_duration(nanoseconds):
    """Format Goss duration (nanoseconds) to a human-readable string."""
    if nanoseconds <= 0:
        return "N/A"
    seconds = nanoseconds / 1_000_000_000
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    remaining = seconds % 60
    return f"{minutes}m {remaining:.1f}s"


def format_text_report(comparison, pre_summary, post_summary, pre_file, post_file, benchmark="Goss Audit"):
    """Generate a text format report."""
    lines = []
    lines.append("=" * 80)
    lines.append(f"{benchmark.upper()} AUDIT COMPARISON REPORT")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Pre-audit file:  {pre_file}")
    lines.append(f"Post-audit file: {post_file}")
    lines.append("")

    # Summary section
    lines.append("-" * 80)
    lines.append("SUMMARY")
    lines.append("-" * 80)
    lines.append("")
    lines.append(f"{'Metric':<30} {'Pre-Audit':>15} {'Post-Audit':>15} {'Change':>15}")
    lines.append("-" * 75)
    lines.append(f"{'Total Tests':<30} {pre_summary['total']:>15} {post_summary['total']:>15} {post_summary['total'] - pre_summary['total']:>+15}")
    lines.append(f"{'Passed':<30} {pre_summary['passed']:>15} {post_summary['passed']:>15} {post_summary['passed'] - pre_summary['passed']:>+15}")
    lines.append(f"{'Failed':<30} {pre_summary['failed']:>15} {post_summary['failed']:>15} {post_summary['failed'] - pre_summary['failed']:>+15}")
    lines.append(f"{'Skipped':<30} {pre_summary['skipped']:>15} {post_summary['skipped']:>15} {post_summary['skipped'] - pre_summary['skipped']:>+15}")

    pre_dur = format_duration(pre_summary['duration'])
    post_dur = format_duration(post_summary['duration'])
    lines.append(f"{'Scan Duration':<30} {pre_dur:>15} {post_dur:>15}")
    lines.append("")

    # Compliance percentage
    pre_compliance = (pre_summary['passed'] / pre_summary['total'] * 100) if pre_summary['total'] > 0 else 0
    post_compliance = (post_summary['passed'] / post_summary['total'] * 100) if post_summary['total'] > 0 else 0
    lines.append(f"{'Compliance Rate':<30} {pre_compliance:>14.1f}% {post_compliance:>14.1f}% {post_compliance - pre_compliance:>+14.1f}%")
    lines.append("")

    # Changes summary
    lines.append("-" * 80)
    lines.append("CHANGES BREAKDOWN")
    lines.append("-" * 80)
    lines.append("")
    lines.append(f"  Fixed (Failed -> Passed):     {len(comparison['fixed']):>5}")
    lines.append(f"  Regressed (Passed -> Failed): {len(comparison['regressed']):>5}")
    lines.append(f"  Still Failed:                 {len(comparison['still_failed']):>5}")
    lines.append(f"  Still Passed:                 {len(comparison['still_passed']):>5}")
    lines.append(f"  Skipped:                      {len(comparison['skipped']):>5}")
    lines.append(f"  New Tests:                    {len(comparison['new_tests']):>5}")
    lines.append(f"  Removed Tests:                {len(comparison['removed_tests']):>5}")
    lines.append("")

    # Fixed controls
    if comparison['fixed']:
        lines.append("-" * 80)
        lines.append("FIXED CONTROLS (Failed -> Passed)")
        lines.append("-" * 80)
        grouped = group_by_control(comparison['fixed'])
        for control_id, items in grouped.items():
            lines.append(f"\n  [{control_id}] - {len(items)} test(s) fixed")
            for item in items[:3]:  # Show first 3
                title = item['pre'].get('title', item['key'])[:60]
                lines.append(f"    - {title}")
            if len(items) > 3:
                lines.append(f"    ... and {len(items) - 3} more")
        lines.append("")

    # Regressed controls
    if comparison['regressed']:
        lines.append("-" * 80)
        lines.append("REGRESSED CONTROLS (Passed -> Failed) - ATTENTION REQUIRED")
        lines.append("-" * 80)
        grouped = group_by_control(comparison['regressed'])
        for control_id, items in grouped.items():
            lines.append(f"\n  [{control_id}] - {len(items)} test(s) regressed")
            for item in items:
                title = item['pre'].get('title', item['key'])[:60]
                lines.append(f"    - {title}")
                if item['post'].get('found'):
                    lines.append(f"      Found: {item['post']['found']}")
        lines.append("")

    # Still failed controls (grouped by control ID)
    if comparison['still_failed']:
        lines.append("-" * 80)
        lines.append("STILL FAILED CONTROLS (Require Manual Remediation)")
        lines.append("-" * 80)
        grouped = group_by_control(comparison['still_failed'])
        for control_id, items in grouped.items():
            lines.append(f"\n  [{control_id}] - {len(items)} test(s) still failing")
            for item in items[:5]:  # Show first 5
                title = item['pre'].get('title', item['key'])[:60]
                lines.append(f"    - {title}")
                if item['post'].get('expected'):
                    lines.append(f"      Expected: {item['post']['expected']}")
                if item['post'].get('found'):
                    lines.append(f"      Found:    {item['post']['found']}")
            if len(items) > 5:
                lines.append(f"    ... and {len(items) - 5} more")
        lines.append("")

    lines.append("=" * 80)
    lines.append("END OF REPORT")
    lines.append("=" * 80)

    return "\n".join(lines)


def format_markdown_report(comparison, pre_summary, post_summary, pre_file, post_file, benchmark="Goss Audit"):
    """Generate a Markdown format report."""
    lines = []
    lines.append(f"# {benchmark} Audit Comparison Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("## Files Compared")
    lines.append("")
    lines.append(f"- **Pre-audit:** `{pre_file}`")
    lines.append(f"- **Post-audit:** `{post_file}`")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Pre-Audit | Post-Audit | Change |")
    lines.append("| ------ | --------: | ---------: | -----: |")
    lines.append(f"| Total Tests | {pre_summary['total']} | {post_summary['total']} | {post_summary['total'] - pre_summary['total']:+d} |")
    lines.append(f"| Passed | {pre_summary['passed']} | {post_summary['passed']} | {post_summary['passed'] - pre_summary['passed']:+d} |")
    lines.append(f"| Failed | {pre_summary['failed']} | {post_summary['failed']} | {post_summary['failed'] - pre_summary['failed']:+d} |")
    lines.append(f"| Skipped | {pre_summary['skipped']} | {post_summary['skipped']} | {post_summary['skipped'] - pre_summary['skipped']:+d} |")
    lines.append(f"| Scan Duration | {format_duration(pre_summary['duration'])} | {format_duration(post_summary['duration'])} | |")
    lines.append("")

    # Compliance percentage
    pre_compliance = (pre_summary['passed'] / pre_summary['total'] * 100) if pre_summary['total'] > 0 else 0
    post_compliance = (post_summary['passed'] / post_summary['total'] * 100) if post_summary['total'] > 0 else 0
    lines.append(f"**Compliance Rate:** {pre_compliance:.1f}% -> {post_compliance:.1f}% ({post_compliance - pre_compliance:+.1f}%)")
    lines.append("")

    # Changes breakdown
    lines.append("## Changes Breakdown")
    lines.append("")
    lines.append(f"- **Fixed** (Failed -> Passed): {len(comparison['fixed'])}")
    lines.append(f"- **Regressed** (Passed -> Failed): {len(comparison['regressed'])}")
    lines.append(f"- **Still Failed**: {len(comparison['still_failed'])}")
    lines.append(f"- **Still Passed**: {len(comparison['still_passed'])}")
    lines.append(f"- **Skipped**: {len(comparison['skipped'])}")
    lines.append("")

    # Fixed controls
    if comparison['fixed']:
        lines.append("## Fixed Controls")
        lines.append("")
        grouped = group_by_control(comparison['fixed'])
        for control_id, items in grouped.items():
            lines.append(f"### {control_id}")
            lines.append("")
            for item in items:
                title = item['pre'].get('title', item['key'])
                lines.append(f"- {title}")
            lines.append("")

    # Regressed controls
    if comparison['regressed']:
        lines.append("## Regressed Controls")
        lines.append("")
        lines.append("> **Warning:** These controls passed before but now fail!")
        lines.append("")
        grouped = group_by_control(comparison['regressed'])
        for control_id, items in grouped.items():
            lines.append(f"### {control_id}")
            lines.append("")
            for item in items:
                title = item['pre'].get('title', item['key'])
                lines.append(f"- {title}")
                if item['post'].get('found'):
                    lines.append(f"  - Found: `{item['post']['found']}`")
            lines.append("")

    # Still failed
    if comparison['still_failed']:
        lines.append("## Still Failed Controls")
        lines.append("")
        lines.append("These controls require manual remediation or configuration changes.")
        lines.append("")
        grouped = group_by_control(comparison['still_failed'])
        for control_id, items in grouped.items():
            lines.append(f"### {control_id} ({len(items)} tests)")
            lines.append("")
            for item in items[:10]:
                title = item['pre'].get('title', item['key'])
                lines.append(f"- {title}")
                if item['post'].get('expected'):
                    lines.append(f"  - Expected: `{item['post']['expected']}`")
                if item['post'].get('found'):
                    lines.append(f"  - Found: `{item['post']['found']}`")
            if len(items) > 10:
                lines.append(f"- *... and {len(items) - 10} more*")
            lines.append("")

    return "\n".join(lines)


def format_json_report(comparison, pre_summary, post_summary, pre_file, post_file, benchmark="Goss Audit"):
    """Generate a JSON format report."""
    report = {
        'metadata': {
            'generated': datetime.now().isoformat(),
            'benchmark': benchmark,
            'pre_audit_file': str(pre_file),
            'post_audit_file': str(post_file),
        },
        'summary': {
            'pre_audit': pre_summary,
            'post_audit': post_summary,
            'compliance_change': {
                'pre': (pre_summary['passed'] / pre_summary['total'] * 100) if pre_summary['total'] > 0 else 0,
                'post': (post_summary['passed'] / post_summary['total'] * 100) if post_summary['total'] > 0 else 0,
            },
            'duration': {
                'pre_nanoseconds': pre_summary['duration'],
                'post_nanoseconds': post_summary['duration'],
                'pre_formatted': format_duration(pre_summary['duration']),
                'post_formatted': format_duration(post_summary['duration']),
            }
        },
        'changes': {
            'fixed_count': len(comparison['fixed']),
            'regressed_count': len(comparison['regressed']),
            'still_failed_count': len(comparison['still_failed']),
            'still_passed_count': len(comparison['still_passed']),
            'skipped_count': len(comparison['skipped']),
        },
        'fixed': [{'control_id': i.get('pre', {}).get('control_id', ''), 'title': i.get('pre', {}).get('title', '')} for i in comparison['fixed']],
        'regressed': [{'control_id': i.get('pre', {}).get('control_id', ''), 'title': i.get('pre', {}).get('title', '')} for i in comparison['regressed']],
        'still_failed_by_control': {
            control_id: [
                {
                    'title': item.get('pre', {}).get('title', ''),
                    'summary_line': item.get('post', {}).get('summary_line', ''),
                    'expected': item.get('post', {}).get('expected', []),
                    'found': item.get('post', {}).get('found', []),
                }
                for item in items
            ]
            for control_id, items in group_by_control(comparison['still_failed']).items()
        },
    }
    return json.dumps(report, indent=2)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
         sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px;
         background: #f5f5f5; color: #1a1a2e; }}
  h1 {{ border-bottom: 3px solid #16213e; padding-bottom: 10px; }}
  h2 {{ margin-top: 0; }}
  h3 {{ margin: 10px 0 5px; }}
  .metadata {{ background: #fff; padding: 15px; border-radius: 8px;
               box-shadow: 0 2px 4px rgba(0,0,0,.1); margin-bottom: 20px; }}
  .metadata span {{ margin-right: 20px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 15px 0;
           background: #fff; border-radius: 8px; overflow: hidden;
           box-shadow: 0 2px 4px rgba(0,0,0,.1); }}
  th {{ background: #16213e; color: #fff; padding: 12px 15px;
       text-align: left; }}
  th.num {{ text-align: right; }}
  td {{ padding: 10px 15px; border-bottom: 1px solid #eee; }}
  td.num {{ text-align: right; }}
  tr:hover {{ background: #f8f9fa; }}
  .section {{ background: #fff; padding: 20px; border-radius: 8px;
              box-shadow: 0 2px 4px rgba(0,0,0,.1); margin-bottom: 20px; }}
  .section-header {{ display: flex; justify-content: space-between;
                     align-items: center; }}
  .badge {{ padding: 4px 12px; border-radius: 12px; font-size: .85em;
            font-weight: bold; display: inline-block; }}
  .badge-fixed {{ background: #d4edda; color: #155724; }}
  .badge-regressed {{ background: #f8d7da; color: #721c24; }}
  .badge-still-failed {{ background: #fff3cd; color: #856404; }}
  .badge-still-passed {{ background: #d4edda; color: #155724; }}
  .badge-skipped {{ background: #e2e3e5; color: #383d41; }}
  .badge-new {{ background: #d1ecf1; color: #0c5460; }}
  .badge-removed {{ background: #e2e3e5; color: #383d41; }}
  .positive {{ color: #155724; }}
  .negative {{ color: #721c24; }}
  .neutral {{ color: #383d41; }}
  code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px;
          font-size: .9em; }}
  details {{ margin: 5px 0; }}
  summary {{ cursor: pointer; padding: 5px 0; font-weight: bold; }}
  .control-group {{ margin-bottom: 15px; padding-left: 10px;
                    border-left: 3px solid #16213e; }}
  .expected-found {{ font-size: .9em; color: #555; margin-left: 20px; }}
  .warning-banner {{ background: #f8d7da; color: #721c24; padding: 12px 15px;
                     border-radius: 8px; margin-bottom: 15px;
                     font-weight: bold; }}
  .summary-table td:first-child {{ font-weight: bold; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="metadata">
  <span><strong>Generated:</strong> {generated}</span>
  <span><strong>Pre-audit:</strong> <code>{pre_file}</code></span>
  <span><strong>Post-audit:</strong> <code>{post_file}</code></span>
</div>
{content}
</body>
</html>
"""


FORMAT_EXTENSIONS = {
    'text': '.txt',
    'markdown': '.md',
    'json': '.json',
    'html': '.html',
}


def generate_default_filename(benchmark, version, fmt):
    """Generate default report filename.

    Pattern: audit_compare_report_{benchmark}_{version}_{datetime}.{ext}
    Example: audit_compare_report_RHEL10_CIS_v1_0_0_2026-02-28_143012.md
    """
    # Sanitize benchmark for filename: replace spaces/special chars with underscores
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', benchmark)
    safe_version = re.sub(r'[^a-zA-Z0-9_.-]', '_', version) if version else 'unknown'
    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    ext = FORMAT_EXTENSIONS.get(fmt, '.txt')
    return f"audit_compare_report_{safe_name}_{safe_version}_{timestamp}{ext}"


def _esc(text):
    """HTML-escape dynamic content."""
    return html_mod.escape(str(text))


def _change_class(value):
    """Return CSS class for a change value."""
    if value > 0:
        return "positive"
    elif value < 0:
        return "negative"
    return "neutral"


def format_html_report(comparison, pre_summary, post_summary, pre_file, post_file, benchmark="Goss Audit"):
    """Generate an HTML format report."""
    sections = []

    # --- Summary table ---
    pre_compliance = (pre_summary['passed'] / pre_summary['total'] * 100) if pre_summary['total'] > 0 else 0
    post_compliance = (post_summary['passed'] / post_summary['total'] * 100) if post_summary['total'] > 0 else 0
    compliance_change = post_compliance - pre_compliance

    def _summary_row(label, pre_val, post_val, change=None, is_pct=False):
        if is_pct:
            pre_str = f"{pre_val:.1f}%"
            post_str = f"{post_val:.1f}%"
            chg_str = f"{change:+.1f}%" if change is not None else ""
        else:
            pre_str = str(pre_val)
            post_str = str(post_val)
            chg_str = f"{change:+d}" if change is not None else ""
        chg_cls = _change_class(change) if change is not None else "neutral"
        return (f"<tr><td>{_esc(label)}</td>"
                f"<td class='num'>{pre_str}</td>"
                f"<td class='num'>{post_str}</td>"
                f"<td class='num {chg_cls}'>{chg_str}</td></tr>\n")

    summary_rows = ""
    summary_rows += _summary_row("Total Tests", pre_summary['total'], post_summary['total'],
                                 post_summary['total'] - pre_summary['total'])
    summary_rows += _summary_row("Passed", pre_summary['passed'], post_summary['passed'],
                                 post_summary['passed'] - pre_summary['passed'])
    summary_rows += _summary_row("Failed", pre_summary['failed'], post_summary['failed'],
                                 post_summary['failed'] - pre_summary['failed'])
    summary_rows += _summary_row("Skipped", pre_summary['skipped'], post_summary['skipped'],
                                 post_summary['skipped'] - pre_summary['skipped'])
    summary_rows += (f"<tr><td>Scan Duration</td>"
                     f"<td class='num'>{_esc(format_duration(pre_summary['duration']))}</td>"
                     f"<td class='num'>{_esc(format_duration(post_summary['duration']))}</td>"
                     f"<td class='num'></td></tr>\n")
    summary_rows += _summary_row("Compliance Rate", pre_compliance, post_compliance,
                                 compliance_change, is_pct=True)

    sections.append(
        f"<div class='section'>\n<h2>Summary</h2>\n"
        f"<table class='summary-table'>\n"
        f"<tr><th>Metric</th><th class='num'>Pre-Audit</th>"
        f"<th class='num'>Post-Audit</th><th class='num'>Change</th></tr>\n"
        f"{summary_rows}</table>\n</div>\n")

    # --- Changes breakdown ---
    breakdown_items = [
        ("Fixed (Failed &rarr; Passed)", len(comparison['fixed']), "badge-fixed"),
        ("Regressed (Passed &rarr; Failed)", len(comparison['regressed']), "badge-regressed"),
        ("Still Failed", len(comparison['still_failed']), "badge-still-failed"),
        ("Still Passed", len(comparison['still_passed']), "badge-still-passed"),
        ("Skipped", len(comparison['skipped']), "badge-skipped"),
        ("New Tests", len(comparison['new_tests']), "badge-new"),
        ("Removed Tests", len(comparison['removed_tests']), "badge-removed"),
    ]
    breakdown_html = ""
    for label, count, badge_cls in breakdown_items:
        breakdown_html += (f"<tr><td>{label}</td>"
                           f"<td class='num'><span class='badge {badge_cls}'>{count}</span></td></tr>\n")
    sections.append(
        f"<div class='section'>\n<h2>Changes Breakdown</h2>\n"
        f"<table>\n<tr><th>Category</th><th class='num'>Count</th></tr>\n"
        f"{breakdown_html}</table>\n</div>\n")

    # --- Fixed controls ---
    if comparison['fixed']:
        grouped = group_by_control(comparison['fixed'])
        controls_html = ""
        for control_id, items in grouped.items():
            test_list = "".join(
                f"<li>{_esc(item['pre'].get('title', item['key']))}</li>\n"
                for item in items
            )
            controls_html += (
                f"<details><summary>[{_esc(control_id)}] &mdash; "
                f"{len(items)} test(s) fixed</summary>\n"
                f"<ul>{test_list}</ul></details>\n")
        sections.append(
            f"<div class='section'>\n"
            f"<div class='section-header'><h2>Fixed Controls</h2>"
            f"<span class='badge badge-fixed'>{len(comparison['fixed'])} tests</span></div>\n"
            f"{controls_html}</div>\n")

    # --- Regressed controls ---
    if comparison['regressed']:
        grouped = group_by_control(comparison['regressed'])
        controls_html = ""
        for control_id, items in grouped.items():
            test_lines = ""
            for item in items:
                title = _esc(item['pre'].get('title', item['key']))
                test_lines += f"<li>{title}"
                if item['post'].get('expected'):
                    test_lines += f"<br><span class='expected-found'>Expected: <code>{_esc(item['post']['expected'])}</code></span>"
                if item['post'].get('found'):
                    test_lines += f"<br><span class='expected-found'>Found: <code>{_esc(item['post']['found'])}</code></span>"
                test_lines += "</li>\n"
            controls_html += (
                f"<details open><summary>[{_esc(control_id)}] &mdash; "
                f"{len(items)} test(s) regressed</summary>\n"
                f"<ul>{test_lines}</ul></details>\n")
        sections.append(
            f"<div class='section'>\n"
            f"<div class='warning-banner'>Regressed Controls &mdash; Passed &rarr; Failed</div>\n"
            f"<div class='section-header'><h2>Regressed Controls</h2>"
            f"<span class='badge badge-regressed'>{len(comparison['regressed'])} tests</span></div>\n"
            f"{controls_html}</div>\n")

    # --- Still failed controls ---
    if comparison['still_failed']:
        grouped = group_by_control(comparison['still_failed'])
        controls_html = ""
        for control_id, items in grouped.items():
            test_lines = ""
            for item in items:
                title = _esc(item['pre'].get('title', item['key']))
                test_lines += f"<li>{title}"
                if item['post'].get('expected'):
                    test_lines += f"<br><span class='expected-found'>Expected: <code>{_esc(item['post']['expected'])}</code></span>"
                if item['post'].get('found'):
                    test_lines += f"<br><span class='expected-found'>Found: <code>{_esc(item['post']['found'])}</code></span>"
                test_lines += "</li>\n"
            controls_html += (
                f"<details><summary>[{_esc(control_id)}] &mdash; "
                f"{len(items)} test(s) still failing</summary>\n"
                f"<ul>{test_lines}</ul></details>\n")
        sections.append(
            f"<div class='section'>\n"
            f"<div class='section-header'><h2>Still Failed Controls</h2>"
            f"<span class='badge badge-still-failed'>{len(comparison['still_failed'])} tests</span></div>\n"
            f"<p>These controls require manual remediation or configuration changes.</p>\n"
            f"{controls_html}</div>\n")

    title = f"{_esc(benchmark)} Audit Comparison Report"
    return HTML_TEMPLATE.format(
        title=title,
        generated=_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        pre_file=_esc(pre_file),
        post_file=_esc(post_file),
        content="\n".join(sections),
    )


def main():
    parser = argparse.ArgumentParser(
        description='Compare pre and post remediation Goss audit results',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s pre_audit.json post_audit.json
    %(prog)s pre_audit.json post_audit.json --format markdown
    %(prog)s pre_audit.json post_audit.json --format html -o report.html
    %(prog)s pre_audit.json post_audit.json --no-report
    %(prog)s pre_audit.json post_audit.json --no-report --format json > out.json
        """
    )
    parser.add_argument('pre_audit', help='Pre-remediation audit JSON file')
    parser.add_argument('post_audit', help='Post-remediation audit JSON file')
    parser.add_argument('--format', '-f', choices=['text', 'markdown', 'json', 'html'],
                        default='text', help='Output format (default: text)')
    parser.add_argument('--output', '-o',
                        help='Output file path (default: auto-generated audit_compare_report_<name>_<date>.<ext>)')
    parser.add_argument('--title', '-t',
                        help='Benchmark name for report title (default: auto-detected from filename)')
    parser.add_argument('--strict', action='store_true',
                        help='Exit 1 on regressions or still-failed controls (default: only regressions)')
    parser.add_argument('--no-report', action='store_true',
                        help='Print to stdout only, do not write a report file')

    args = parser.parse_args()

    # Load audit files
    pre_data = load_audit_file(args.pre_audit)
    post_data = load_audit_file(args.post_audit)

    # Extract results and summaries
    pre_results = extract_results(pre_data)
    post_results = extract_results(post_data)
    pre_summary = extract_summary(pre_data)
    post_summary = extract_summary(post_data)

    # Compare audits
    comparison = compare_audits(pre_results, post_results)

    # Resolve benchmark title and version
    benchmark = args.title if args.title else detect_benchmark_name(args.pre_audit, args.post_audit)
    version = detect_benchmark_version(args.pre_audit, args.post_audit)

    # Generate report
    if args.format == 'text':
        report = format_text_report(comparison, pre_summary, post_summary,
                                    args.pre_audit, args.post_audit, benchmark)
    elif args.format == 'markdown':
        report = format_markdown_report(comparison, pre_summary, post_summary,
                                        args.pre_audit, args.post_audit, benchmark)
    elif args.format == 'html':
        report = format_html_report(comparison, pre_summary, post_summary,
                                    args.pre_audit, args.post_audit, benchmark)
    else:
        report = format_json_report(comparison, pre_summary, post_summary,
                                    args.pre_audit, args.post_audit, benchmark)

    # Output report
    if args.no_report:
        print(report)
    else:
        output_path = args.output if args.output else generate_default_filename(benchmark, version, args.format)
        with open(output_path, 'w') as f:
            f.write(report)
        print(f"Report written to: {output_path}", file=sys.stderr)

    # Exit codes: 0 = no regressions, 1 = regressions (or still-failed in strict mode), 2 = input error
    if comparison['regressed']:
        sys.exit(1)
    if args.strict and comparison['still_failed']:
        sys.exit(1)


if __name__ == '__main__':
    main()
