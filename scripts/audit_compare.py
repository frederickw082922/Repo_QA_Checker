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
import functools
import html as html_mod
import http.server
import json
import os
import re
import sys
import urllib.parse
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


def format_text_report(comparison, pre_summary, post_summary, pre_file, post_file, benchmark="Goss Audit", summary_only=False):
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

    if summary_only:
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        return "\n".join(lines)

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


def format_markdown_report(comparison, pre_summary, post_summary, pre_file, post_file, benchmark="Goss Audit", summary_only=False):
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

    if summary_only:
        return "\n".join(lines)

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


def format_json_report(comparison, pre_summary, post_summary, pre_file, post_file, benchmark="Goss Audit", summary_only=False):
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
    }
    if not summary_only:
        report['fixed'] = [{'control_id': i.get('pre', {}).get('control_id', ''), 'title': i.get('pre', {}).get('title', '')} for i in comparison['fixed']]
        report['regressed'] = [{'control_id': i.get('pre', {}).get('control_id', ''), 'title': i.get('pre', {}).get('title', '')} for i in comparison['regressed']]
        report['still_failed_by_control'] = {
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
  /* --- Interactive toolbar --- */
  .toolbar {{ background: #fff; padding: 12px 15px; border-radius: 8px;
              box-shadow: 0 2px 4px rgba(0,0,0,.1); margin-bottom: 20px;
              display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
  .toolbar-group {{ display: flex; gap: 6px; align-items: center; }}
  .toolbar-label {{ font-weight: bold; font-size: .85em; margin-right: 2px; }}
  .filter-btn {{ padding: 4px 12px; border-radius: 12px; font-size: .85em;
                 font-weight: bold; border: 2px solid transparent; cursor: pointer;
                 transition: opacity 0.2s; }}
  .filter-btn.inactive {{ opacity: 0.35; text-decoration: line-through; }}
  .search-input {{ padding: 6px 12px; border: 1px solid #dee2e6; border-radius: 6px;
                   font-size: .9em; width: 220px; }}
  .action-btn {{ padding: 6px 14px; border: 1px solid #16213e; border-radius: 6px;
                 background: #fff; color: #16213e; cursor: pointer; font-size: .85em; }}
  .action-btn:hover {{ background: #16213e; color: #fff; }}
  .search-count {{ font-size: .8em; color: #666; margin-left: 4px; }}
  .clickable-row {{ cursor: pointer; }}
  .clickable-row:hover {{ background: #e8f4f8 !important; }}
  /* Print-friendly */
  @media print {{
    .toolbar, .no-print {{ display: none !important; }}
    body {{ background: #fff; padding: 10px; }}
    .section {{ box-shadow: none; border: 1px solid #ccc; break-inside: avoid; }}
    details {{ display: block !important; }}
    details > * {{ display: block !important; }}
    details[open] summary {{ margin-bottom: 5px; }}
  }}
</style>
<noscript><style>.toolbar {{ display: none; }}</style></noscript>
</head>
<body>
<h1>{title}</h1>
<div class="metadata">
  <span><strong>Generated:</strong> {generated}</span>
  <span><strong>Pre-audit:</strong> <code>{pre_file}</code></span>
  <span><strong>Post-audit:</strong> <code>{post_file}</code></span>
</div>
{content}
<script>
{script}
</script>
</body>
</html>
"""


JS_INTERACTIVE = """
/* ---- Audit Compare Interactive Features ---- */

function initFilterControls() {
    var toolbar = document.getElementById('toolbar');
    if (!toolbar) return;
    var btns = toolbar.querySelectorAll('.filter-btn[data-cat]');
    btns.forEach(function(btn) {
        btn.addEventListener('click', function() {
            btn.classList.toggle('inactive');
            var cat = btn.getAttribute('data-cat');
            var sections = document.querySelectorAll('.section[data-category="' + cat + '"]');
            var hide = btn.classList.contains('inactive');
            sections.forEach(function(s) { s.style.display = hide ? 'none' : ''; });
        });
    });
}

function initSearch() {
    var input = document.getElementById('searchInput');
    var countEl = document.getElementById('searchCount');
    if (!input) return;
    input.addEventListener('input', function() {
        var q = input.value.toLowerCase().trim();
        var details = document.querySelectorAll('.section[data-category] details[data-search-text]');
        var shown = 0, total = details.length;
        details.forEach(function(d) {
            if (!q) { d.style.display = ''; shown++; return; }
            var text = (d.getAttribute('data-search-text') || '').toLowerCase();
            var match = text.indexOf(q) !== -1;
            d.style.display = match ? '' : 'none';
            if (match) shown++;
        });
        if (countEl) {
            countEl.textContent = q ? shown + ' / ' + total : '';
        }
    });
}

function initSortColumns() {
    var tables = document.querySelectorAll('table[data-sortable]');
    tables.forEach(function(table) {
        var headers = table.querySelectorAll('th');
        headers.forEach(function(th, colIdx) {
            th.style.cursor = 'pointer';
            th.style.userSelect = 'none';
            var dir = 0;  // 0=none, 1=asc, -1=desc
            th.addEventListener('click', function() {
                // Reset other headers
                headers.forEach(function(h) {
                    var arrow = h.querySelector('.sort-arrow');
                    if (arrow) arrow.textContent = '';
                });
                dir = dir === 1 ? -1 : 1;
                var arrow = th.querySelector('.sort-arrow');
                if (!arrow) {
                    arrow = document.createElement('span');
                    arrow.className = 'sort-arrow';
                    arrow.style.marginLeft = '4px';
                    arrow.style.fontSize = '0.75em';
                    th.appendChild(arrow);
                }
                arrow.textContent = dir === 1 ? '\\u25B2' : '\\u25BC';
                var tbody = table.querySelector('tbody') || table;
                var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
                // Skip header row if no tbody
                var headerRow = null;
                if (!table.querySelector('tbody') && rows.length > 0) {
                    var first = rows[0];
                    if (first.querySelector('th')) { headerRow = rows.shift(); }
                }
                rows.sort(function(a, b) {
                    var aCell = a.cells[colIdx];
                    var bCell = b.cells[colIdx];
                    if (!aCell || !bCell) return 0;
                    var aText = aCell.textContent.trim();
                    var bText = bCell.textContent.trim();
                    var aNum = parseFloat(aText.replace(/[^\\d.+-]/g, ''));
                    var bNum = parseFloat(bText.replace(/[^\\d.+-]/g, ''));
                    if (!isNaN(aNum) && !isNaN(bNum)) return (aNum - bNum) * dir;
                    return aText.localeCompare(bText) * dir;
                });
                if (headerRow) tbody.insertBefore(headerRow, tbody.firstChild);
                rows.forEach(function(row) { tbody.appendChild(row); });
            });
        });
    });
}

function initExpandCollapseAll() {
    var btn = document.getElementById('expandAllBtn');
    if (!btn) return;
    var expanded = false;
    btn.addEventListener('click', function() {
        expanded = !expanded;
        var details = document.querySelectorAll('.section[data-category] details');
        details.forEach(function(d) { d.open = expanded; });
        btn.textContent = expanded ? 'Collapse All' : 'Expand All';
    });
}

function initSummaryCardLinks() {
    var rows = document.querySelectorAll('tr[data-target]');
    rows.forEach(function(row) {
        row.addEventListener('click', function() {
            var targetId = row.getAttribute('data-target');
            var target = document.getElementById(targetId);
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                target.style.outline = '2px solid #16213e';
                setTimeout(function() { target.style.outline = ''; }, 1500);
            }
        });
    });
}

function initPrintMode() {
    var btn = document.getElementById('printBtn');
    if (!btn) return;
    btn.addEventListener('click', function() {
        var details = document.querySelectorAll('details');
        var prevStates = [];
        details.forEach(function(d) { prevStates.push(d.open); d.open = true; });
        setTimeout(function() {
            window.print();
            // Restore states after print dialog
            setTimeout(function() {
                details.forEach(function(d, i) { d.open = prevStates[i]; });
            }, 500);
        }, 100);
    });
}

document.addEventListener('DOMContentLoaded', function() {
    initFilterControls();
    initSearch();
    initSortColumns();
    initExpandCollapseAll();
    initSummaryCardLinks();
    initPrintMode();
});
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


def _build_search_text(control_id, items, key_field='pre'):
    """Build search text for a control group (control_id + all titles)."""
    parts = [control_id]
    for item in items:
        src = item.get(key_field) or item.get('post') or item.get('pre') or {}
        parts.append(src.get('title', ''))
    return ' '.join(parts)


def format_html_report(comparison, pre_summary, post_summary, pre_file, post_file, benchmark="Goss Audit", summary_only=False):
    """Generate an interactive HTML format report."""
    sections = []

    # --- Toolbar ---
    # Map categories to their badge classes and labels for filter buttons
    filter_cats = [
        ("fixed", "badge-fixed", "Fixed"),
        ("regressed", "badge-regressed", "Regressed"),
        ("still_failed", "badge-still-failed", "Still Failed"),
    ]
    filter_btns = ""
    for cat, badge_cls, label in filter_cats:
        count = len(comparison[cat])
        if count > 0:
            filter_btns += (
                f"    <button class='filter-btn {badge_cls}' data-cat='{cat}'>"
                f"{_esc(label)} ({count})</button>\n")

    toolbar = (
        "<div class='toolbar no-print' id='toolbar'>\n"
        "  <div class='toolbar-group'>\n"
        "    <span class='toolbar-label'>Filter:</span>\n"
        f"{filter_btns}"
        "  </div>\n"
        "  <div class='toolbar-group'>\n"
        "    <input type='text' class='search-input' id='searchInput'"
        " placeholder='Search control ID or test name...'>\n"
        "    <span class='search-count' id='searchCount'></span>\n"
        "  </div>\n"
        "  <div class='toolbar-group'>\n"
        "    <button class='action-btn' id='expandAllBtn'>Expand All</button>\n"
        "    <button class='action-btn' id='printBtn'>Print Report</button>\n"
        "  </div>\n"
        "</div>\n"
    )
    sections.append(toolbar)

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
        f"<div class='section' id='section-summary'>\n<h2>Summary</h2>\n"
        f"<table class='summary-table' data-sortable>\n"
        f"<tr><th>Metric</th><th class='num'>Pre-Audit</th>"
        f"<th class='num'>Post-Audit</th><th class='num'>Change</th></tr>\n"
        f"{summary_rows}</table>\n</div>\n")

    # --- Changes breakdown ---
    breakdown_items = [
        ("Fixed (Failed &rarr; Passed)", len(comparison['fixed']), "badge-fixed", "section-fixed"),
        ("Regressed (Passed &rarr; Failed)", len(comparison['regressed']), "badge-regressed", "section-regressed"),
        ("Still Failed", len(comparison['still_failed']), "badge-still-failed", "section-still-failed"),
        ("Still Passed", len(comparison['still_passed']), "badge-still-passed", ""),
        ("Skipped", len(comparison['skipped']), "badge-skipped", ""),
        ("New Tests", len(comparison['new_tests']), "badge-new", ""),
        ("Removed Tests", len(comparison['removed_tests']), "badge-removed", ""),
    ]
    breakdown_html = ""
    for label, count, badge_cls, target_id in breakdown_items:
        row_attrs = f" data-target='{target_id}' class='clickable-row'" if target_id and count > 0 else ""
        breakdown_html += (f"<tr{row_attrs}><td>{label}</td>"
                           f"<td class='num'><span class='badge {badge_cls}'>{count}</span></td></tr>\n")
    sections.append(
        f"<div class='section' id='section-breakdown'>\n<h2>Changes Breakdown</h2>\n"
        f"<table data-sortable>\n<tr><th>Category</th><th class='num'>Count</th></tr>\n"
        f"{breakdown_html}</table>\n</div>\n")

    if summary_only:
        title = f"{_esc(benchmark)} Audit Comparison Report"
        return HTML_TEMPLATE.format(
            title=title,
            generated=_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            pre_file=_esc(pre_file),
            post_file=_esc(post_file),
            content="\n".join(sections),
            script=JS_INTERACTIVE,
        )

    # --- Fixed controls ---
    if comparison['fixed']:
        grouped = group_by_control(comparison['fixed'])
        controls_html = ""
        for control_id, items in grouped.items():
            search_text = _esc(_build_search_text(control_id, items))
            test_list = "".join(
                f"<li>{_esc(item['pre'].get('title', item['key']))}</li>\n"
                for item in items
            )
            controls_html += (
                f"<details data-search-text='{search_text}'>"
                f"<summary>[{_esc(control_id)}] &mdash; "
                f"{len(items)} test(s) fixed</summary>\n"
                f"<ul>{test_list}</ul></details>\n")
        sections.append(
            f"<div class='section' id='section-fixed' data-category='fixed'>\n"
            f"<div class='section-header'><h2>Fixed Controls</h2>"
            f"<span class='badge badge-fixed'>{len(comparison['fixed'])} tests</span></div>\n"
            f"{controls_html}</div>\n")

    # --- Regressed controls ---
    if comparison['regressed']:
        grouped = group_by_control(comparison['regressed'])
        controls_html = ""
        for control_id, items in grouped.items():
            search_text = _esc(_build_search_text(control_id, items))
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
                f"<details open data-search-text='{search_text}'>"
                f"<summary>[{_esc(control_id)}] &mdash; "
                f"{len(items)} test(s) regressed</summary>\n"
                f"<ul>{test_lines}</ul></details>\n")
        sections.append(
            f"<div class='section' id='section-regressed' data-category='regressed'>\n"
            f"<div class='warning-banner'>Regressed Controls &mdash; Passed &rarr; Failed</div>\n"
            f"<div class='section-header'><h2>Regressed Controls</h2>"
            f"<span class='badge badge-regressed'>{len(comparison['regressed'])} tests</span></div>\n"
            f"{controls_html}</div>\n")

    # --- Still failed controls ---
    if comparison['still_failed']:
        grouped = group_by_control(comparison['still_failed'])
        controls_html = ""
        for control_id, items in grouped.items():
            search_text = _esc(_build_search_text(control_id, items))
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
                f"<details data-search-text='{search_text}'>"
                f"<summary>[{_esc(control_id)}] &mdash; "
                f"{len(items)} test(s) still failing</summary>\n"
                f"<ul>{test_lines}</ul></details>\n")
        sections.append(
            f"<div class='section' id='section-still-failed' data-category='still_failed'>\n"
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
        script=JS_INTERACTIVE,
    )


# ---------------------------------------------------------------------------
# Web UI (--serve)
# ---------------------------------------------------------------------------

WEB_UI_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Goss Audit Compare &mdash; Web UI</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
         sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px;
         background: #f5f5f5; color: #1a1a2e; }
  h1 { border-bottom: 3px solid #16213e; padding-bottom: 10px; margin-bottom: 20px; }
  h1 small { font-size: .5em; color: #666; font-weight: normal; }
  .panel { background: #fff; padding: 20px; border-radius: 8px;
           box-shadow: 0 2px 4px rgba(0,0,0,.1); margin-bottom: 20px; }
  .panel h2 { margin-top: 0; font-size: 1.1em; color: #16213e; }
  .form-row { display: flex; gap: 12px; align-items: end; margin-bottom: 12px;
              flex-wrap: wrap; }
  .form-group { display: flex; flex-direction: column; flex: 1; min-width: 200px; }
  .form-group label { font-weight: bold; font-size: .85em; margin-bottom: 4px; }
  .form-group input, .form-group select { padding: 8px 12px; border: 1px solid #dee2e6;
      border-radius: 6px; font-size: .9em; }
  .btn { padding: 8px 20px; border: none; border-radius: 6px; cursor: pointer;
         font-size: .9em; font-weight: bold; }
  .btn-primary { background: #16213e; color: #fff; }
  .btn-primary:hover { background: #1a3a5c; }
  .btn-primary:disabled { background: #999; cursor: not-allowed; }
  .btn-secondary { background: #e2e3e5; color: #383d41; }
  .btn-secondary:hover { background: #d6d8db; }
  .file-list { max-height: 200px; overflow-y: auto; border: 1px solid #dee2e6;
               border-radius: 6px; margin-top: 8px; }
  .file-item { padding: 6px 12px; cursor: pointer; font-size: .85em;
               display: flex; justify-content: space-between; }
  .file-item:hover { background: #e8f4f8; }
  .file-item.selected { background: #d4edda; font-weight: bold; }
  .file-item .tag { padding: 2px 8px; border-radius: 10px; font-size: .75em;
                    font-weight: bold; }
  .tag-pre { background: #d1ecf1; color: #0c5460; }
  .tag-post { background: #d4edda; color: #155724; }
  .status { padding: 10px 15px; border-radius: 6px; margin-bottom: 15px;
            font-size: .9em; }
  .status-info { background: #d1ecf1; color: #0c5460; }
  .status-error { background: #f8d7da; color: #721c24; }
  .status-success { background: #d4edda; color: #155724; }
  #results { min-height: 100px; }
  #results .toolbar { position: sticky; top: 0; z-index: 10; }
  .dir-path { font-family: monospace; font-size: .85em; }
  .spinner { display: inline-block; width: 16px; height: 16px;
             border: 2px solid #ccc; border-top-color: #16213e;
             border-radius: 50%; animation: spin .6s linear infinite;
             vertical-align: middle; margin-right: 6px; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<h1>Goss Audit Compare <small>Web UI</small></h1>

<div class="panel">
  <h2>Select Audit Files</h2>
  <div class="form-row">
    <div class="form-group" style="flex:2">
      <label>Directory</label>
      <div style="display:flex;gap:6px">
        <input type="text" id="dirInput" placeholder="Current directory" style="flex:1">
        <button class="btn btn-secondary" onclick="loadFiles()">Browse</button>
        <button class="btn btn-secondary" onclick="goUp()">Up</button>
      </div>
    </div>
    <div class="form-group" style="flex:1">
      <label>Report Title (optional)</label>
      <input type="text" id="titleInput" placeholder="Auto-detected">
    </div>
  </div>
  <div style="display:flex;gap:12px;">
    <div style="flex:1">
      <strong style="font-size:.85em">Pre-Audit File:</strong>
      <span id="preSelected" class="dir-path" style="color:#666">None selected</span>
      <div class="file-list" id="preList"></div>
    </div>
    <div style="flex:1">
      <strong style="font-size:.85em">Post-Audit File:</strong>
      <span id="postSelected" class="dir-path" style="color:#666">None selected</span>
      <div class="file-list" id="postList"></div>
    </div>
  </div>
  <div style="margin-top:12px;display:flex;gap:10px;align-items:center">
    <button class="btn btn-primary" id="compareBtn" onclick="runCompare()" disabled>
      Compare
    </button>
    <span id="statusMsg"></span>
  </div>
</div>

<div id="results"></div>

<script>
var currentDir = '';
var preFile = '';
var postFile = '';

function setStatus(msg, type) {
    var el = document.getElementById('statusMsg');
    if (msg) {
        el.innerHTML = (type === 'loading' ? '<span class="spinner"></span>' : '') + msg;
        el.className = 'status status-' + (type === 'loading' ? 'info' : type);
    } else {
        el.innerHTML = '';
        el.className = '';
    }
}

function loadFiles(dir) {
    var dirVal = dir || document.getElementById('dirInput').value;
    var url = '/api/files' + (dirVal ? '?dir=' + encodeURIComponent(dirVal) : '');
    setStatus('Loading files...', 'loading');
    fetch(url).then(function(r) { return r.json(); }).then(function(data) {
        if (data.error) { setStatus(data.error, 'error'); return; }
        currentDir = data.dir || '';
        document.getElementById('dirInput').value = currentDir;
        renderFileList('preList', data.files, 'pre');
        renderFileList('postList', data.files, 'post');
        setStatus('');
    }).catch(function(e) { setStatus('Failed to load files: ' + e, 'error'); });
}

function goUp() {
    if (!currentDir) return;
    var parts = currentDir.replace(/\\/\\/$/, '').split('/');
    parts.pop();
    var parent = parts.join('/') || '/';
    document.getElementById('dirInput').value = parent;
    loadFiles(parent);
}

function renderFileList(containerId, files, role) {
    var el = document.getElementById(containerId);
    el.innerHTML = '';
    files.forEach(function(f) {
        var div = document.createElement('div');
        div.className = 'file-item';
        var tag = '';
        if (f.type === 'pre') tag = '<span class="tag tag-pre">PRE</span>';
        else if (f.type === 'post') tag = '<span class="tag tag-post">POST</span>';
        div.innerHTML = '<span>' + escHtml(f.name) + '</span>' + tag;
        div.addEventListener('click', function() {
            if (role === 'pre') {
                preFile = f.path;
                document.getElementById('preSelected').textContent = f.name;
            } else {
                postFile = f.path;
                document.getElementById('postSelected').textContent = f.name;
            }
            // Highlight selection
            var siblings = el.querySelectorAll('.file-item');
            siblings.forEach(function(s) { s.classList.remove('selected'); });
            div.classList.add('selected');
            updateCompareBtn();
        });
        el.appendChild(div);
    });
}

function updateCompareBtn() {
    document.getElementById('compareBtn').disabled = !(preFile && postFile);
}

function runCompare() {
    if (!preFile || !postFile) return;
    var title = document.getElementById('titleInput').value;
    var url = '/api/report?pre=' + encodeURIComponent(preFile) +
              '&post=' + encodeURIComponent(postFile) + '&format=html';
    if (title) url += '&title=' + encodeURIComponent(title);
    setStatus('Running comparison...', 'loading');
    document.getElementById('compareBtn').disabled = true;
    fetch(url).then(function(r) {
        if (!r.ok) return r.json().then(function(d) { throw new Error(d.error || 'Server error'); });
        return r.text();
    }).then(function(html) {
        // Extract the body content from the full HTML report
        var match = html.match(/<body[^>]*>([\\s\\S]*)<\\/body>/i);
        var content = match ? match[1] : html;
        document.getElementById('results').innerHTML = content;
        setStatus('Comparison complete', 'success');
        document.getElementById('compareBtn').disabled = false;
        // Re-initialize interactive features on the injected report
        if (typeof initFilterControls === 'function') initFilterControls();
        if (typeof initSearch === 'function') initSearch();
        if (typeof initSortColumns === 'function') initSortColumns();
        if (typeof initExpandCollapseAll === 'function') initExpandCollapseAll();
        if (typeof initSummaryCardLinks === 'function') initSummaryCardLinks();
        if (typeof initPrintMode === 'function') initPrintMode();
    }).catch(function(e) {
        setStatus('Error: ' + e.message, 'error');
        document.getElementById('compareBtn').disabled = false;
    });
}

function escHtml(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

// Include the interactive report JS so it can be re-initialized
""" + JS_INTERACTIVE + """

// Load files on page load
loadFiles();
</script>
</body>
</html>
"""


class AuditCompareHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the audit comparison web UI."""

    def __init__(self, *args, base_dir='', **kwargs):
        self.base_dir = base_dir
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Route GET requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == '/':
            self._serve_index()
        elif path == '/api/files':
            self._serve_api_files(params)
        elif path == '/api/compare':
            self._serve_api_compare(params)
        elif path == '/api/report':
            self._serve_api_report(params)
        else:
            self._send_error(404, 'Not found')

    def _serve_index(self):
        """Serve the single-page application."""
        self._send_html(WEB_UI_HTML)

    def _serve_api_files(self, params):
        """List JSON files in a directory."""
        target_dir = params.get('dir', [''])[0] or self.base_dir
        validated = self._validate_path(target_dir, must_be_file=False)
        if validated is None:
            self._send_json({'error': 'Invalid directory path'}, 400)
            return
        if not os.path.isdir(validated):
            self._send_json({'error': 'Not a directory'}, 400)
            return

        files = []
        try:
            for name in sorted(os.listdir(validated)):
                if not name.endswith('.json'):
                    continue
                filepath = os.path.join(validated, name)
                if not os.path.isfile(filepath):
                    continue
                stat = os.stat(filepath)
                # Infer pre/post from filename
                name_lower = name.lower()
                file_type = None
                if '_pre_' in name_lower or 'pre_scan' in name_lower or name_lower.startswith('pre'):
                    file_type = 'pre'
                elif '_post_' in name_lower or 'post_scan' in name_lower or name_lower.startswith('post'):
                    file_type = 'post'
                files.append({
                    'name': name,
                    'path': filepath,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'type': file_type,
                })
        except OSError as e:
            self._send_json({'error': str(e)}, 500)
            return

        self._send_json({'dir': validated, 'files': files})

    def _serve_api_compare(self, params):
        """Run comparison and return JSON results."""
        pre_path = params.get('pre', [''])[0]
        post_path = params.get('post', [''])[0]
        title = params.get('title', [''])[0]

        pre_validated = self._validate_path(pre_path)
        post_validated = self._validate_path(post_path)
        if not pre_validated or not post_validated:
            self._send_json({'error': 'Invalid file path'}, 400)
            return

        try:
            pre_data = json.loads(Path(pre_validated).read_text())
            post_data = json.loads(Path(post_validated).read_text())
        except (json.JSONDecodeError, OSError) as e:
            self._send_json({'error': f'Failed to load audit file: {e}'}, 400)
            return

        pre_results = extract_results(pre_data)
        post_results = extract_results(post_data)
        pre_summary = extract_summary(pre_data)
        post_summary = extract_summary(post_data)
        comparison = compare_audits(pre_results, post_results)
        benchmark = title or detect_benchmark_name(pre_path, post_path)

        report = format_json_report(comparison, pre_summary, post_summary,
                                    pre_path, post_path, benchmark)
        self._send_json(json.loads(report))

    def _serve_api_report(self, params):
        """Generate formatted report and return it."""
        pre_path = params.get('pre', [''])[0]
        post_path = params.get('post', [''])[0]
        title = params.get('title', [''])[0]
        fmt = params.get('format', ['html'])[0]

        pre_validated = self._validate_path(pre_path)
        post_validated = self._validate_path(post_path)
        if not pre_validated or not post_validated:
            self._send_json({'error': 'Invalid file path'}, 400)
            return

        try:
            pre_data = json.loads(Path(pre_validated).read_text())
            post_data = json.loads(Path(post_validated).read_text())
        except (json.JSONDecodeError, OSError) as e:
            self._send_json({'error': f'Failed to load audit file: {e}'}, 400)
            return

        pre_results = extract_results(pre_data)
        post_results = extract_results(post_data)
        pre_summary = extract_summary(pre_data)
        post_summary = extract_summary(post_data)
        comparison = compare_audits(pre_results, post_results)
        benchmark = title or detect_benchmark_name(pre_path, post_path)

        if fmt == 'json':
            report = format_json_report(comparison, pre_summary, post_summary,
                                        pre_path, post_path, benchmark)
            self._send_json(json.loads(report))
        else:
            report = format_html_report(comparison, pre_summary, post_summary,
                                        pre_path, post_path, benchmark)
            self._send_html(report)

    def _validate_path(self, filepath, must_be_file=True):
        """Validate and resolve a file path to prevent directory traversal."""
        if not filepath:
            return None
        try:
            resolved = os.path.realpath(filepath)
        except (ValueError, OSError):
            return None
        # Allow paths within the base directory
        if not resolved.startswith(os.path.realpath(self.base_dir)):
            return None
        if must_be_file and not os.path.isfile(resolved):
            return None
        return resolved

    def _send_json(self, data, status=200):
        """Send a JSON response."""
        body = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, content, status=200):
        """Send an HTML response."""
        body = content.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status, message):
        """Send an error response."""
        self._send_json({'error': message}, status)

    def log_message(self, format, *args):
        """Suppress default request logging for cleaner output."""
        pass


def serve_web_ui(port, base_dir=None):
    """Launch local web server for the audit comparison UI."""
    if base_dir is None:
        base_dir = os.getcwd()

    handler = functools.partial(AuditCompareHandler, base_dir=base_dir)

    try:
        server = http.server.ThreadingHTTPServer(('127.0.0.1', port), handler)
    except OSError as e:
        print(f"Error: Could not start server on port {port}: {e}", file=sys.stderr)
        print(f"Try a different port: --serve {port + 1}", file=sys.stderr)
        sys.exit(2)

    print(f"Audit Compare Web UI running at: http://127.0.0.1:{port}", file=sys.stderr)
    print(f"Browsing files in: {base_dir}", file=sys.stderr)
    print("Press Ctrl+C to stop.", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.", file=sys.stderr)
        server.shutdown()


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
    %(prog)s pre_audit.json post_audit.json --summary-only --no-report
    %(prog)s --serve 9090
        """
    )
    parser.add_argument('pre_audit', nargs='?', help='Pre-remediation audit JSON file')
    parser.add_argument('post_audit', nargs='?', help='Post-remediation audit JSON file')
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
    parser.add_argument('--summary-only', action='store_true',
                        help='Show only summary and changes breakdown, skip control details')
    parser.add_argument('--serve', nargs='?', const=9090, type=int, metavar='PORT',
                        help='Launch web UI on PORT (default: 9090)')

    args = parser.parse_args()

    # Web UI mode
    if args.serve is not None:
        serve_web_ui(args.serve)
        return

    # Validate positional arguments for CLI mode
    if not args.pre_audit or not args.post_audit:
        parser.error('pre_audit and post_audit are required (unless using --serve)')

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
    so = args.summary_only
    if args.format == 'text':
        report = format_text_report(comparison, pre_summary, post_summary,
                                    args.pre_audit, args.post_audit, benchmark, summary_only=so)
    elif args.format == 'markdown':
        report = format_markdown_report(comparison, pre_summary, post_summary,
                                        args.pre_audit, args.post_audit, benchmark, summary_only=so)
    elif args.format == 'html':
        report = format_html_report(comparison, pre_summary, post_summary,
                                    args.pre_audit, args.post_audit, benchmark, summary_only=so)
    else:
        report = format_json_report(comparison, pre_summary, post_summary,
                                    args.pre_audit, args.post_audit, benchmark, summary_only=so)

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
