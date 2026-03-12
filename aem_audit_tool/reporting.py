from __future__ import annotations

import json
import sys
from collections import Counter
from typing import Iterable, List

from .engine import report_to_dict
from .models import Finding, ScanReport

# ---------------------------------------------------------------------------
# ANSI colour helpers — automatically disabled when stdout is not a TTY
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Wrap text in an ANSI escape sequence, or return plain text if no TTY."""
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


# Convenience wrappers
def _bold(t: str) -> str:           return _c("1", t)
def _dim(t: str) -> str:            return _c("2", t)
def _red(t: str) -> str:            return _c("1;31", t)
def _yellow(t: str) -> str:         return _c("1;33", t)
def _green(t: str) -> str:          return _c("1;32", t)
def _cyan(t: str) -> str:           return _c("1;36", t)
def _blue(t: str) -> str:           return _c("1;34", t)
def _magenta(t: str) -> str:        return _c("1;35", t)
def _white(t: str) -> str:          return _c("1;37", t)
def _grey(t: str) -> str:           return _c("38;5;244", t)

# Statuses treated as non-findings context in terminal/markdown output.
_NON_FINDING_CODES = {401, 403, 404}

_REDIRECT_CODES = {301, 302, 303, 307, 308}


def _sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            f.check_id,
            f.category,
            f.evidence.endpoint or "",
            f.evidence.status_code or 0,
        ),
    )


def _bucket_key(status: int | None) -> int | None:
    if status is None:
        return None
    if status == 200:
        return 200
    if status in _REDIRECT_CODES:
        return 301
    if status == 401:
        return 401
    if status == 403:
        return 403
    if status == 404:
        return 404
    return None


def _status_color(status: int | None) -> str:
    if status == 200:
        return _green(str(status))
    if status in _REDIRECT_CODES:
        return _yellow(str(status))
    if status in (401, 403):
        return _red(str(status))
    return _grey(str(status) if status else "—")


def _status_text(status: int | None) -> str:
    if status is None:
        return "n/a"
    if status in _REDIRECT_CODES:
        return f"{status} redirect"
    if status == 401:
        return "401 auth required"
    if status == 403:
        return "403 blocked"
    return str(status)


_CVE_PREFIXES = ("AEM-CVE", "AEM-CREDS", "AEM-XSS", "AEM-SSRF", "AEM-WEBDAV", "AEM-DESER", "AEM-AUDIT")


def _is_cve_finding(f: Finding) -> bool:
    return any(f.check_id.startswith(p) for p in _CVE_PREFIXES)


def _truncate(text: str, limit: int = 160) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _actionable_findings(findings: Iterable[Finding]) -> list[Finding]:
    return [
        f for f in findings
        if f.evidence.status_code not in _NON_FINDING_CODES
    ]


def _auth_gated_count(findings: Iterable[Finding]) -> int:
    return sum(
        1 for f in findings
        if f.evidence.status_code == 401
    )


def _suppressed_status_counts(findings: Iterable[Finding]) -> Counter:
    return Counter(f.evidence.status_code for f in findings if f.evidence.status_code in _NON_FINDING_CODES)


def _aem_status(report: ScanReport) -> str:
    fp = report.aem_fingerprint
    if not fp.is_likely_aem:
        return "not confirmed"
    if fp.detected_version:
        return f"likely AEM ({fp.detected_version})"
    return "likely AEM"


def _assessment_notes(report: ScanReport, actionable: list[Finding], auth_gated: int) -> list[str]:
    notes: list[str] = []
    summary = report.summary()

    if summary["edge_blocking_detected"]:
        notes.append("Edge filtering is likely affecting coverage; origin behavior may differ from what the scanner received.")
    if auth_gated:
        notes.append(f"{auth_gated} endpoint(s) responded with 401 and were treated as authenticated surface, not vulnerabilities.")
    if summary["state_changing_findings"]:
        notes.append("The scan recorded state-changing activity. Review cleanup results before sharing the report externally.")

    if actionable:
        notes.append(f"{len(actionable)} validated finding(s) are shown below.")
    else:
        notes.append("No actionable findings were recorded in this run.")

    return notes


def _print_finding(f: Finding, show_rec: bool = True, show_poc: bool = False) -> None:
    ep = f.evidence.endpoint or _grey("(no endpoint)")
    hstat = _status_color(f.evidence.status_code)
    cid = _bold(f.check_id)

    print(f"  {cid} — {f.title}")
    print(f"    {_grey('URL')}  {_cyan(ep)}")
    print(f"    {_grey('HTTP')} {hstat}")
    if f.evidence.rationale:
        print(f"    {_grey('Why')}  {_truncate(f.evidence.rationale)}")
    if f.evidence.snippet:
        print(f"    {_grey('Body')} {_dim(_truncate(f.evidence.snippet, 120))}")
    if show_poc and f.curl_poc:
        print(f"    {_grey('PoC')}  {_dim(f.curl_poc)}")
    if show_rec and f.recommendation:
        print(f"    {_grey('Rec')}  {_truncate(f.recommendation)}")
    if f.state_changing:
        print(f"    {_red('⚠  STATE-CHANGING ACTION')}")
    print()


def _section(label: str, char: str = "─") -> None:
    line = char * 72
    print(f"\n{_grey(line)}")
    print(f"  {_bold(label)}")
    print(_grey(line))


def _print_finding_list(label: str, findings: list[Finding], show_poc: bool = False) -> None:
    if not findings:
        return
    _section(label)
    for finding in findings:
        _print_finding(finding, show_poc=show_poc)


def _markdown_findings_section(lines: list[str], heading: str, findings: list[Finding]) -> None:
    lines.append(f"## {heading}")
    if not findings:
        lines.append("No findings in this section.")
        lines.append("")
        return

    for finding in findings:
        lines.append(f"### {finding.check_id} - {finding.title}")
        lines.append(f"- Category: {finding.category}")
        lines.append(f"- Endpoint: {finding.evidence.endpoint}")
        lines.append(f"- HTTP status: {_status_text(finding.evidence.status_code)}")
        if finding.evidence.rationale:
            lines.append(f"- Why it matters: {_truncate(finding.evidence.rationale, 280)}")
        if finding.evidence.snippet:
            lines.append(f"- Evidence: {_truncate(finding.evidence.snippet, 220)}")
        if finding.recommendation:
            lines.append(f"- Recommendation: {_truncate(finding.recommendation, 280)}")
        if finding.state_changing:
            lines.append("- State-changing: yes")
        if finding.curl_poc:
            lines.append(f"- Reproduce: `{finding.curl_poc}`")
        lines.append("")


def print_terminal_report(report: ScanReport) -> None:
    summary = report.summary()
    actionable_findings = _actionable_findings(report.findings)
    auth_gated = _auth_gated_count(report.findings)
    suppressed = _suppressed_status_counts(report.findings)

    W = 72  # output width

    # ── Header ──────────────────────────────────────────────────────────────
    print()
    print(_cyan("╔" + "═" * (W - 2) + "╗"))
    title = "  AEM PENETRATION TEST REPORT"
    print(_cyan("║") + _bold(title.ljust(W - 2)) + _cyan("║"))
    print(_cyan("╚" + "═" * (W - 2) + "╝"))

    def kv(key: str, val: str, color_fn=None) -> None:
        v = color_fn(val) if color_fn else val
        print(f"  {_grey(key.ljust(14))} {v}")

    print()
    kv("Target",    summary["target"],       _cyan)
    kv("Generated", summary["generated_at_utc"][:19].replace("T", "  "))
    kv("Profile",   summary["profile"],      _bold)

    if report.reachability_error:
        print()
        print(f"  {_red('✖  PREFLIGHT FAILED')}")
        print(f"     {_grey('Cause')}  {report.reachability_error}")
        print(f"     {_grey('Action')} Validate URL, proxy/tunnel, TLS trust, and reachability.")
        return

    kv("AEM Status", _green(_aem_status(report)) if report.aem_fingerprint.is_likely_aem else _yellow(_aem_status(report)))
    kv("Findings", str(len(actionable_findings)), _bold)
    kv("Suppressed", str(sum(suppressed.values())), _yellow if suppressed else _grey)
    kv("Auth-gated", str(auth_gated), _yellow if auth_gated else _grey)
    waf_str = _red("detected") if summary["edge_blocking_detected"] else _green("not detected")
    kv("Edge Filter", waf_str)
    print()

    if suppressed:
        parts = []
        for code in (401, 403, 404):
            if suppressed.get(code):
                parts.append(f"{code}={suppressed[code]}")
        print(f"  {_grey('Suppressed'.ljust(14))} {_dim(', '.join(parts))}")

    _section("ASSESSMENT")
    for note in _assessment_notes(report, actionable_findings, auth_gated):
        print(f"  - {note}")

    if actionable_findings:
        _print_finding_list("VALIDATED FINDINGS", _sorted_findings(actionable_findings), show_poc=True)
    else:
        print()
        print(f"  {_green('✔')}  No findings recorded.")

    # ── Cleanup ───────────────────────────────────────────────────────────────
    print()
    print(_grey("─" * W))
    print(f"  {_grey('CLEANUP')}")
    print(_grey("─" * W))
    if not report.artifacts:
        print(f"  {_green('✔')}  No artifacts created during this scan.")
    else:
        for artifact in report.artifacts:
            print(
                f"  {_yellow('!')}  {artifact.action_id} | {artifact.artifact_path} | "
                f"cleanup_attempted={artifact.cleanup_attempted} "
                f"cleanup_success={artifact.cleanup_success}"
            )
        print(f"  {_yellow('⚠ ')} Verify above paths and confirm cleanup in the change record.")
    print()


def write_json(path: str, report: ScanReport) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report_to_dict(report), handle, indent=2)


def write_markdown(path: str, report: ScanReport) -> None:
    data = report_to_dict(report)
    actionable_findings = _actionable_findings(report.findings)
    auth_gated = _auth_gated_count(report.findings)
    suppressed = _suppressed_status_counts(report.findings)
    lines = [
        "# AEM Hacker Report",
        "",
        f"- Generated (UTC): {data['generated_at_utc']}",
        f"- Target: {data['summary']['target']}",
        f"- Profile: {data['summary']['profile']}",
        f"- AEM status: {_aem_status(report)}",
        f"- Findings: {len(actionable_findings)}",
        f"- Suppressed non-findings (401/403/404): {sum(suppressed.values())}",
        f"- Auth-gated endpoints: {auth_gated}",
        f"- Edge/WAF blocking detected: {'yes' if data['summary'].get('edge_blocking_detected') else 'no'}",
        "",
        "## Assessment",
    ]
    for note in _assessment_notes(report, actionable_findings, auth_gated):
        lines.append(f"- {note}")

    if suppressed:
        parts = []
        for code in (401, 403, 404):
            if suppressed.get(code):
                parts.append(f"{code}: {suppressed[code]}")
        lines.append(f"- Suppressed status counts: {', '.join(parts)}")

    lines.append("")
    _markdown_findings_section(lines, "Validated Findings", _sorted_findings(actionable_findings))

    lines.append("## Cleanup")
    lines.append(f"- Required: {'yes' if data['cleanup']['required'] else 'no'}")
    if data["cleanup"]["required"]:
        for artifact in data["cleanup"]["artifacts"]:
            lines.append(
                f"- {artifact['action_id']}: {artifact['artifact_path']} cleanup_success={artifact['cleanup_success']}"
            )

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
