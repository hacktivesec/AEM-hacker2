from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import Iterable, List

from .engine import report_to_dict
from .models import Finding, SEVERITY_ORDER, ScanReport

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

_SEV_LABEL = {
    "critical": "CRIT",
    "high":     "HIGH",
    "medium":   "MED ",
    "low":      "LOW ",
    "info":     "INFO",
}

_SEV_COLOR = {
    "critical": _red,
    "high":     _red,
    "medium":   _yellow,
    "low":      _blue,
    "info":     _white,
}

# Buckets printed as individual findings (401 and 404 are suppressed to a summary)
_STATUS_BUCKETS = [
    (200, "HTTP 200 — ACTIVELY ACCESSIBLE"),
    (301, "HTTP 3xx — REDIRECT"),
    (403, "HTTP 403 — BLOCKED / FORBIDDEN"),
    (None, "OTHER STATUS"),
]

# Codes that are demoted to summary-only (not shown as individual findings)
_SUMMARY_ONLY_CODES = {401, 404}

_REDIRECT_CODES = {301, 302, 303, 307, 308}


def _sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)


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


_CVE_PREFIXES = ("AEM-CVE", "AEM-CREDS", "AEM-XSS", "AEM-SSRF", "AEM-WEBDAV", "AEM-DESER", "AEM-AUDIT")


def _is_cve_finding(f: Finding) -> bool:
    return any(f.check_id.startswith(p) for p in _CVE_PREFIXES)


def _print_finding(f: Finding, show_rec: bool = False) -> None:
    """Print a single finding with its curl PoC."""
    label = _SEV_LABEL.get(f.severity, f.severity[:4].upper())
    color_fn = _SEV_COLOR.get(f.severity, _white)
    sev_str = color_fn(f"[{label}]")

    ep    = f.evidence.endpoint or _grey("(no endpoint)")
    hstat = _status_color(f.evidence.status_code)
    cid   = _bold(f.check_id)

    print(f"  {sev_str} {cid} — {f.title}")
    print(f"    {_grey('URL')}  {_cyan(ep)}")
    print(f"    {_grey('HTTP')} {hstat}")
    if f.evidence.snippet:
        snippet = f.evidence.snippet[:120].replace("\n", " ")
        print(f"    {_grey('Body')} {_dim(snippet)}")
    if f.curl_poc:
        print(f"    {_grey('PoC')}  {_dim(f.curl_poc)}")
    if show_rec and f.recommendation:
        print(f"    {_grey('Rec')}  {f.recommendation[:120]}")
    if f.state_changing:
        print(f"    {_red('⚠  STATE-CHANGING ACTION')}")
    print()


def _section(label: str, char: str = "─") -> None:
    line = char * 72
    print(f"\n{_grey(line)}")
    print(f"  {_bold(label)}")
    print(_grey(line))


def _print_findings_grouped(findings: List[Finding]) -> None:
    """Print findings grouped by HTTP status. 401/404 are suppressed to a summary line only."""
    cve_findings = [f for f in findings if _is_cve_finding(f)]
    general_findings = [f for f in findings if not _is_cve_finding(f)]

    # Split general findings: actionable vs summary-only
    actionable = [f for f in general_findings if f.evidence.status_code not in _SUMMARY_ONLY_CODES]
    summary_only = [f for f in general_findings if f.evidence.status_code in _SUMMARY_ONLY_CODES]

    # Group actionable findings by status bucket
    buckets: dict[int | None, List[Finding]] = defaultdict(list)
    for f in actionable:
        key = _bucket_key(f.evidence.status_code)
        buckets[key].append(f)

    printed_any = False

    for bucket_code, bucket_label in _STATUS_BUCKETS:
        group = _sorted_findings(buckets.get(bucket_code, []))
        if not group:
            continue
        printed_any = True
        _section(bucket_label)
        for f in group:
            _print_finding(f)

    # CVE-specific section (always shown regardless of status code)
    all_cve = _sorted_findings(cve_findings)
    if all_cve:
        _section("CVE / KNOWN VULNERABILITY CHECKS")
        for f in all_cve:
            _print_finding(f, show_rec=True)

    if not printed_any and not cve_findings:
        print("  (no findings to show)")

    # Summary-only counts for 401/404
    counts_401 = sum(1 for f in summary_only if f.evidence.status_code == 401)
    counts_404 = sum(1 for f in summary_only if f.evidence.status_code == 404)
    counts_200 = sum(1 for f in (actionable + cve_findings) if f.evidence.status_code == 200)
    if counts_401 or counts_404 or counts_200:
        _section("ENDPOINT STATUS SUMMARY")
        if counts_200:
            print(f"  {_green('●')} 200 Accessible   {_bold(str(counts_200)):>5}  (shown above as findings)")
        if counts_401:
            print(f"  {_yellow('●')} 401 Auth-gated   {_bold(str(counts_401)):>5}  (valid endpoints — not vulnerabilities)")
        if counts_404:
            print(f"  {_grey('●')} 404 Not found    {_grey(str(counts_404)):>5}  (absent or Dispatcher-stripped)")
        print()


def print_terminal_report(report: ScanReport) -> None:
    summary = report.summary()

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

    fp = report.aem_fingerprint
    aem_str = (_green("✔  YES") + f"  (confidence {fp.confidence}/10)") if fp.is_likely_aem else _red("✖  NO")
    kv("AEM Detected", aem_str)
    kv("AEM Version",  fp.detected_version or _grey("unknown"))
    waf_str = _red("⚠  DETECTED — scan coverage may be limited") if summary["edge_blocking_detected"] else _green("not detected")
    kv("WAF / BIG-IP", waf_str)
    print()

    # ── Severity summary bar ─────────────────────────────────────────────────
    all_findings_list = list(report.findings)
    actionable_findings = [
        f for f in all_findings_list
        if f.evidence.status_code != 401 or _is_cve_finding(f)
    ]
    non_vuln_401 = [
        f for f in all_findings_list
        if f.evidence.status_code == 401 and not _is_cve_finding(f)
    ]
    total = len(actionable_findings)

    from collections import Counter
    sev_counts: Counter = Counter(f.severity for f in actionable_findings)

    sev_parts = []
    for sev, fn in [("critical", _red), ("high", _red), ("medium", _yellow), ("low", _blue), ("info", _white)]:
        c = sev_counts.get(sev, 0)
        if c:
            sev_parts.append(f"{fn(str(c))} {sev}")

    print(f"  {_grey('Findings'.ljust(14))} {_bold(str(total))}   " + "  ".join(sev_parts))

    if non_vuln_401:
        print(f"  {_grey('Auth-gated'.ljust(14))} {_yellow(str(len(non_vuln_401)))}   (401 — valid endpoints, need auth)")

    # ── Warnings ─────────────────────────────────────────────────────────────
    if not fp.is_likely_aem:
        print()
        print(f"  {_yellow('⚠ ')} Low AEM confidence — AEM-specific checks suppressed.")

    if summary["edge_blocking_detected"]:
        print()
        print(f"  {_yellow('⚠ ')} {_bold('EdgeWAF / BIG-IP active.')}  401s may be 200s on origin.")
        print(f"      Inject APM tokens with {_cyan('--cookie')} or test from a trusted IP.")

    # ── Findings ─────────────────────────────────────────────────────────────
    if all_findings_list:
        print()
        print(_cyan("╔" + "═" * (W - 2) + "╗"))
        hdr = "  FINDINGS — grouped by HTTP status"
        print(_cyan("║") + _bold(hdr.ljust(W - 2)) + _cyan("║"))
        print(_cyan("╚" + "═" * (W - 2) + "╝"))
        _print_findings_grouped(all_findings_list)
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
    lines = [
        "# AEM Penetration Test Report",
        "",
        f"- Generated (UTC): {data['generated_at_utc']}",
        f"- Target: {data['summary']['target']}",
        f"- Profile: {data['summary']['profile']}",
        f"- Findings: {data['summary']['total_findings']}",
        f"- Edge/WAF blocking detected: {'yes' if data['summary'].get('edge_blocking_detected') else 'no'}",
        "",
        "## Severity",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = data["summary"]["severity_counts"].get(sev, 0)
        if count:
            lines.append(f"- {sev}: {count}")

    lines.append("\n## Findings")
    for finding in data["findings"]:
        lines.append(f"\n### {finding['check_id']} - {finding['title']}")
        lines.append(f"- Severity: {finding['severity']}")
        lines.append(f"- Category: {finding['category']}")
        lines.append(f"- Endpoint: {finding['evidence']['endpoint']}")
        lines.append(f"- Status: {finding['evidence']['status_code']}")
        lines.append(f"- Hash: {finding['evidence']['response_hash']}")
        lines.append(f"- Rationale: {finding['evidence']['rationale']}")
        lines.append(f"- Recommendation: {finding['recommendation']}")

    lines.append("\n## Cleanup")
    lines.append(f"- Required: {'yes' if data['cleanup']['required'] else 'no'}")
    if data["cleanup"]["required"]:
        for artifact in data["cleanup"]["artifacts"]:
            lines.append(
                f"- {artifact['action_id']}: {artifact['artifact_path']} cleanup_success={artifact['cleanup_success']}"
            )

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
