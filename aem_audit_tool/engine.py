from __future__ import annotations

import dataclasses
import json
from typing import List

from .chaining import evaluate_chains, ChainSuggestion as _ChainSuggestion
from .checks.base import CheckContext, check_selected
from .checks.registry import get_all_checks
from .http_client import HttpClient
from .models import ChainSuggestion, Fingerprint, ScanConfig, ScanReport, now_utc_iso


def _build_curl_poc(url: str, config: ScanConfig, method: str = "GET", note: str = "") -> str:
    """Generate a reproducible curl command for a confirmed finding URL."""
    parts = ["curl"]
    if not config.verify_ssl:
        parts.append("-k")
    parts += ["-s", "-o", "/dev/null", "-w", "'%{http_code}'"]
    parts += ["-X", method]
    if config.proxy:
        parts += ["-x", config.proxy]
    if config.cookie:
        parts += ["-b", f"'{config.cookie}'"]
    ua = config.user_agent or "AEM-Audit-Pro/2.0"
    parts += ["-A", f"'{ua}'"]
    if config.username and config.password:
        parts += ["-u", f"'{config.username}:{config.password}'"]
    parts.append(f"'{url}'")
    cmd = " ".join(parts)
    if note:
        cmd += f"  # {note}"
    return cmd


def run_scan(config: ScanConfig) -> ScanReport:
    fingerprint = Fingerprint(is_likely_aem=False, confidence=0, detected_version=None, markers=[])
    client = HttpClient(
        base_url=config.target,
        timeout=config.timeout,
        verify_ssl=config.verify_ssl,
        proxy=config.proxy,
        username=config.username,
        password=config.password,
        retries=config.retries,
        backoff=config.backoff,
        rate_limit=config.rate_limit,
        cookie=config.cookie,
        user_agent=config.user_agent,
    )

    preflight = client.preflight()
    if not preflight.ok:
        return ScanReport(
            generated_at_utc=now_utc_iso(),
            target=config.target,
            profile=config.profile,
            aem_fingerprint=fingerprint,
            reachability_error=preflight.message,
            findings=[],
            artifacts=[],
        )

    findings = []
    artifacts = []

    ctx = CheckContext(client=client, config=config, fingerprint=fingerprint)
    checks = get_all_checks()

    for check in checks:
        if not check_selected(check, config.profile, config.include_checks, config.exclude_checks):
            continue
        if check.requires_auth and not (config.username and config.password):
            continue
        if check.active and not config.active_tests:
            continue
        if check.state_changing and not config.include_state_changing:
            continue

        outcome = check.run(ctx)
        findings.extend(outcome.findings)
        artifacts.extend(outcome.artifacts)

    # Post-process: fill curl_poc for any finding that doesn't already have one
    for finding in findings:
        if not finding.curl_poc and finding.evidence.endpoint:
            finding.curl_poc = _build_curl_poc(
                url=finding.evidence.endpoint,
                config=config,
            )

    # Build attack chain suggestions from all collected findings
    raw_chains = evaluate_chains(findings)
    chain_suggestions: List[ChainSuggestion] = [
        ChainSuggestion(
            chain_id=c.chain_id,
            title=c.title,
            impact=c.impact,
            prerequisite_check_ids=c.prerequisite_check_ids,
            prerequisite_categories=c.prerequisite_categories,
            steps=c.steps,
            triggered_by=c.triggered_by,
            references=c.references,
        )
        for c in raw_chains
    ]

    return ScanReport(
        generated_at_utc=now_utc_iso(),
        target=config.target,
        profile=config.profile,
        aem_fingerprint=fingerprint,
        reachability_error=None,
        findings=findings,
        artifacts=artifacts,
        chain_suggestions=chain_suggestions,
        config=config,
    )


def report_to_dict(report: ScanReport) -> dict:
    return {
        "generated_at_utc": report.generated_at_utc,
        "summary": report.summary(),
        "aem_fingerprint": dataclasses.asdict(report.aem_fingerprint),
        "reachability_error": report.reachability_error,
        "findings": [dataclasses.asdict(finding) for finding in report.findings],
        "cleanup": {
            "required": bool(report.artifacts),
            "artifacts": [dataclasses.asdict(item) for item in report.artifacts],
        },
        "attack_chains": [
            dataclasses.asdict(chain) for chain in report.chain_suggestions
        ],
    }


def report_to_json(report: ScanReport) -> str:
    return json.dumps(report_to_dict(report), indent=2)
