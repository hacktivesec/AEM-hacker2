from __future__ import annotations

import dataclasses
import datetime as dt
from typing import Dict, List, Optional


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}



@dataclasses.dataclass
class Evidence:
    endpoint: str
    status_code: Optional[int]
    response_hash: str
    snippet: str
    rationale: str


@dataclasses.dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    category: str
    evidence: Evidence
    recommendation: str
    authenticated: bool = False
    state_changing: bool = False
    # Reproducible curl command generated post-scan from the confirmed URL + scan config
    curl_poc: Optional[str] = None


@dataclasses.dataclass
class ActionArtifact:
    action_id: str
    description: str
    artifact_path: str
    cleanup_attempted: bool
    cleanup_success: bool
    notes: str


@dataclasses.dataclass
class Fingerprint:
    is_likely_aem: bool
    confidence: int
    detected_version: Optional[str]
    markers: List[str]


@dataclasses.dataclass
class ScanConfig:
    target: str
    username: Optional[str]
    password: Optional[str]
    proxy: Optional[str]
    timeout: float
    verify_ssl: bool
    workers: int
    rate_limit: float
    retries: int
    backoff: float
    active_tests: bool
    include_state_changing: bool
    profile: str
    include_checks: List[str]
    exclude_checks: List[str]
    json_out: Optional[str]
    md_out: Optional[str]
    dry_run: bool
    # Optional OOB callback URL for active SSRF probes (e.g. https://your.interactsh.tld/token)
    oob_collector: Optional[str] = None
    # Optional raw Cookie header value — useful for BIG-IP APM session cookies
    # (MRHSession, LastMRH_Session, F5_ST) or any pre-authenticated session token.
    cookie: Optional[str] = None
    # Optional custom User-Agent string. Defaults to "AEM-Audit-Pro/2.0" when not set.
    user_agent: Optional[str] = None


@dataclasses.dataclass
class ChainSuggestion:
    """A suggested attack chain produced by the chaining analysis engine."""
    chain_id: str
    title: str
    impact: str
    prerequisite_check_ids: List[str]
    prerequisite_categories: List[str]
    steps: List[str]
    triggered_by: List[str]
    references: List[str]


@dataclasses.dataclass
class ScanReport:
    generated_at_utc: str
    target: str
    profile: str
    aem_fingerprint: Fingerprint
    reachability_error: Optional[str]
    findings: List[Finding]
    artifacts: List[ActionArtifact]
    chain_suggestions: List["ChainSuggestion"] = dataclasses.field(default_factory=list)
    # Scan config retained for PoC generation and post-processing; excluded from summary()
    config: Optional["ScanConfig"] = dataclasses.field(default=None, compare=False, repr=False)

    def summary(self) -> Dict[str, object]:
        severity_counts: Dict[str, int] = {}
        auth_findings = 0
        unauth_findings = 0
        state_changing = 0
        edge_blocking_findings = 0
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            if finding.authenticated:
                auth_findings += 1
            else:
                unauth_findings += 1
            if finding.state_changing:
                state_changing += 1
            if finding.category == "edge_blocking":
                edge_blocking_findings += 1

        return {
            "generated_at_utc": self.generated_at_utc,
            "target": self.target,
            "profile": self.profile,
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "unauthenticated_findings": unauth_findings,
            "authenticated_findings": auth_findings,
            "state_changing_findings": state_changing,
            "edge_blocking_findings": edge_blocking_findings,
            "edge_blocking_detected": edge_blocking_findings > 0,
            "cleanup_required": bool(self.artifacts),
        }


@dataclasses.dataclass
class HttpResult:
    url: str
    status_code: Optional[int]
    headers: Dict[str, str]
    text: str
    response_hash: str
    error: Optional[str]
    # Raw HTTP status before any local normalization heuristics.
    raw_status_code: Optional[int] = None


@dataclasses.dataclass
class ReachabilityResult:
    ok: bool
    message: str


def now_utc_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat()
