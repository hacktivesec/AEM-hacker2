from __future__ import annotations

import uuid
from collections import Counter
from typing import List, Optional, Tuple

from .base import Check, CheckContext, CheckOutcome
from ..models import Evidence, Finding, HttpResult
from ..response_analysis import analyse_response


_BENIGN_PROBES = [
    "/",
    "/robots.txt",
    "/favicon.ico",
]

_SUSPICIOUS_PROBES = [
    "/system/console",
    "/crx/de",
    "/bin/querybuilder.json?path=/home/users&type=rep:User&p.limit=-1",
    "/content/..;/system/console",
    "/%2e%2e/%2e%2e/etc/passwd",
]

_BIGIP_HEADER_HINTS = [
    "x-cnection",
    "x-wa-info",
    "x-f5-",
]

_BIGIP_COOKIE_HINTS = [
    "bigipserver",
    "f5avr",
    "ts01",
    "ts0",
]

_BIGIP_BODY_HINTS = [
    "the requested url was rejected",
    "support id",
    "request rejected",
    "f5 networks",
    "asm support id",
]


def _build_evidence(endpoint: str, status: Optional[int], response_hash: str, rationale: str, snippet: str) -> Evidence:
    return Evidence(
        endpoint=endpoint,
        status_code=status,
        response_hash=response_hash,
        snippet=(snippet or "")[:220].replace("\n", " "),
        rationale=rationale,
    )


def _bigip_signals(result: HttpResult) -> List[str]:
    signals: List[str] = []
    headers = {k.lower(): v for k, v in result.headers.items()}
    body = (result.text or "").lower()

    server = headers.get("server", "").lower()
    if "big-ip" in server or "bigip" in server or "f5" in server:
        signals.append(f"server={headers.get('server', '')}")

    for key in headers:
        if any(key.startswith(prefix) for prefix in _BIGIP_HEADER_HINTS):
            signals.append(f"header={key}")

    set_cookie = headers.get("set-cookie", "").lower()
    if set_cookie:
        for cookie_hint in _BIGIP_COOKIE_HINTS:
            if cookie_hint in set_cookie:
                signals.append(f"cookie~{cookie_hint}")

    for hint in _BIGIP_BODY_HINTS:
        if hint in body:
            signals.append(f"body={hint}")

    return list(dict.fromkeys(signals))


class EdgeBlockingDetectionCheck(Check):
    check_id = "AEM-EDGE-001"
    name = "edge-blocking-detection"
    tags = ["waf", "proxy", "reverse-proxy", "bigip", "blocking"]
    profiles = ["quick", "standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        nonce_path = f"/aem-audit-{uuid.uuid4().hex[:10]}.txt"
        benign_probe_paths = [*_BENIGN_PROBES, nonce_path]

        benign_results: List[Tuple[str, HttpResult]] = []
        suspicious_results: List[Tuple[str, HttpResult]] = []

        for path in benign_probe_paths:
            result = ctx.client.request("GET", path)
            if not result.error:
                benign_results.append((path, result))

        for path in _SUSPICIOUS_PROBES:
            result = ctx.client.request("GET", path)
            if not result.error:
                suspicious_results.append((path, result))

        if not benign_results and not suspicious_results:
            return CheckOutcome(findings=[], artifacts=[])

        benign_ok = sum(1 for _, r in benign_results if (r.status_code or 0) < 500)
        suspicious_blocked = [
            (p, r) for p, r in suspicious_results if r.status_code in (401, 403, 406, 429, 503)
        ]

        all_results = benign_results + suspicious_results
        all_hashes = [r.response_hash for _, r in all_results if r.response_hash and r.response_hash != "-"]
        repeated_hash = False
        repeated_hash_value = ""
        if all_hashes:
            hash_counts = Counter(all_hashes)
            repeated_hash_value, repeated_count = hash_counts.most_common(1)[0]
            repeated_hash = repeated_count >= max(3, len(all_hashes) // 2)

        edge_confident = 0
        bigip_markers: List[str] = []
        for _, result in all_results:
            analysis = analyse_response(result)
            if analysis.edge_confidence >= 65:
                edge_confident += 1
            bigip_markers.extend(_bigip_signals(result))
        bigip_markers = list(dict.fromkeys(bigip_markers))

        score = 0
        reasons: List[str] = []

        if benign_ok >= 2 and len(suspicious_blocked) >= 2:
            score += 30
            reasons.append(
                f"Differential behavior detected: benign probes reachable ({benign_ok}) while sensitive probes are blocked ({len(suspicious_blocked)})."
            )

        if edge_confident >= 3:
            score += 20
            reasons.append(f"Multiple responses classified as edge-filtered (count={edge_confident}).")

        if repeated_hash:
            score += 15
            reasons.append(
                f"Repeated response signature detected (hash={repeated_hash_value}), indicating a likely generic block page."
            )

        if bigip_markers:
            score += 35
            reasons.append("BIG-IP/F5 indicators present: " + ", ".join(bigip_markers[:4]))

        if any((r.status_code == 429) for _, r in all_results):
            score += 10
            reasons.append("Rate-limiting behavior observed (HTTP 429).")

        if score < 45:
            return CheckOutcome(findings=[], artifacts=[])

        representative = suspicious_blocked[0] if suspicious_blocked else all_results[0]
        representative_path, representative_result = representative

        findings.append(
            Finding(
                check_id=self.check_id,
                title="Reverse proxy/WAF blocking likely affecting scan coverage",
                severity="high" if score >= 65 else "medium",
                category="edge_blocking",
                evidence=_build_evidence(
                    endpoint=representative_result.url,
                    status=representative_result.status_code,
                    response_hash=representative_result.response_hash,
                    rationale=(
                        f"Blocking confidence score={score}/100. "
                        + " ".join(reasons[:4])
                    ),
                    snippet=(
                        f"representative_path={representative_path}; "
                        f"status={representative_result.status_code}; "
                        f"bigip_indicators={'; '.join(bigip_markers[:3]) or 'none'}"
                    ),
                ),
                recommendation=(
                    "This target appears to be protected by an edge filter (WAF/reverse proxy). "
                    "For accurate AEM coverage, obtain an authorised allowlist for tester source IP/User-Agent, "
                    "or route testing to an origin endpoint behind change controls. "
                    "Compare baseline and bypass responses to distinguish edge blocks from AEM ACL denials."
                ),
            )
        )

        if bigip_markers:
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="F5 BIG-IP signature observed in responses",
                    severity="info",
                    category="edge_blocking",
                    evidence=_build_evidence(
                        endpoint=ctx.client.base_url,
                        status=representative_result.status_code,
                        response_hash=representative_result.response_hash,
                        rationale="Detected vendor signatures consistent with F5 BIG-IP/ASM.",
                        snippet="; ".join(bigip_markers[:6]),
                    ),
                    recommendation=(
                        "Coordinate with the BIG-IP/WAF team for temporary policy tuning during authorised testing, "
                        "then re-run deep profile checks for accurate exposure results."
                    ),
                )
            )

        return CheckOutcome(findings=findings, artifacts=[])