from __future__ import annotations

import re
from typing import List

from .base import Check, CheckContext, CheckOutcome
from ..models import Evidence, Finding

AEM_VERSION_RE = re.compile(r"AEM\s*(?:Version)?\s*([0-9][^\s<]*)", re.IGNORECASE)


class FingerprintCheck(Check):
    check_id = "AEM-FP-001"
    name = "fingerprint"
    tags = ["fingerprint", "aem"]
    profiles = ["quick", "standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        markers = []
        confidence = 0
        version = None

        probes = [
            "/",
            "/libs/granite/core/content/login.html",
            "/system/sling/info.sessionInfo.json",
            "/crx/de/index.jsp",
        ]

        for path in probes:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            body = result.text.lower()
            headers = {k.lower(): v for k, v in result.headers.items()}

            if "adobe experience manager" in body or "cq-authoring" in body:
                confidence += 3
                markers.append(f"{path}:html_marker")
            if "granite" in body or "sling" in body:
                confidence += 2
                markers.append(f"{path}:granite_or_sling_marker")
            if "x-aem" in " ".join(headers.keys()):
                confidence += 2
                markers.append(f"{path}:aem_header")
            if result.status_code in (200, 401, 403) and path in {
                "/libs/granite/core/content/login.html",
                "/crx/de/index.jsp",
            }:
                confidence += 1
                markers.append(f"{path}:known_endpoint_behavior")

            version_match = AEM_VERSION_RE.search(result.text)
            if version_match:
                version = version_match.group(1)
                markers.append(f"{path}:version={version}")

        ctx.fingerprint.is_likely_aem = confidence >= 4
        ctx.fingerprint.confidence = confidence
        ctx.fingerprint.detected_version = version
        ctx.fingerprint.markers = markers

        findings.append(
            Finding(
                check_id=self.check_id,
                title="AEM fingerprint assessment",
                severity="info",
                category="fingerprint",
                evidence=Evidence(
                    endpoint=ctx.client.base_url,
                    status_code=200 if ctx.fingerprint.is_likely_aem else None,
                    response_hash="-",
                    snippet="; ".join(markers[:4]) or "No reliable AEM markers",
                    rationale=(
                        f"Likely AEM={ctx.fingerprint.is_likely_aem}. "
                        f"Detected version={version or 'unknown'}. "
                        f"Observed markers={len(markers)}."
                    ),
                ),
                recommendation=(
                    "Proceed with AEM-specific checks when confidence is high; otherwise validate target stack first."
                ),
            )
        )

        return CheckOutcome(findings=findings, artifacts=[])
