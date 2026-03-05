from __future__ import annotations

import concurrent.futures
from typing import List, Tuple

from .base import Check, CheckContext, CheckOutcome
from ..aem_endpoints import get_endpoints_for_profile
from ..models import Evidence, Finding


def _evidence(path: str, status: int | None, response_hash: str, text: str, rationale: str) -> Evidence:
    snippet = (text or "")[:180].replace("\n", " ")
    return Evidence(
        endpoint=path,
        status_code=status,
        response_hash=response_hash,
        snippet=snippet,
        rationale=rationale,
    )


# Severity mapping for endpoint categories
CATEGORY_SEVERITY = {
    "console": "high",
    "crx": "high",
    "packmgr": "critical",
    "replication": "high",
    "querybuilder": "medium",
    "granite": "medium",
    "sling": "medium",
    "acs_commons": "high",
    "groovy_console": "critical",
    "analytics": "medium",
    "cloudservices": "medium",
    "opensocial": "high",
    "mcm_salesforce": "high",
    "wcm": "medium",
    "dam": "medium",
    "admin_ui": "high",
    "reports": "medium",
    "content_paths": "low",
    "repository": "medium",
    "security": "medium",
    "cq_search": "low",
    "cq_forms": "high",
    "cq_other": "medium",
}


class ComprehensiveExposureCheck(Check):
    check_id = "AEM-EXP-001"
    name = "exposure"
    tags = ["osgi", "crx", "packmgr", "acs", "replication", "granite", "sling", "analytics", "cloudservices"]
    profiles = ["quick", "standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        if not ctx.fingerprint.is_likely_aem:
            return CheckOutcome(findings=[], artifacts=[])

        endpoints_by_category = get_endpoints_for_profile(ctx.config.profile)
        findings: List[Finding] = []

        # Flatten endpoints with category metadata
        probe_list: List[Tuple[str, str, str]] = []
        for category, paths in endpoints_by_category.items():
            severity = CATEGORY_SEVERITY.get(category, "medium")
            for path in paths:
                probe_list.append((path, category, severity))

        def probe(item: Tuple[str, str, str]) -> tuple[Tuple[str, str, str], object]:
            path, category, severity = item
            result = ctx.client.request("GET", path)
            return item, result

        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.config.workers) as pool:
            futures = [pool.submit(probe, item) for item in probe_list]
            for future in concurrent.futures.as_completed(futures):
                item, result = future.result()
                path, category, severity = item
                if result.error:
                    continue
                if result.status_code in (200, 201, 202, 204, 401, 403):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title=f"AEM {category} endpoint reachable",
                            severity=severity if result.status_code == 200 else "info",
                            category="aem_surface_exposure",
                            evidence=_evidence(
                                path=result.url,
                                status=result.status_code,
                                response_hash=result.response_hash,
                                text=result.text,
                                rationale=(
                                    f"AEM {category} endpoint is accessible (status={result.status_code}). "
                                    f"This surface may expose administrative or sensitive functionality."
                                ),
                            ),
                            recommendation=f"Restrict {category} endpoint access using dispatcher, ACL rules, and network controls.",
                        )
                    )

        return CheckOutcome(findings=findings, artifacts=[])


class DispatcherBypassCheck(Check):
    check_id = "AEM-DISP-001"
    name = "dispatcher-bypass"
    tags = ["dispatcher", "bypass"]
    profiles = ["deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        if not ctx.fingerprint.is_likely_aem:
            return CheckOutcome(findings=[], artifacts=[])

        variants = [
            "/system/console",
            "//system/console",
            "/system/console/",
            "/system/console%2e",
            "/content/..;/system/console",
        ]

        statuses = {}
        hashes = {}
        for path in variants:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            statuses[path] = result.status_code
            hashes[path] = result.response_hash

        findings: List[Finding] = []
        if statuses:
            baseline = statuses.get("/system/console")
            for path, code in statuses.items():
                if path == "/system/console" or baseline is None:
                    continue
                if code == 200 and baseline in (401, 403, 404):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Potential dispatcher bypass behavior",
                            severity="high",
                            category="dispatcher",
                            evidence=Evidence(
                                endpoint=path,
                                status_code=code,
                                response_hash=hashes[path],
                                snippet=f"baseline={baseline} variant={code}",
                                rationale=(
                                    "Variant path appears more permissive than baseline sensitive endpoint."
                                ),
                            ),
                            recommendation="Harden dispatcher/web-tier normalization and block encoded traversal variants.",
                        )
                    )

        return CheckOutcome(findings=findings, artifacts=[])


class VulnerabilityClassCheck(Check):
    check_id = "AEM-VCLASS-001"
    name = "vuln-classes"
    tags = ["cve", "ssrf", "xxe", "xss"]
    profiles = ["standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        if not ctx.fingerprint.is_likely_aem:
            return CheckOutcome(findings=[], artifacts=[])

        checks = [
            ("/libs/cq/ui/content/dumplibs.rebuild.html", "Potential sensitive maintenance servlet exposure", "medium"),
            ("/libs/cq/personalization/components/salesforce/clientcontextcloudconfig/content/config.json", "Potential Salesforce secret surface", "medium"),
            ("/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet", "Potential SiteCatalyst SSRF class surface", "high"),
            ("/libs/cq/forms/content/forms/af/guideInternalSubmitServlet", "Potential GuideInternalSubmitServlet XXE class surface", "high"),
            ("/etc/clientlibs/foundation/swfobject/swfobject.js", "SWF legacy attack surface indicator", "low"),
        ]

        findings: List[Finding] = []
        for path, title, sev in checks:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            if result.status_code in (200, 401, 403):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=title,
                        severity=sev if result.status_code == 200 else "info",
                        category="vulnerability_class",
                        evidence=_evidence(
                            path=result.url,
                            status=result.status_code,
                            response_hash=result.response_hash,
                            text=result.text,
                            rationale=(
                                "Endpoint associated with known historical AEM vulnerability classes is reachable. "
                                "This is a misconfiguration signal, not exploitation."
                            ),
                        ),
                        recommendation="Validate patch level and restrict endpoint exposure at dispatcher and ACL layers.",
                    )
                )

        return CheckOutcome(findings=findings, artifacts=[])
