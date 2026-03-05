from __future__ import annotations


def markdown_matrix() -> str:
    rows = [
        ("Exposed DefaultGetServlet", "Partially implemented", "Indirect via exposure/fingerprint, not full path brute-force", "Add curated secret-path corpus with strict evidence thresholds"),
        ("Exposed QueryBuilderJson/Feed", "Implemented", "QueryBuilder JSON reachability and abuse-signal checks included", "Add feed servlet variant checks"),
        ("Exposed GQLServlet", "Partially implemented", "Not fully enumerated across historical GQL endpoints", "Add dedicated GQL endpoint/probe set"),
        ("Ability to create JCR nodes", "Implemented", "Explicit state-changing create/delete probe behind opt-in flags", "Add additional repository path profiles"),
        ("Exposed POSTServlet", "Implemented", "State-changing Sling POST probe with cleanup tracking", "Add per-tier policy baseline diff"),
        ("Exposed login/user info servlets", "Implemented", "Granite/Sling auth/user endpoints validated", "Expand to custom app auth surfaces"),
        ("Default credentials", "Not implemented yet", "Avoided brute-force style checks by safer default", "Add optional credential audit mode with strict rate limits and explicit legal warning"),
        ("Exposed Felix console", "Implemented", "Felix/OSGi admin surfaces checked", "Add authenticated role-validation checks"),
        ("WCMDebugFilter / WCMSuggestions", "Partially implemented", "Covered as vuln-class surface patterns only", "Add focused reflected-XSS-safe signal checks"),
        ("Exposed CRXDE/CRX", "Implemented", "CRXDE and CRX explorer checks included", "Add deeper ACL behavior verification"),
        ("Exposed reports", "Partially implemented", "Core admin/reporting-like paths covered, not exhaustive", "Add report endpoint pack"),
        ("SSRF: SalesforceSecretServlet", "Partially implemented", "Class-surface exposure detection only", "Add controlled out-of-band validator mode"),
        ("SSRF: ReportingServicesServlet", "Partially implemented", "Class-surface exposure baseline only", "Add safe callback validation option"),
        ("SSRF: Sitecatalyst/Autoprovisioning", "Partially implemented", "Surface checks only; no weaponization", "Add explicit lab-only SSRF callback module"),
        ("SSRF: Opensocial proxy/makeRequest", "Not implemented yet", "Not included in current safe baseline", "Add targeted checks with allowlisted callback domains"),
        ("SWF XSS", "Partially implemented", "Legacy SWF attack-surface indicator only", "Add SWF parameter reflection signatures"),
        ("Deser ExternalJobServlet", "Not implemented yet", "Not yet added", "Add non-exploit deserialization risk probe"),
        ("Exposed WebDAV", "Not implemented yet", "Not yet added", "Add WebDAV method/auth exposure checks"),
        ("Exposed Groovy Console", "Implemented", "Groovy console exposure explicitly checked", "Add auth role and execution lock checks"),
        ("Exposed ACS AEM Tools", "Implemented", "ACS admin surface exposure checked", "Add ACS tool-specific endpoint expansion"),
        ("GuideInternalSubmitServlet", "Implemented", "Vulnerability class endpoint presence checked", "Add safe request-shape validation"),
        ("MergeMetadataServlet / SetPreferences", "Not implemented yet", "Not yet added", "Add reflected input safety checks"),
    ]

    lines = [
        "# AEM Hacker Coverage Matrix",
        "",
        "| Capability (AEM Hacker) | Status | Reason | Next Step |",
        "|---|---|---|---|",
    ]
    for capability, status, reason, next_step in rows:
        lines.append(f"| {capability} | {status} | {reason} | {next_step} |")
    return "\n".join(lines) + "\n"
