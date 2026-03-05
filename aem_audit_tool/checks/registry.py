from __future__ import annotations

from typing import List

from .active import ActiveSafetyCheck, StateChangingProbeCheck
from .authenticated import AuthenticatedAuditCheck
from .blocking import EdgeBlockingDetectionCheck
from .base import Check
from .bypass import (
    AdvancedDispatcherBypassCheck,
    LinkCheckerSSRFCheck,
    QueryBuilderDumpCheck,
    SelectorManipulationCheck,
    SlingPostServletCheck,
)
from .fingerprint import FingerprintCheck
from .passive import ComprehensiveExposureCheck, DispatcherBypassCheck, VulnerabilityClassCheck
from .cve_2025 import (
    CVE2025QueryBuilderCheck,
    CVE2025MSTokenSSRFCheck,
    CVE2025PackageMgrXXECheck,
    CVE2025ELInjectionCheck,
)
from .cve_legacy import (
    DefaultCredentialsCheck,
    WCMDebugFilterCheck,
    WCMSuggestionsCheck,
    SWFXSSCheck,
    SalesforceSSRFCheck,
    ReportingServicesSSRFCheck,
    SiteCatalystSSRFCheck,
    OpenSocialSSRFCheck,
    WebDAVExposureCheck,
    AuditLogServletCheck,
    ExternalJobDeserCheck,
)


def get_all_checks() -> list[Check]:
    return [
        # --- Pre-fingerprint edge/WAF detection ---
        EdgeBlockingDetectionCheck(),
        # --- Fingerprint (always runs first) ---
        FingerprintCheck(),
        # --- Passive surface exposure ---
        ComprehensiveExposureCheck(),
        VulnerabilityClassCheck(),
        # --- Dispatcher bypass (legacy + advanced) ---
        DispatcherBypassCheck(),
        AdvancedDispatcherBypassCheck(),
        # --- Selector & Sling info-disclosure ---
        SelectorManipulationCheck(),
        QueryBuilderDumpCheck(),
        # --- Active probes ---
        SlingPostServletCheck(),
        LinkCheckerSSRFCheck(),
        # --- Authenticated checks ---
        AuthenticatedAuditCheck(),
        ActiveSafetyCheck(),
        StateChangingProbeCheck(),
        # --- CVE-2025 (APSB25-90) ---
        CVE2025QueryBuilderCheck(),
        CVE2025MSTokenSSRFCheck(),
        CVE2025PackageMgrXXECheck(),
        CVE2025ELInjectionCheck(),
        # --- Legacy CVE checks (aem-hacker) ---
        DefaultCredentialsCheck(),
        WCMDebugFilterCheck(),
        WCMSuggestionsCheck(),
        SWFXSSCheck(),
        SalesforceSSRFCheck(),
        ReportingServicesSSRFCheck(),
        SiteCatalystSSRFCheck(),
        OpenSocialSSRFCheck(),
        WebDAVExposureCheck(),
        AuditLogServletCheck(),
        ExternalJobDeserCheck(),
    ]
