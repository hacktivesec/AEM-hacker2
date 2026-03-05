from __future__ import annotations

from typing import List

from .base import Check, CheckContext, CheckOutcome
from ..models import Evidence, Finding


class AuthenticatedAuditCheck(Check):
    check_id = "AEM-AUTH-001"
    name = "authenticated"
    tags = ["authenticated", "admin", "querybuilder", "package"]
    profiles = ["authenticated-deep"]
    requires_auth = True

    def run(self, ctx: CheckContext) -> CheckOutcome:
        if not ctx.fingerprint.is_likely_aem:
            return CheckOutcome(findings=[], artifacts=[])

        findings: List[Finding] = []
        probes = [
            ("/system/console/status-productinfo", "Authenticated access to product info"),
            ("/crx/packmgr/service.jsp?cmd=ls", "Authenticated package service listing capability"),
            (
                "/bin/querybuilder.json?path=/home/users&p.limit=5&p.hits=full",
                "Authenticated querybuilder access to user paths",
            ),
            ("/libs/granite/security/currentuser.json", "Authenticated current user API access"),
        ]

        for path, title in probes:
            result = ctx.client.request("GET", path)
            if result.error:
                continue
            if result.status_code == 200:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=title,
                        severity="medium",
                        category="authenticated_audit",
                        evidence=Evidence(
                            endpoint=result.url,
                            status_code=result.status_code,
                            response_hash=result.response_hash,
                            snippet=result.text[:180].replace("\n", " "),
                            rationale="Endpoint became accessible with provided credentials.",
                        ),
                        recommendation="Confirm role-based restrictions, least privilege, and audit logs for this operation.",
                        authenticated=True,
                    )
                )

        return CheckOutcome(findings=findings, artifacts=[])
