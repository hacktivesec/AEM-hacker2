from __future__ import annotations

import uuid
from typing import List

from .base import Check, CheckContext, CheckOutcome
from ..models import ActionArtifact, Evidence, Finding


class ActiveSafetyCheck(Check):
    check_id = "AEM-ACT-001"
    name = "active-safe"
    tags = ["active", "csrf"]
    profiles = ["standard", "deep", "authenticated-deep"]
    active = True

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []
        token = ctx.client.request("GET", "/libs/granite/csrf/token.json")
        if token.error:
            return CheckOutcome(findings=[], artifacts=[])
        if token.status_code == 200 and "token" in token.text.lower():
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="CSRF token endpoint reachable",
                    severity="info",
                    category="active_testing",
                    evidence=Evidence(
                        endpoint=token.url,
                        status_code=token.status_code,
                        response_hash=token.response_hash,
                        snippet=token.text[:160].replace("\n", " "),
                        rationale="Token endpoint responded; verify enforcement for state-changing operations.",
                    ),
                    recommendation="Confirm CSRF token validation is mandatory for POST/PUT/DELETE operations.",
                )
            )
        return CheckOutcome(findings=findings, artifacts=[])


class StateChangingProbeCheck(Check):
    check_id = "AEM-ACT-100"
    name = "state-changing"
    tags = ["active", "state-changing", "sling-post"]
    profiles = ["deep", "authenticated-deep"]
    active = True
    state_changing = True

    def run(self, ctx: CheckContext) -> CheckOutcome:
        findings: List[Finding] = []
        artifacts: List[ActionArtifact] = []

        probe_name = f"aem-audit-probe-{uuid.uuid4().hex[:8]}"
        target_path = f"/content/{probe_name}"

        create_resp = ctx.client.request(
            "POST",
            target_path,
            data={
                "jcr:primaryType": "nt:unstructured",
                "auditMarker": "AEM_AUDIT",
                "createdByTool": "aem_audit_tool",
            },
        )

        if create_resp.error:
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="State-changing create probe failed",
                    severity="medium",
                    category="active_testing",
                    evidence=Evidence(
                        endpoint=create_resp.url,
                        status_code=create_resp.status_code,
                        response_hash=create_resp.response_hash,
                        snippet=create_resp.error,
                        rationale="Write probe was attempted under explicit flag and failed safely.",
                    ),
                    recommendation="Review ACL and CSRF enforcement for Sling POST servlet.",
                    state_changing=True,
                )
            )
            artifacts.append(
                ActionArtifact(
                    action_id="AEM-ACT-101",
                    description="Create probe artifact",
                    artifact_path=target_path,
                    cleanup_attempted=False,
                    cleanup_success=False,
                    notes=create_resp.error,
                )
            )
            return CheckOutcome(findings=findings, artifacts=artifacts)

        created = create_resp.status_code in (200, 201, 204)
        findings.append(
            Finding(
                check_id=self.check_id,
                title="State-changing create probe executed",
                severity="high" if created else "medium",
                category="active_testing",
                evidence=Evidence(
                    endpoint=create_resp.url,
                    status_code=create_resp.status_code,
                    response_hash=create_resp.response_hash,
                    snippet=create_resp.text[:160].replace("\n", " "),
                    rationale="Create probe verifies whether unexpected write is permitted.",
                ),
                recommendation="If write succeeds unexpectedly, harden publish-tier ACL and dispatcher filters.",
                state_changing=True,
            )
        )

        delete_resp = ctx.client.request("POST", target_path, data={":operation": "delete"})
        verify_resp = ctx.client.request("GET", target_path)
        removed = verify_resp.status_code in (401, 403, 404)
        cleanup_success = not verify_resp.error and removed
        cleanup_note = (
            f"delete_status={delete_resp.status_code}; verify_status={verify_resp.status_code}; removed={removed}"
            if not delete_resp.error and not verify_resp.error
            else f"delete_error={delete_resp.error}; verify_error={verify_resp.error}"
        )

        findings.append(
            Finding(
                check_id="AEM-ACT-101",
                title="State-changing cleanup result",
                severity="info" if cleanup_success else "high",
                category="active_testing",
                evidence=Evidence(
                    endpoint=verify_resp.url,
                    status_code=verify_resp.status_code,
                    response_hash=verify_resp.response_hash,
                    snippet=verify_resp.text[:160].replace("\n", " "),
                    rationale=(
                        "Cleanup probe verifies post-delete node state. "
                        f"delete_status={delete_resp.status_code}; verify_status={verify_resp.status_code}; removed={removed}."
                    ),
                ),
                recommendation=(
                    "No action required beyond repository verification."
                    if cleanup_success
                    else "Manual cleanup required; verify and remove temporary node under /content."
                ),
                state_changing=True,
            )
        )

        artifacts.append(
            ActionArtifact(
                action_id="AEM-ACT-102",
                description="Create/delete probe artifact",
                artifact_path=target_path,
                cleanup_attempted=True,
                cleanup_success=cleanup_success,
                notes=cleanup_note,
            )
        )

        return CheckOutcome(findings=findings, artifacts=artifacts)
