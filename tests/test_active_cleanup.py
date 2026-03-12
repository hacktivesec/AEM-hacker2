import unittest

from aem_audit_tool.checks.active import StateChangingProbeCheck
from aem_audit_tool.checks.base import CheckContext
from aem_audit_tool.models import Fingerprint, HttpResult, ScanConfig


class FakeClient:
    base_url = "https://example.com/"

    def request(self, method, path, **kwargs):
        data = kwargs.get("data") or {}

        if method == "POST" and path.startswith("/content/aem-audit-probe-") and data.get(":operation") == "delete":
            return HttpResult(
                url=f"https://example.com{path}",
                status_code=200,
                headers={"Content-Type": "text/html"},
                text="delete accepted",
                response_hash="delhash",
                error=None,
            )

        if method == "POST" and path.startswith("/content/aem-audit-probe-"):
            return HttpResult(
                url=f"https://example.com{path}",
                status_code=201,
                headers={"Content-Type": "text/plain"},
                text="created",
                response_hash="createhash",
                error=None,
            )

        if method == "GET" and path.startswith("/content/aem-audit-probe-"):
            return HttpResult(
                url=f"https://example.com{path}",
                status_code=404,
                headers={"Content-Type": "text/html"},
                text="not found",
                response_hash="verifyhash",
                error=None,
            )

        return HttpResult(
            url=f"https://example.com{path}",
            status_code=404,
            headers={},
            text="",
            response_hash="x",
            error=None,
        )


class ActiveCleanupTests(unittest.TestCase):
    def test_cleanup_result_uses_post_delete_verification_status(self):
        config = ScanConfig(
            target="https://example.com",
            username=None,
            password=None,
            proxy=None,
            timeout=5,
            verify_ssl=True,
            workers=2,
            rate_limit=5,
            retries=1,
            backoff=0.1,
            active_tests=True,
            include_state_changing=True,
            profile="deep",
            include_checks=[],
            exclude_checks=[],
            json_out=None,
            md_out=None,
            dry_run=False,
        )

        ctx = CheckContext(client=FakeClient(), config=config, fingerprint=Fingerprint(False, 0, None, []))
        outcome = StateChangingProbeCheck().run(ctx)

        cleanup_finding = next(f for f in outcome.findings if f.check_id == "AEM-ACT-101")
        self.assertEqual(cleanup_finding.evidence.status_code, 404)
        self.assertEqual(cleanup_finding.severity, "info")


if __name__ == "__main__":
    unittest.main()
