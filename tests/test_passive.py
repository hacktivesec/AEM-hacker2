import unittest

from aem_audit_tool.checks.base import CheckContext
from aem_audit_tool.checks.passive import ComprehensiveExposureCheck
from aem_audit_tool.models import Fingerprint, HttpResult, ScanConfig


class FakeClient:
    base_url = "https://example.com/"

    def request(self, method, path, **kwargs):
        status = 403 if path.endswith("console") else 200
        return HttpResult(
            url=f"https://example.com{path}",
            status_code=status,
            headers={"Content-Type": "text/html"},
            text="ok" if status == 200 else "access denied",
            response_hash="deadbeef",
            error=None,
        )


class PassiveCheckTests(unittest.TestCase):
    def test_exposure_check_only_reports_success_statuses(self):
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
            active_tests=False,
            include_state_changing=False,
            profile="quick",
            include_checks=[],
            exclude_checks=[],
            json_out=None,
            md_out=None,
            dry_run=False,
        )

        ctx = CheckContext(client=FakeClient(), config=config, fingerprint=Fingerprint(True, 6, None, []))
        outcome = ComprehensiveExposureCheck().run(ctx)

        self.assertTrue(outcome.findings)
        self.assertTrue(all((f.evidence.status_code or 0) < 300 for f in outcome.findings))


if __name__ == "__main__":
    unittest.main()
