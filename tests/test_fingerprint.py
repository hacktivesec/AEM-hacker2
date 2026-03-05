import unittest

from aem_audit_tool.checks.base import CheckContext
from aem_audit_tool.checks.fingerprint import FingerprintCheck
from aem_audit_tool.models import Fingerprint, HttpResult, ScanConfig


class FakeClient:
    base_url = "https://example.com/"

    def request(self, method, path, **kwargs):
        text = ""
        status = 404
        if path == "/":
            text = "Adobe Experience Manager"
            status = 200
        elif path == "/libs/granite/core/content/login.html":
            text = "granite login"
            status = 200
        return HttpResult(
            url=f"https://example.com{path}",
            status_code=status,
            headers={},
            text=text,
            response_hash="deadbeef",
            error=None,
        )


class FingerprintTests(unittest.TestCase):
    def test_aem_detected(self):
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
            profile="standard",
            include_checks=[],
            exclude_checks=[],
            json_out=None,
            md_out=None,
            dry_run=False,
        )
        fp = Fingerprint(False, 0, None, [])
        ctx = CheckContext(client=FakeClient(), config=config, fingerprint=fp)

        outcome = FingerprintCheck().run(ctx)

        self.assertTrue(ctx.fingerprint.is_likely_aem)
        self.assertGreaterEqual(ctx.fingerprint.confidence, 4)
        self.assertEqual(len(outcome.findings), 1)


if __name__ == "__main__":
    unittest.main()
