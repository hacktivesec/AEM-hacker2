import unittest

from aem_audit_tool.checks.base import CheckContext
from aem_audit_tool.checks.blocking import EdgeBlockingDetectionCheck
from aem_audit_tool.models import Fingerprint, HttpResult, ScanConfig


class FakeClient:
    base_url = "https://example.com/"

    def request(self, method, path, **kwargs):
        if path in {"/", "/robots.txt", "/favicon.ico"}:
            return HttpResult(
                url=f"https://example.com{path}",
                status_code=200,
                headers={"Server": "Apache"},
                text="ok",
                response_hash="goodhash",
                error=None,
            )

        if path.startswith("/aem-audit-"):
            return HttpResult(
                url=f"https://example.com{path}",
                status_code=404,
                headers={"Server": "Apache"},
                text="Not Found",
                response_hash="random404",
                error=None,
            )

        return HttpResult(
            url=f"https://example.com{path}",
            status_code=403,
            headers={
                "Server": "BigIP",
                "X-Cnection": "close",
                "Set-Cookie": "BIGipServerPOOL=123456.20480.0000; path=/",
            },
            text="The requested URL was rejected. Please consult with your administrator. Support ID: 12345",
            response_hash="blockhash",
            error=None,
        )


class EdgeBlockingTests(unittest.TestCase):
    def test_detects_edge_blocking_and_bigip_signatures(self):
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

        ctx = CheckContext(client=FakeClient(), config=config, fingerprint=Fingerprint(False, 0, None, []))
        outcome = EdgeBlockingDetectionCheck().run(ctx)

        self.assertGreaterEqual(len(outcome.findings), 1)
        self.assertTrue(any(f.check_id == "AEM-EDGE-001" for f in outcome.findings))
        self.assertTrue(any(f.category == "edge_blocking" for f in outcome.findings))
        self.assertTrue(any("BIG-IP" in f.title for f in outcome.findings))


if __name__ == "__main__":
    unittest.main()
