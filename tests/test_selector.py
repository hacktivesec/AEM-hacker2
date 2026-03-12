import unittest

from aem_audit_tool.checks.base import CheckContext
from aem_audit_tool.checks.bypass import SelectorManipulationCheck
from aem_audit_tool.models import Fingerprint, HttpResult, ScanConfig


class FakeClient:
    base_url = "https://example.com/"

    def request(self, method, path, **kwargs):
        return HttpResult(
            url=f"https://example.com{path}",
            status_code=200,
            headers={"Content-Type": "text/html"},
            text="<html><head><title>Burp Suite Professional</title></head><body>Access Denied</body></html>",
            response_hash="deadbeef",
            error=None,
        )


class SelectorCheckTests(unittest.TestCase):
    def test_html_error_page_is_not_treated_as_selector_disclosure(self):
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
        outcome = SelectorManipulationCheck().run(ctx)

        self.assertEqual(len(outcome.findings), 0)


if __name__ == "__main__":
    unittest.main()
