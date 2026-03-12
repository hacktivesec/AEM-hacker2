import unittest

from aem_audit_tool.checks.base import CheckContext
from aem_audit_tool.checks.bypass import AdvancedDispatcherBypassCheck
from aem_audit_tool.models import Fingerprint, HttpResult, ScanConfig


class FakeClient:
    base_url = "https://example.com/"

    def request(self, method, path, **kwargs):
        # Baselines are not found; mutated variants are blocked by edge (403).
        if path in {
            "/system/console",
            "/crx/de",
            "/crx/packmgr",
            "/bin/querybuilder.json",
            "/etc/replication",
            "/libs/granite/core/content/login.html",
        }:
            return HttpResult(
                url=f"https://example.com{path}",
                status_code=404,
                headers={"Server": "Apache"},
                text="Not Found",
                response_hash="baseline404",
                error=None,
            )

        return HttpResult(
            url=f"https://example.com{path}",
            status_code=403,
            headers={"Server": "AkamaiGHost"},
            text="Access Denied",
            response_hash="blocked403",
            error=None,
        )


class AdvancedBypassTests(unittest.TestCase):
    def test_403_variant_is_not_reported_as_bypass_vulnerability(self):
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
        outcome = AdvancedDispatcherBypassCheck().run(ctx)

        self.assertFalse(any(f.title.startswith("Dispatcher bypass via") for f in outcome.findings))


if __name__ == "__main__":
    unittest.main()
