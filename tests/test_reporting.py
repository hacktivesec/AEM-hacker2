import unittest

from aem_audit_tool.models import Evidence, Finding, Fingerprint, ScanReport


class ReportingSummaryTests(unittest.TestCase):
    def test_summary_counts(self):
        report = ScanReport(
            generated_at_utc="2026-01-01T00:00:00Z",
            target="https://example.com",
            profile="standard",
            aem_fingerprint=Fingerprint(False, 0, None, []),
            reachability_error=None,
            findings=[
                Finding(
                    check_id="X",
                    title="x",
                    severity="high",
                    category="cat",
                    evidence=Evidence("/x", 200, "abcd", "snippet", "rationale"),
                    recommendation="fix",
                ),
                Finding(
                    check_id="Y",
                    title="y",
                    severity="info",
                    category="cat",
                    evidence=Evidence("/y", 200, "efgh", "snippet", "rationale"),
                    recommendation="fix",
                    authenticated=True,
                ),
            ],
            artifacts=[],
        )
        summary = report.summary()
        self.assertEqual(summary["total_findings"], 2)
        self.assertEqual(summary["authenticated_findings"], 1)
        self.assertEqual(summary["unauthenticated_findings"], 1)
        self.assertEqual(summary["severity_counts"]["high"], 1)
        self.assertFalse(summary["edge_blocking_detected"])
        self.assertEqual(summary["edge_blocking_findings"], 0)


if __name__ == "__main__":
    unittest.main()
