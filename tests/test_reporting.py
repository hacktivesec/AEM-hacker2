import unittest
from tempfile import NamedTemporaryFile

from aem_audit_tool.models import Evidence, Finding, Fingerprint, ScanReport
from aem_audit_tool.reporting import write_markdown


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

    def test_markdown_uses_validated_findings_and_omits_scoring_labels(self):
        report = ScanReport(
            generated_at_utc="2026-01-01T00:00:00Z",
            target="https://example.com",
            profile="standard",
            aem_fingerprint=Fingerprint(True, 6, "6.5.0", ["/:html_marker"]),
            reachability_error=None,
            findings=[
                Finding(
                    check_id="AEM-EDGE-001",
                    title="Reverse proxy/WAF blocking likely affecting scan coverage",
                    severity="high",
                    category="edge_blocking",
                    evidence=Evidence(
                        "https://example.com/system/console",
                        200,
                        "abcd",
                        "representative_path=/system/console",
                        "Differential behavior detected while sensitive probes were blocked.",
                    ),
                    recommendation="Validate origin access and rerun from an approved path.",
                ),
                Finding(
                    check_id="AEM-FP-001",
                    title="AEM fingerprint assessment",
                    severity="info",
                    category="fingerprint",
                    evidence=Evidence(
                        "https://example.com",
                        403,
                        "-",
                        "granite marker observed",
                        "Likely AEM=True. Detected version=6.5.0. Observed markers=1.",
                    ),
                    recommendation="Proceed with AEM-specific validation.",
                ),
            ],
            artifacts=[],
        )

        with NamedTemporaryFile("r+", encoding="utf-8") as handle:
            write_markdown(handle.name, report)
            handle.seek(0)
            content = handle.read()

        self.assertIn("# AEM Hacker Report", content)
        self.assertIn("## Validated Findings", content)
        self.assertNotIn("score=", content)
        self.assertNotIn("Severity:", content)
        self.assertNotIn("## Severity", content)
        self.assertNotIn("AEM fingerprint assessment", content)


if __name__ == "__main__":
    unittest.main()
