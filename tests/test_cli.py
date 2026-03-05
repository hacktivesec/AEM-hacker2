import unittest

from aem_audit_tool.cli import parse_args


class CliParsingTests(unittest.TestCase):
    def test_defaults(self):
        args = parse_args(["--target", "https://example.com"])
        self.assertEqual(args.profile, "standard")
        self.assertEqual(args.workers, 8)
        self.assertFalse(args.active_tests)
        self.assertIsNone(args.cookie)

    def test_cookie_flag_parsed(self):
        args = parse_args(
            ["--target", "https://example.com",
             "--cookie", "MRHSession=abc123; LastMRH_Session=abc123; F5_ST=xyz"]
        )
        self.assertIn("MRHSession", args.cookie)

    def test_state_changing_flag_parsed(self):
        args = parse_args(
            ["--target", "https://example.com", "--active-tests", "--include-state-changing"]
        )
        self.assertTrue(args.active_tests)
        self.assertTrue(args.include_state_changing)


if __name__ == "__main__":
    unittest.main()
