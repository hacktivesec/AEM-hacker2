import unittest

from aem_audit_tool.checks.base import Check, check_selected
from aem_audit_tool.checks.registry import get_all_checks


class DummyCheck(Check):
    check_id = "DUMMY-001"
    name = "dummy"
    tags = ["alpha", "beta"]
    profiles = ["standard"]

    def run(self, ctx):
        raise NotImplementedError


class SelectorTests(unittest.TestCase):
    def test_profile_filter(self):
        check = DummyCheck()
        self.assertFalse(check_selected(check, "quick", [], []))
        self.assertTrue(check_selected(check, "standard", [], []))

    def test_include_exclude(self):
        check = DummyCheck()
        self.assertTrue(check_selected(check, "standard", ["alpha"], []))
        self.assertFalse(check_selected(check, "standard", ["gamma"], []))
        self.assertFalse(check_selected(check, "standard", [], ["dummy"]))

    def test_registry_contains_edge_blocking_check(self):
        checks = get_all_checks()
        check_ids = {check.check_id for check in checks}
        self.assertIn("AEM-EDGE-001", check_ids)


if __name__ == "__main__":
    unittest.main()
