import unittest

from aem_audit_tool.http_client import _normalize_status_code


class HttpClientNormalizationTests(unittest.TestCase):
    def test_normalizes_burp_html_success_to_not_found(self):
        body = "<html><head><title>Burp Suite Professional</title></head><body>404 Not Found</body></html>"
        status = _normalize_status_code(200, {"content-type": "text/html"}, body)
        self.assertEqual(status, 404)

    def test_normalizes_soft_access_denied_success_to_forbidden(self):
        body = "<html><head><title>Access Denied</title></head><body>The requested URL was rejected</body></html>"
        status = _normalize_status_code(200, {"content-type": "text/html"}, body)
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
