from __future__ import annotations

import hashlib
import re
import threading
import time
from typing import Dict, Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.auth import HTTPBasicAuth

from .models import HttpResult, ReachabilityResult


_SOFT_404_PATTERNS = [
    "404 not found",
    "page not found",
    "object not found",
    "the specified resource does not exist",
]

_SOFT_403_PATTERNS = [
    "access denied",
    "403 forbidden",
    "request rejected",
    "the requested url was rejected",
]

_AEM_MARKERS = ["sling:", "jcr:", "cq:", "granite", "adobe experience manager"]


def _normalize_status_code(raw_status: int, headers: Dict[str, str], text: str) -> int:
    """Map misleading success statuses to blocked/not-found when body clearly indicates an error page."""
    if raw_status not in (200, 201, 202, 204):
        return raw_status

    body = (text or "")[:4000].lower()
    content_type = headers.get("content-type", "").lower()

    # Burp-generated HTML wrappers are not valid success responses from target AEM.
    if "burp suite professional" in body:
        if any(p in body for p in _SOFT_403_PATTERNS):
            return 403
        if any(p in body for p in _SOFT_404_PATTERNS):
            return 404
        return 404

    # Typical branded edge block pages often return 200 while functionally denying access.
    if any(p in body for p in _SOFT_403_PATTERNS):
        has_aem_markers = any(marker in body for marker in _AEM_MARKERS)
        if not has_aem_markers:
            return 403

    # Soft 404 pages returned as 200.
    if any(p in body for p in _SOFT_404_PATTERNS):
        if "text/html" in content_type or "<html" in body:
            return 404

    # Generic HTML from non-AEM tier for JSON/XML-style probes should not be treated as success.
    if "text/html" in content_type and "<html" in body and not any(marker in body for marker in _AEM_MARKERS):
        title_match = re.search(r"<title>(.*?)</title>", body, flags=re.I | re.S)
        if title_match:
            title = title_match.group(1)
            if "not found" in title:
                return 404
            if "forbidden" in title or "access denied" in title:
                return 403

    return raw_status


def _parse_cookie_string(raw: str) -> Dict[str, str]:
    """Parse a raw Cookie header string (e.g. 'MRHSession=abc; F5_ST=xyz') into a dict."""
    cookies: Dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


class HttpClient:
    def __init__(
        self,
        base_url: str,
        timeout: float,
        verify_ssl: bool,
        proxy: Optional[str],
        username: Optional[str],
        password: Optional[str],
        retries: int,
        backoff: float,
        rate_limit: float,
        cookie: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.retries = max(0, retries)
        self.backoff = max(0.0, backoff)
        self.rate_limit = max(0.0, rate_limit)

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent or "AEM-Audit-Pro/2.0"})
        if username and password:
            self.session.auth = HTTPBasicAuth(username, password)
        if cookie:
            # Inject as request-level cookies so they are sent on every request
            # and do not collide with any Set-Cookie values the server returns.
            self.session.cookies.update(_parse_cookie_string(cookie))
        if proxy:
            self._validate_proxy(proxy)
            self.session.proxies = {"http": proxy, "https": proxy}
            self.session.trust_env = False

        self._rate_lock = threading.Lock()
        self._last_request_ts = 0.0

    def _validate_proxy(self, proxy: str) -> None:
        parsed = urlparse(proxy)
        if parsed.scheme not in {"http", "https", "socks5", "socks5h"}:
            raise ValueError(
                "Unsupported proxy scheme. Use http://, https://, socks5:// or socks5h://"
            )
        if not parsed.hostname or not parsed.port:
            raise ValueError("Proxy must include host and port, e.g. http://127.0.0.1:8080")

    def _apply_rate_limit(self) -> None:
        if self.rate_limit <= 0:
            return
        min_interval = 1.0 / self.rate_limit
        with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_ts
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self._last_request_ts = time.monotonic()

    def request(self, method: str, path: str, **kwargs) -> HttpResult:
        url = urljoin(self.base_url, path.lstrip("/"))

        for attempt in range(self.retries + 1):
            self._apply_rate_limit()
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                    **kwargs,
                )
                text = response.text if response.text else ""
                snippet = text[:320]
                digest = hashlib.sha256(snippet.encode("utf-8", errors="ignore")).hexdigest()[:16]
                normalized_status = _normalize_status_code(
                    raw_status=response.status_code,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    text=text,
                )
                return HttpResult(
                    url=url,
                    status_code=normalized_status,
                    headers={k: v for k, v in response.headers.items()},
                    text=text,
                    response_hash=digest,
                    error=None,
                    raw_status_code=response.status_code,
                )
            except requests.exceptions.SSLError as exc:
                msg = (
                    f"TLS verification failed: {exc}. "
                    "If target/proxy uses self-signed certs, use --insecure or trust the CA."
                )
                return HttpResult(url=url, status_code=None, headers={}, text="", response_hash="-", error=msg, raw_status_code=None)
            except requests.exceptions.ProxyError as exc:
                msg = (
                    f"Proxy connection failed: {exc}. "
                    "Verify proxy host/port, scheme, and CONNECT support for HTTPS or SSH tunnel forwarding."
                )
                return HttpResult(url=url, status_code=None, headers={}, text="", response_hash="-", error=msg, raw_status_code=None)
            except requests.exceptions.InvalidSchema as exc:
                msg = (
                    f"Proxy/schema error: {exc}. For SOCKS support install requests[socks]."
                )
                return HttpResult(url=url, status_code=None, headers={}, text="", response_hash="-", error=msg, raw_status_code=None)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                if attempt < self.retries:
                    time.sleep(self.backoff * (2**attempt))
                    continue
                return HttpResult(
                    url=url,
                    status_code=None,
                    headers={},
                    text="",
                    response_hash="-",
                    error=f"Network error: {exc}",
                    raw_status_code=None,
                )
            except requests.RequestException as exc:
                return HttpResult(
                    url=url,
                    status_code=None,
                    headers={},
                    text="",
                    response_hash="-",
                    error=f"Request error: {exc}",
                    raw_status_code=None,
                )

        return HttpResult(url=url, status_code=None, headers={}, text="", response_hash="-", error="Unknown error", raw_status_code=None)

    def preflight(self) -> ReachabilityResult:
        result = self.request("GET", "/")
        if result.error:
            return ReachabilityResult(ok=False, message=result.error)
        return ReachabilityResult(ok=True, message=f"Reachable: HTTP {result.status_code}")


def build_headers(extra_headers: Optional[list[str]]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    if not extra_headers:
        return parsed
    for header in extra_headers:
        if ":" not in header:
            continue
        key, value = header.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed
