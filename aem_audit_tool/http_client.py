from __future__ import annotations

import hashlib
import threading
import time
from typing import Dict, Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.auth import HTTPBasicAuth

from .models import HttpResult, ReachabilityResult


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
                return HttpResult(
                    url=url,
                    status_code=response.status_code,
                    headers={k: v for k, v in response.headers.items()},
                    text=text,
                    response_hash=digest,
                    error=None,
                )
            except requests.exceptions.SSLError as exc:
                msg = (
                    f"TLS verification failed: {exc}. "
                    "If target/proxy uses self-signed certs, use --insecure or trust the CA."
                )
                return HttpResult(url=url, status_code=None, headers={}, text="", response_hash="-", error=msg)
            except requests.exceptions.ProxyError as exc:
                msg = (
                    f"Proxy connection failed: {exc}. "
                    "Verify proxy host/port, scheme, and CONNECT support for HTTPS or SSH tunnel forwarding."
                )
                return HttpResult(url=url, status_code=None, headers={}, text="", response_hash="-", error=msg)
            except requests.exceptions.InvalidSchema as exc:
                msg = (
                    f"Proxy/schema error: {exc}. For SOCKS support install requests[socks]."
                )
                return HttpResult(url=url, status_code=None, headers={}, text="", response_hash="-", error=msg)
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
                )
            except requests.RequestException as exc:
                return HttpResult(
                    url=url,
                    status_code=None,
                    headers={},
                    text="",
                    response_hash="-",
                    error=f"Request error: {exc}",
                )

        return HttpResult(url=url, status_code=None, headers={}, text="", response_hash="-", error="Unknown error")

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
