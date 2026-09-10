"""
Hardened HTTP client used by the crawler and the detection modules.

Safety controls:
  * bounded timeouts and a maximum response body size (streamed),
  * configurable delay between requests (rate limiting),
  * manual redirect handling: every redirect target is validated by a
    caller-supplied validator before it is followed.  This prevents
    redirect-based SSRF and scope escape (a page cannot bounce the scanner to
    an internal address or a third-party host),
  * a single reusable session per scan; no cookie state is preserved for
    unrelated targets.
"""
import logging
import time
from urllib.parse import urljoin

import requests

logger = logging.getLogger("vulnscan.scanner")

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 VulnScan/1.0"
)

MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_REDIRECTS = 5
REDIRECT_CODES = (301, 302, 303, 307, 308)


class ScanResponse:
    """Normalised response wrapper returned to the scanner."""

    __slots__ = (
        "url",
        "final_url",
        "status_code",
        "headers",
        "text",
        "ok",
        "error",
        "history",
    )

    def __init__(self, url, final_url=None, status_code=None, headers=None,
                 text="", ok=False, error=None):
        self.url = url
        self.final_url = final_url or url
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text or ""
        self.ok = ok
        self.error = error
        self.history = []


class HttpClient:
    def __init__(self, timeout=10, delay_ms=0, verify_ssl=True,
                 user_agent=DEFAULT_USER_AGENT, max_body_bytes=MAX_BODY_BYTES,
                 max_redirects=MAX_REDIRECTS, url_validator=None):
        self.timeout = timeout
        self.delay = max(0, delay_ms / 1000.0)
        self.verify_ssl = verify_ssl
        self.max_body_bytes = max_body_bytes
        self.max_redirects = max_redirects
        # url_validator(target_url) -> (ok: bool, reason: str)
        self.url_validator = url_validator
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": user_agent})
        self._last_request_at = 0.0
        self.request_count = 0

    # ------------------------------------------------------------------ rate
    def _throttle(self):
        now = time.monotonic()
        elapsed = now - self._last_request_at
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request_at = time.monotonic()

    # ------------------------------------------------------------------ core
    def _read_body(self, resp):
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            chunks.append(chunk)
            total += len(chunk)
            if total > self.max_body_bytes:
                break
        body = b"".join(chunks)[: self.max_body_bytes]
        encoding = resp.encoding or "utf-8"
        try:
            return body.decode(encoding, errors="replace")
        except (LookupError, TypeError):
            return body.decode("utf-8", errors="replace")

    def _request(self, method, url, **kwargs):
        current = url
        redirects = 0
        history = []

        while True:
            self._throttle()
            self.request_count += 1
            try:
                resp = self._session.request(
                    method, current,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                    stream=True,
                    **kwargs,
                )
            except requests.exceptions.Timeout:
                return ScanResponse(url, final_url=current, error="Request timed out")
            except requests.exceptions.SSLError:
                return ScanResponse(url, final_url=current, error="SSL error")
            except requests.exceptions.ConnectionError:
                return ScanResponse(url, final_url=current, error="Connection error")
            except requests.exceptions.RequestException as exc:
                return ScanResponse(url, final_url=current, error=f"Request failed: {exc}")

            with resp:
                if resp.status_code in REDIRECT_CODES and resp.headers.get("Location"):
                    target = urljoin(current, resp.headers["Location"])
                    if redirects >= self.max_redirects:
                        return ScanResponse(
                            url, final_url=current, status_code=resp.status_code,
                            headers=dict(resp.headers), error="Too many redirects",
                        )
                    if self.url_validator is not None:
                        ok, reason = self.url_validator(target)
                        if not ok:
                            return ScanResponse(
                                url, final_url=current, status_code=resp.status_code,
                                headers=dict(resp.headers),
                                error=f"Blocked redirect to {target} ({reason})",
                            )
                    history.append(current)
                    if resp.status_code == 303 or (
                        resp.status_code in (301, 302) and method.upper() == "POST"
                    ):
                        method = "GET"
                        kwargs.pop("data", None)
                        kwargs.pop("json", None)
                    current = target
                    redirects += 1
                    continue

                result = ScanResponse(
                    url=url,
                    final_url=current,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    text=self._read_body(resp),
                    ok=True,
                )
                result.history = history
                return result

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def head(self, url, **kwargs):
        return self._request("HEAD", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, **kwargs)

    # ------------------------------------------------------------------ utils
    @staticmethod
    def is_html(response):
        ctype = (response.headers.get("Content-Type") or "").lower()
        return "html" in ctype or ctype.startswith("text/plain")

    def close(self):
        try:
            self._session.close()
        except Exception:
            pass
