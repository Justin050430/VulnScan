"""
Web Crawler - bounded, scope-restricted page discovery.

Crawling is limited by the scan profile (MaxDepth, MaxPages, RequestDelayMs)
and is restricted to the target's scope so that the scanner never issues
requests to arbitrary third-party websites:
  * same-origin pages are always in scope,
  * when the profile enables FollowExternalLinks the scope is expanded to the
    target's registrable domain (sub-domains), never arbitrary hosts.
"""
import logging
from collections import deque
from urllib.parse import urlparse

from app.scanner.base import PageInfo
from app.scanner.client import ScanResponse
from app.utils.urls import extract_links, is_static_resource, normalize_url

logger = logging.getLogger("vulnscan.crawler")


class Crawler:
    def __init__(self, http=None, max_pages=30, max_depth=2, follow_external=False):
        self.http = http
        self.max_pages = max(1, max_pages)
        self.max_depth = max(0, max_depth)
        self.follow_external = bool(follow_external)

    def in_scope(self, url, base_parsed):
        """Return True when url is within the target's scan scope."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.netloc.lower() == base_parsed.netloc.lower():
            return True
        if self.follow_external:
            return self._same_registrable_domain(parsed.netloc, base_parsed.netloc)
        return False

    @staticmethod
    def _same_registrable_domain(host_a, host_b):
        a = host_a.lower()
        b = host_b.lower()
        if a == b:
            return True
        if _is_ip(a) or _is_ip(b):
            return False
        def base(host):
            parts = host.split(".")
            if len(parts) <= 2:
                return host
            return ".".join(parts[-2:])
        return base(a) == base(b)

    def crawl(self, start_url):
        start = normalize_url(start_url)
        base_parsed = urlparse(start)
        pages = []
        seen = set()
        queue = deque()
        queue.append((start, 0))
        seen.add(start)
        order = 0

        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()
            response = self.http.get(url)
            order += 1
            page = PageInfo(
                url=url,
                depth=depth,
                order=order,
                http_status=response.status_code,
                title=_extract_title(response.text),
                error=response.error,
            )
            if response.ok:
                pages.append(page)
            elif depth == 0:
                # If the very first request fails, keep it so the scan can
                # report a failure meaningfully.
                pages.append(page)
                continue
            else:
                continue

            if depth >= self.max_depth or len(pages) >= self.max_pages:
                continue
            if not (self.http.is_html(response) or response.status_code == 404):
                # Non-HTML (images, JS, APIs returning JSON) - no links to follow.
                continue

            for link in extract_links(url, response.text):
                if len(pages) >= self.max_pages:
                    break
                try:
                    absolute = normalize_url(link)
                except Exception:
                    continue
                if not self.in_scope(absolute, base_parsed):
                    continue
                if is_static_resource(absolute):
                    continue
                if absolute in seen:
                    continue
                seen.add(absolute)
                queue.append((absolute, depth + 1))

        logger.info("Crawler discovered %d page(s) for %s", len(pages), start_url)
        return pages


def _is_ip(host):
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _extract_title(html):
    """Best-effort <title> extraction from an HTML document."""
    if not html:
        return None
    lower = html.lower()
    start = lower.find("<title")
    if start == -1:
        return None
    gt = html.find(">", start)
    end = lower.find("</title>", gt)
    if gt == -1 or end == -1:
        return None
    title = html[gt + 1 : end].strip()
    return title[:255] if title else None
