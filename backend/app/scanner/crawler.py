"""
Web Crawler - bounded, scope-restricted page discovery.

Crawling is limited by the scan profile (MaxDepth, MaxPages, RequestDelayMs)
and is restricted to the target's scope so that the scanner never issues
requests to arbitrary third-party websites:
  * same-origin pages are always in scope,
  * when the profile enables FollowExternalLinks the scope is expanded to the
    target's registrable domain (sub-domains), never arbitrary hosts.

Discovery sources, in the order their URLs are queued:

  1. the start URL (always requested, exactly once),
  2. ordinary links found in analysed pages,
  3. GET form actions found in analysed pages - forms are never submitted and
     POST actions are never fetched,
  4. URLs listed by the target's sitemap(s), including one level of
     sitemap-index nesting and Sitemap locations declared by robots.txt.

Every candidate URL - whatever discovered it - passes the same gate: it is
normalised, filtered for static/binary resources, checked against the target
scope, checked by the SSRF guard, checked against the crawl state for
duplicates, and finally checked against the target's robots.txt policy.

robots.txt is honoured as a crawl policy by default: a disallowed path is never
requested, whatever discovered it.  It is *not* an authorisation mechanism - it
can only remove URLs, never add them or widen the scope - and the scope/SSRF
checks (which also run on every redirect hop inside the HTTP client) still
apply.  The start URL is always requested because target ownership is
established separately from the crawl policy.
"""
import logging
from collections import deque
from urllib.parse import urljoin, urlparse

from app.scanner.base import PageInfo
from app.scanner.forms import form_signature, parse_forms
from app.scanner.robots import RobotsPolicy, fetch_policy
from app.scanner.sitemap import (
    MAX_SITEMAPS_PER_CRAWL,
    SitemapError,
    default_sitemap_url,
    parse_sitemap,
)
from app.utils.urls import (
    extract_links,
    is_http_url,
    is_static_resource,
    normalize_url,
)

logger = logging.getLogger("vulnscan.crawler")

#: Bound on the URLs recorded per exclusion category, so the discovery record
#: stays small however large the target is.
MAX_RECORDED_EXCLUSIONS = 25
#: Bound on a recorded URL's length (evidence only, never a request target).
MAX_RECORDED_URL_LENGTH = 300


def _trim(url):
    return (url or "")[:MAX_RECORDED_URL_LENGTH]


def _blank_discovery(max_pages, max_depth):
    """The discovery record for one crawl (persisted as a scan audit event)."""
    return {
        "Version": 1,
        "Sources": {"StartURL": 0, "Links": 0, "Sitemaps": 0, "FormActions": 0},
        "RobotsTxt": {
            "URL": None,
            "Fetched": False,
            "HTTPStatus": None,
            "Respected": True,
            "RulesApplied": 0,
            "SitemapDeclarations": [],
            "BlockedCount": 0,
            "Error": None,
        },
        "Sitemaps": {
            "Considered": 0,
            "UsedDefaultLocation": False,
            "Parsed": 0,
            "IndexFiles": 0,
            "URLsFound": 0,
            "URLsQueued": 0,
            "RejectedCount": 0,
            "Rejected": [],
            "Truncated": False,
        },
        "Excluded": {
            "RobotsBlockedCount": 0,
            "ScopeRejectedCount": 0,
            "StaticSkippedCount": 0,
            "Samples": {"Robots": [], "Scope": []},
        },
        "Limits": {
            "MaxPages": max_pages,
            "MaxDepth": max_depth,
            "PageBudgetReached": False,
        },
    }


class Crawler:
    def __init__(self, http=None, max_pages=30, max_depth=2, follow_external=False,
                 skip_url_contains=None, respect_robots=True,
                 discover_sitemaps=True, discover_form_actions=True):
        self.http = http
        self.max_pages = max(1, max_pages)
        self.max_depth = max(0, max_depth)
        self.follow_external = bool(follow_external)
        # Authenticated scans skip sign-out routes; following them would
        # destroy the session mid-crawl.
        self.skip_url_contains = tuple(
            token.lower() for token in (skip_url_contains or ())
        )
        # Site-wide forms appear on many pages; only the first instance is
        # attached to a page so its fields are tested once per scan.
        self._seen_form_signatures = set()
        # Discovery policy; robots.txt is honoured by default.
        self.respect_robots = bool(respect_robots)
        self.discover_sitemaps = bool(discover_sitemaps)
        self.discover_form_actions = bool(discover_form_actions)
        # State of the crawl in progress.
        self._seen = set()
        self._queue = deque()
        self._base_parsed = None
        self._robots = RobotsPolicy()
        #: Populated by crawl(); the engine records it as scan coverage.
        self.discovery = _blank_discovery(self.max_pages, self.max_depth)

    def dedupe_forms(self, forms):
        """Drop forms already seen on an earlier page of this crawl."""
        unique = []
        for form in forms:
            signature = form_signature(form)
            if signature in self._seen_form_signatures:
                continue
            self._seen_form_signatures.add(signature)
            unique.append(form)
        return tuple(unique)

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
        self._base_parsed = urlparse(start)
        origin = f"{self._base_parsed.scheme}://{self._base_parsed.netloc}"
        self._seen = set()
        self._queue = deque()
        self.discovery = _blank_discovery(self.max_pages, self.max_depth)

        self._robots = self._load_robots(origin)
        sitemap_candidates = self._discover_sitemap_urls(origin)

        pages = []
        order = 0
        self._seen.add(start)
        self._queue.append((start, 0, "StartURL"))
        self.discovery["Sources"]["StartURL"] = 1

        while self._queue and len(pages) < self.max_pages:
            url, depth, _source = self._queue.popleft()
            response = self.http.get(url)
            order += 1
            is_html = response.ok and self.http.is_html(response)
            parsed_forms = (
                parse_forms(response.final_url or url, response.text)
                if is_html
                else ()
            )
            page = PageInfo(
                url=url,
                depth=depth,
                order=order,
                http_status=response.status_code,
                title=_extract_title(response.text),
                error=response.error,
                forms=self.dedupe_forms(parsed_forms) if parsed_forms else (),
            )
            if response.ok:
                pages.append(page)
            elif depth == 0:
                # If the very first request fails, keep it so the scan can
                # report a failure meaningfully.
                pages.append(page)
            else:
                continue

            if (
                response.ok
                and depth < self.max_depth
                and len(pages) < self.max_pages
                and (is_html or response.status_code == 404)
            ):
                # Non-HTML (images, JS, APIs returning JSON) has no links.
                for link in extract_links(url, response.text):
                    self._accept(link, depth + 1, "Links")
                if self.discover_form_actions:
                    # Only GET actions are followed: forms are never submitted
                    # and POST endpoints are never requested.
                    for form in parsed_forms:
                        if form.method == "GET":
                            self._accept(form.action, depth + 1, "FormActions")

            if depth == 0 and sitemap_candidates:
                # Queued after the start page's own links so link discovery
                # keeps its priority under the page budget.
                for candidate in sitemap_candidates:
                    self._accept(candidate, 1, "Sitemaps")
                sitemap_candidates = []
                self.discovery["Sitemaps"]["URLsQueued"] = (
                    self.discovery["Sources"]["Sitemaps"]
                )

        self.discovery["Limits"]["PageBudgetReached"] = (
            bool(self._queue) and len(pages) >= self.max_pages
        )
        logger.info(
            "Crawler discovered %d page(s) for %s (sources: %s)",
            len(pages), start_url, self.discovery["Sources"],
        )
        return pages

    # ---------------------------------------------------------------- gates
    def _accept(self, url, depth, source):
        """
        Queue `url` when every discovery gate allows it.

        Returns True when the URL was queued.  Rejections are counted and, for
        the two categories the coverage report explains, sampled with a reason.
        """
        if depth > self.max_depth:
            return False
        try:
            absolute = normalize_url(url)
        except Exception:
            return False
        if not is_http_url(absolute):
            self._record_scope_rejection(url, "unsupported URL scheme")
            return False
        if absolute in self._seen:
            return False
        if is_static_resource(absolute):
            self.discovery["Excluded"]["StaticSkippedCount"] += 1
            return False
        if self._is_skipped_route(absolute):
            self._record_scope_rejection(
                absolute, "sign-out or login route skipped during a crawl"
            )
            return False
        ok, reason = self._validate_scope(absolute)
        if not ok:
            self._record_scope_rejection(absolute, reason)
            return False
        if self.respect_robots and self._robots.available:
            rule = self._robots.blocking_rule(urlparse(absolute).path or "/")
            if rule is not None:
                self._record_robots_block(absolute, rule)
                return False

        self._seen.add(absolute)
        self._queue.append((absolute, depth, source))
        if source in self.discovery["Sources"]:
            self.discovery["Sources"][source] += 1
        return True

    def _validate_scope(self, url):
        """Apply the same scope and SSRF rules used for redirect hops."""
        if self._base_parsed is None:
            return False, "outside the target scan scope"
        if not self.in_scope(url, self._base_parsed):
            return False, "outside the target scan scope"
        validator = getattr(self.http, "url_validator", None)
        if validator is not None:
            ok, reason = validator(url)
            if not ok:
                return False, reason
        return True, ""

    def _is_skipped_route(self, url):
        if not self.skip_url_contains:
            return False
        path = (urlparse(url).path or "").lower()
        return any(token in path for token in self.skip_url_contains)

    def _record_scope_rejection(self, url, reason):
        excluded = self.discovery["Excluded"]
        excluded["ScopeRejectedCount"] += 1
        samples = excluded["Samples"]["Scope"]
        if len(samples) < MAX_RECORDED_EXCLUSIONS:
            samples.append({"URL": _trim(url), "Reason": reason})

    def _record_robots_block(self, url, rule):
        self.discovery["RobotsTxt"]["BlockedCount"] += 1
        samples = self.discovery["Excluded"]["Samples"]["Robots"]
        if len(samples) < MAX_RECORDED_EXCLUSIONS:
            samples.append(
                {"URL": _trim(url), "Reason": f"disallowed by 'Disallow: {rule}'"}
            )

    # --------------------------------------------------------------- robots
    def _load_robots(self, origin):
        info = self.discovery["RobotsTxt"]
        if not self.respect_robots:
            info["Respected"] = False
            return RobotsPolicy()
        policy = fetch_policy(self.http, origin)
        info.update(
            {
                "URL": _trim(policy.url),
                "Fetched": policy.available,
                "HTTPStatus": policy.status,
                "RulesApplied": policy.rules_applied,
                "SitemapDeclarations": [
                    _trim(url) for url in policy.sitemaps
                ],
                "Error": policy.error,
            }
        )
        return policy

    # ------------------------------------------------------------- sitemaps
    def _discover_sitemap_urls(self, origin):
        """
        Return the page URLs listed by the target's sitemaps.

        robots.txt ``Sitemap:`` declarations are used when present, otherwise
        the conventional ``/sitemap.xml`` is probed once.  One level of
        sitemap-index nesting is followed.  Every sitemap - and every URL it
        lists - is scope/SSRF validated before it is fetched or queued, so a
        sitemap can never widen the crawl beyond the target.  Returning an
        unvalidated URL here is harmless: it is re-checked by _accept().
        """
        sitemaps = self.discovery["Sitemaps"]
        if not self.discover_sitemaps or self.max_depth < 1:
            return []

        reference = f"{origin}/"
        candidates = [
            urljoin_safe(reference, declared)
            for declared in self._robots.sitemaps
            if declared
        ]
        if not candidates:
            # Nothing declared: probe the conventional location once.
            candidates = [default_sitemap_url(origin)]
            sitemaps["UsedDefaultLocation"] = True
        sitemaps["Considered"] = len(candidates)

        found = []
        worklist = deque((url, 0) for url in candidates)
        visited = set()
        while worklist and sitemaps["Parsed"] < MAX_SITEMAPS_PER_CRAWL:
            url, level = worklist.popleft()
            if not is_http_url(url):
                self._reject_sitemap(url, "not an absolute http(s) URL")
                continue
            normalised = normalize_url(url)
            if normalised in visited:
                continue
            visited.add(normalised)
            ok, reason = self._validate_scope(normalised)
            if not ok:
                self._reject_sitemap(normalised, reason)
                continue
            response = self.http.get(normalised)
            if not response.ok:
                self._reject_sitemap(
                    normalised, response.error or "request failed"
                )
                continue
            if response.status_code != 200:
                self._reject_sitemap(normalised, f"HTTP {response.status_code}")
                continue
            try:
                kind, locations, truncated = parse_sitemap(response.text or "")
            except SitemapError as exc:
                self._reject_sitemap(normalised, str(exc))
                continue

            sitemaps["Parsed"] += 1
            sitemaps["Truncated"] = sitemaps["Truncated"] or truncated
            if kind == "sitemapindex":
                if level >= 1:
                    self._reject_sitemap(
                        normalised,
                        "nested sitemap index not followed (one level only)",
                    )
                    continue
                sitemaps["IndexFiles"] += 1
                for child in locations:
                    worklist.append((urljoin_safe(normalised, child), level + 1))
                continue

            sitemaps["URLsFound"] += len(locations)
            found.extend(locations)

        if worklist:
            # Hit the per-crawl sitemap cap with files still unread.
            sitemaps["Truncated"] = True
        return found

    def _reject_sitemap(self, url, reason):
        sitemaps = self.discovery["Sitemaps"]
        sitemaps["RejectedCount"] += 1
        if len(sitemaps["Rejected"]) < MAX_RECORDED_EXCLUSIONS:
            sitemaps["Rejected"].append({"URL": _trim(url), "Reason": reason})


def urljoin_safe(base, candidate):
    """Resolve `candidate` against `base` without raising on bad input."""
    try:
        return urljoin(base, (candidate or "").strip())
    except Exception:  # pragma: no cover - defensive
        return ""


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
