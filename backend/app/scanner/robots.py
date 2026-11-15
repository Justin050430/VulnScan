"""
robots.txt crawl-policy handling.

robots.txt is a crawl *policy*, not an authorisation.  Honouring it can only
remove URLs from the crawl: it never widens the scan scope, and every URL it
permits must still pass the target-scope and SSRF checks (including on every
redirect hop).  A permissive robots.txt therefore cannot make the scanner
contact anything it would not otherwise have contacted.

Only the rule groups that apply to this crawler are kept (``*`` and any group
naming the VulnScan product token).  Matching follows RFC 9309: the longest
matching path wins and ``Allow`` wins a tie, with ``*`` and a trailing ``$``
supported.  Parsing is bounded so a pathological file cannot affect the scan.
"""
import logging
import re
from urllib.parse import urljoin

logger = logging.getLogger("vulnscan.crawler.robots")

#: A robots.txt larger than this is ignored (treated as "no policy").
MAX_ROBOTS_BYTES = 512 * 1024
#: Bound on compiled rules so path matching stays cheap.
MAX_ROBOTS_RULES = 500
#: Product token used to match User-agent groups.
ROBOTS_USER_AGENT = "vulnscan"
#: Bound on the Sitemap declarations kept from one file.
MAX_SITEMAP_DECLARATIONS = 20


class RobotsPolicy:
    """The part of a robots.txt file that applies to this crawler."""

    def __init__(self, url=None, status=None, available=False, sitemaps=(),
                 rules=(), error=None):
        self.url = url
        self.status = status
        self.available = bool(available)
        self.sitemaps = list(sitemaps)
        self.error = error
        #: ``(allow, pattern, compiled_regex)`` triples.
        self._rules = list(rules)

    @property
    def rules_applied(self):
        return len(self._rules)

    def blocking_rule(self, path):
        """Return the winning ``Disallow`` pattern for `path`, or None."""
        winner = self._match(path)
        if winner is None or winner[0]:
            return None
        return winner[1]

    def allows(self, path):
        """True when `path` is not disallowed for this crawler."""
        return self.blocking_rule(path) is None

    def _match(self, path):
        if not self._rules:
            return None
        candidate = path or "/"
        best = None
        for allow, pattern, regex in self._rules:
            if not regex.match(candidate):
                continue
            length = len(pattern)
            if best is None or length > best[2] or (length == best[2] and allow):
                best = (allow, pattern, length)
        if best is None:
            return None
        return best[0], best[1]

    def __repr__(self):
        return (
            f"<RobotsPolicy available={self.available} "
            f"rules={len(self._rules)} sitemaps={len(self.sitemaps)}>"
        )


def _compile(pattern):
    """Compile a robots pattern (``*`` wildcard, optional ``$`` anchor)."""
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    regex = re.escape(body).replace(r"\*", ".*")
    return re.compile("^" + regex + ("$" if anchored else ""))


def _applies_to_crawler(agents, user_agent):
    for agent in agents:
        if agent == "*" or user_agent in agent:
            return True
    return False


def parse_robots(text, url=None, status=None, user_agent=ROBOTS_USER_AGENT,
                 max_rules=MAX_ROBOTS_RULES):
    """
    Parse robots.txt `text` into a RobotsPolicy for this crawler.

    Never raises: unparsable content simply yields a policy with no rules.
    """
    sitemaps = []
    rules = []
    groups = []
    agents = []
    group_rules = []

    for raw_line in (text or "").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()

        if field == "sitemap":
            # Sitemap directives are not group-scoped and may repeat.
            if value and value not in sitemaps:
                sitemaps.append(value)
            continue

        if field == "user-agent":
            if group_rules:
                groups.append((agents, group_rules))
                agents, group_rules = [], []
            if value:
                agents.append(value.lower())
            continue

        if field in ("allow", "disallow"):
            if not agents:
                # A rule before any User-agent line belongs to no group.
                continue
            if not value and field == "disallow":
                # "Disallow:" with an empty value means "allow everything".
                continue
            group_rules.append((field == "allow", value))

    if agents:
        groups.append((agents, group_rules))

    seen = set()
    for group_agents, raw_rules in groups:
        if not _applies_to_crawler(group_agents, user_agent):
            continue
        for allow, pattern in raw_rules:
            key = (allow, pattern)
            if key in seen:
                continue
            seen.add(key)
            rules.append((allow, pattern, _compile(pattern)))
            if len(rules) >= max_rules:
                break
        if len(rules) >= max_rules:
            break

    return RobotsPolicy(
        url=url,
        status=status,
        available=True,
        sitemaps=sitemaps[:MAX_SITEMAP_DECLARATIONS],
        rules=rules,
    )


def _looks_like_html(text):
    head = (text or "")[:1024].lower()
    return "<html" in head or "<!doctype html" in head


def fetch_policy(http, origin, user_agent=ROBOTS_USER_AGENT):
    """
    Retrieve and parse ``<origin>/robots.txt`` through the scan's HTTP client.

    The request goes through the same client (and therefore the same scope and
    SSRF validation, including redirects) as every other scan request.  An
    unreachable or unusable robots.txt yields an empty policy - RFC 9309 treats
    a missing policy as "no restrictions" - with the reason recorded.
    """
    url = urljoin(origin.rstrip("/") + "/", "robots.txt")
    try:
        response = http.get(url)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("robots.txt request failed for %s: %s", url, exc)
        return RobotsPolicy(url=url, error="request failed")

    if not response.ok:
        return RobotsPolicy(
            url=url,
            status=response.status_code,
            error=response.error or "request failed",
        )
    if response.status_code != 200:
        return RobotsPolicy(url=url, status=response.status_code)

    text = response.text or ""
    if len(text) > MAX_ROBOTS_BYTES:
        return RobotsPolicy(
            url=url, status=200, error="file exceeds the size limit"
        )
    if _looks_like_html(text):
        return RobotsPolicy(
            url=url, status=200, error="response was HTML, not robots.txt"
        )
    return parse_robots(text, url=url, status=200, user_agent=user_agent)
