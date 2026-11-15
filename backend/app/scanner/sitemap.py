"""
Bounded sitemap parsing for crawler discovery.

Only the two documented sitemap formats are understood: ``urlset`` (a list of
pages) and ``sitemapindex`` (a list of sitemaps).  Anything else - HTML soft
404s, RSS feeds, unknown roots - is rejected with a reason instead of being
guessed at.

Everything here is bounded so untrusted XML cannot consume the scan's memory or
CPU:

  * the document size is capped before parsing,
  * documents declaring a DTD or entities are rejected outright (no entity
    expansion, so "billion laughs" cannot be triggered),
  * only the direct children of the root element are read, so deeply nested
    input cannot cause deep recursion,
  * the number of URLs / child sitemaps taken from one file is capped.

The parser never raises anything but :class:`SitemapError`, and it performs no
network access; fetching and scope validation stay in the crawler.
"""
from xml.etree import ElementTree

#: Maximum sitemap document size accepted (1 MB).
MAX_SITEMAP_BYTES = 1024 * 1024
#: Maximum page URLs taken from a single urlset document.
MAX_URLS_PER_SITEMAP = 500
#: Maximum child sitemaps taken from a single sitemapindex document.
MAX_INDEX_CHILDREN = 10
#: Maximum sitemap files fetched during one crawl (robots declarations +
#: index children + the default location).
MAX_SITEMAPS_PER_CRAWL = 10
#: Sitemap location probed when robots.txt declares none.
DEFAULT_SITEMAP_PATH = "sitemap.xml"

FORBIDDEN_MARKERS = ("<!doctype", "<!entity")


class SitemapError(ValueError):
    """Raised when a sitemap document cannot be used safely."""


def local_name(tag):
    """Element tag without its XML namespace, lower-cased."""
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1].lower()


def parse_sitemap(text, max_urls=MAX_URLS_PER_SITEMAP,
                  max_children=MAX_INDEX_CHILDREN):
    """
    Parse a sitemap document.

    Returns ``(kind, locations, truncated)`` where kind is ``"urlset"`` or
    ``"sitemapindex"`` and truncated reports that more entries existed than the
    cap allowed.  Raises :class:`SitemapError` for anything unusable.
    """
    if not text:
        raise SitemapError("empty document")
    if len(text) > MAX_SITEMAP_BYTES:
        raise SitemapError(
            f"document exceeds the {MAX_SITEMAP_BYTES} byte limit"
        )

    lowered = text.lower()
    if any(marker in lowered for marker in FORBIDDEN_MARKERS):
        # A sitemap never needs a DTD; rejecting it keeps entity-expansion
        # attacks (XML bombs) impossible.
        raise SitemapError(
            "document type declarations and entities are not allowed"
        )

    try:
        # Bytes avoid ElementTree's "unicode strings with encoding declaration"
        # error; the body was already decoded by the HTTP client.
        root = ElementTree.fromstring(text.encode("utf-8", "replace"))
    except ElementTree.ParseError as exc:
        raise SitemapError(f"malformed XML ({exc})") from exc
    except ValueError as exc:  # pragma: no cover - defensive
        raise SitemapError(f"malformed XML ({exc})") from exc

    kind = local_name(root.tag)
    if kind == "urlset":
        child_tag, limit = "url", max_urls
    elif kind == "sitemapindex":
        child_tag, limit = "sitemap", max_children
    else:
        raise SitemapError(f"unsupported root element '{kind or 'unknown'}'")

    locations = []
    truncated = False
    for child in root:
        if local_name(child.tag) != child_tag:
            continue
        location = None
        for node in child:
            if local_name(node.tag) == "loc":
                location = (node.text or "").strip()
                break
        if not location:
            continue
        if len(locations) >= limit:
            truncated = True
            break
        locations.append(location)
    return kind, locations, truncated


def default_sitemap_url(origin):
    """The sitemap location probed when robots.txt declares none."""
    return f"{origin.rstrip('/')}/{DEFAULT_SITEMAP_PATH}"
