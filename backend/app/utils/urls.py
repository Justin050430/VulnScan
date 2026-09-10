"""URL parsing/normalisation and scan-scope helpers."""
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


def normalize_url(url):
    """Lowercase scheme/host, strip fragments, keep query parameters sorted."""
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    host = parsed.netloc.lower()
    path = parsed.path or "/"
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((scheme, host, path, "", query, ""))


def is_http_url(url):
    parsed = urlparse(url)
    return parsed.scheme.lower() in ("http", "https") and bool(parsed.netloc)


def is_static_resource(url):
    """Heuristic to skip binary/static resources during crawling."""
    path = urlparse(url).path.lower()
    static_exts = (
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp",
        ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar", ".mp4", ".mp3", ".avi",
        ".mov", ".webm", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    )
    # A bare extension at the end of the path => static resource.
    return any(path.endswith(ext) for ext in static_exts)


def extract_links(base_url, html):
    """Extract absolute http(s) links from an HTML document."""
    from html.parser import HTMLParser

    class _LinkParser(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.links = []

        def handle_starttag(self, tag, attrs):
            if tag not in ("a", "area", "frame", "iframe", "link"):
                return
            attrs = dict(attrs)
            href = attrs.get("href") or attrs.get("src")
            if href and href.strip():
                self.links.append(href.strip())

    parser = _LinkParser()
    try:
        parser.feed(html)
    except Exception:
        return []
    result = []
    for link in parser.links:
        absolute = urljoin(base_url, link)
        if is_http_url(absolute):
            result.append(absolute)
    return result
