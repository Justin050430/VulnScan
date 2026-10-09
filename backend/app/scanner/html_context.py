"""
HTML reflection-context analysis for reflected-XSS detection.

Decides *where* an unencoded reflection lands in the document and whether it
can alter the parsed markup or script from that position - the property that
separates an exploitable reflection from a harmless echo.

Contexts recognised (OWASP XSS Prevention / PortSwigger context taxonomy):
  * HTML text content  - executable when the payload can open a new tag.
  * attribute value    - executable only when the payload breaks out of the
                         attribute (matching quote; whitespace or '>' for an
                         unquoted value) and injects markup or an event-handler
                         attribute; a javascript: value in a URL attribute is
                         executable without a breakout.
  * raw-text elements  - <script>/<style>/<textarea>/<title>/<xmp>/<noscript>/
                         <template>: executable only when the payload closes
                         the element and opens new markup; a raw reflection in
                         a <script> block that cannot be shown to break out is
                         reported as *suspected* (JS-string quoting is not
                         analysed).
  * HTML comment       - never executable.

The analysis is static (no browser is launched); it proves what the browser
parser would do with the reflected markup, not that a client-side control
(WAF, sanitizer, CSP) would let it run.
"""
import re
from dataclasses import dataclass
from typing import Optional

_RAW_TEXT_ELEMENTS = (
    "script", "style", "textarea", "title", "xmp", "noscript", "template",
)
_URL_ATTRIBUTES = (
    "href", "src", "action", "formaction", "data", "poster", "xlink:href",
)

_TAG_START_RE = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9:-]*)")
_ATTR_RE = re.compile(
    r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(\"[^\"]*\"|'[^']*'|[^\s>]*))?"
)
_MARKUP_RE = re.compile(r"<\s*[a-zA-Z!/]")
_EVENT_ATTR_RE = re.compile(r"(?i)on[a-z]+\s*=|autofocus|onerror\s*=")


@dataclass
class ReflectionContext:
    """Where a reflected payload appears and whether it can execute."""

    context: str                      # 'text' | 'attribute' | 'comment' | 'raw_text'
    element: Optional[str] = None     # enclosing element name when known
    attribute: Optional[str] = None
    quote: Optional[str] = None       # '"' | "'" | None (unquoted attribute)
    breakout: bool = False
    executable: bool = False
    suspected: bool = False           # raw reflection in a <script> block that
                                      # cannot be shown to break out
    description: str = ""


def classify_reflection(body: str, payload: str) -> Optional[ReflectionContext]:
    """Classify where `payload` sits in `body`, or None if not reflected."""
    if not body or not payload:
        return None
    index = body.find(payload)
    if index == -1:
        return None

    # ---- HTML comment context -------------------------------------------
    comment_start = body.rfind("<!--", 0, index)
    if comment_start != -1:
        comment_end = body.find("-->", comment_start)
        if comment_end == -1 or comment_end > index:
            return ReflectionContext(
                context="comment",
                description="inside an HTML comment (treated as inert text by "
                            "the browser; not executable)",
            )

    # ---- sequential scan up to the payload ------------------------------
    pos = 0
    while pos < index:
        lt = body.find("<", pos)
        if lt == -1 or lt >= index:
            break  # payload is in text content between tags

        if body.startswith("<!--", lt):
            end = body.find("-->", lt + 4)
            if end == -1:
                break
            pos = end + 3
            continue

        match = _TAG_START_RE.match(body, lt)
        if not match:
            pos = lt + 1
            continue
        name = match.group(1).lower()
        tag_end = _find_tag_end(body, lt)
        if tag_end == -1:
            tag_end = len(body)

        if lt <= index <= tag_end:
            return _attribute_context(body, lt, tag_end, name, index, payload)

        tag_text = body[lt:tag_end + 1]
        if name in _RAW_TEXT_ELEMENTS and not tag_text.rstrip().endswith("/>"):
            close = re.search(r"</\s*" + re.escape(name) + r"\b", body[tag_end + 1:] or " ",
                              re.IGNORECASE)
            close_start = (tag_end + 1) + close.start() if close else len(body)
            close_end = body.find(">", close_start)
            if close_end == -1:
                close_end = len(body)
            if tag_end < index <= close_start:
                return _raw_text_context(name, payload)
            if close_start < index <= close_end:
                return _attribute_context(body, close_start, close_end,
                                          "/" + name, index, payload)
            pos = close_end + 1
            continue

        pos = tag_end + 1

    # ---- plain text content ---------------------------------------------
    has_markup = bool(_MARKUP_RE.search(payload))
    return ReflectionContext(
        context="text",
        breakout=has_markup,
        executable=has_markup,
        description="in HTML text content; the payload can open new markup "
                    "elements" if has_markup else
                    "in HTML text content; the payload cannot open new markup "
                    "elements (no tag start present)",
    )


def _find_tag_end(body: str, start: int) -> int:
    quote = None
    i = start + 1
    while i < len(body):
        char = body[i]
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == ">":
            return i
        i += 1
    return -1


def _attribute_context(body, tag_start, tag_end, name, index, payload):
    tag_text = body[tag_start:tag_end + 1]
    offset = index - tag_start
    for match in _ATTR_RE.finditer(tag_text):
        raw_value = match.group(2)
        if raw_value is None:
            continue
        if match.start(2) <= offset <= match.end(2):
            attribute = match.group(1).lower()
            if raw_value.startswith('"'):
                quote = '"'
            elif raw_value.startswith("'"):
                quote = "'"
            else:
                quote = None
            if quote:
                breakout = quote in payload
            else:
                breakout = bool(re.search(r"[\s>]", payload))
            has_markup = bool(_MARKUP_RE.search(payload))
            injects_event = bool(_EVENT_ATTR_RE.search(payload))
            javascript_url = (
                attribute in _URL_ATTRIBUTES
                and payload.lstrip().lower().startswith("javascript:")
            )
            executable = javascript_url or (breakout and (has_markup or injects_event))
            pieces = [
                f"inside the '{attribute}' attribute value of <{name.lstrip('/')}>",
                "quoted with " + (quote or "no quote (unquoted)"),
            ]
            if breakout:
                pieces.append("payload breaks out of the attribute")
            else:
                pieces.append("payload does NOT break out of the attribute")
            if has_markup:
                pieces.append("and injects new markup")
            elif injects_event:
                pieces.append("and injects an event-handler attribute")
            if javascript_url:
                pieces.append("javascript: URL scheme")
            return ReflectionContext(
                context="attribute",
                element=name.lstrip("/"),
                attribute=attribute,
                quote=quote,
                breakout=breakout,
                executable=executable,
                description="; ".join(pieces),
            )
    # Inside a tag but not inside a recognised attribute value.
    return ReflectionContext(
        context="attribute",
        element=name.lstrip("/"),
        description=f"inside the <{name.lstrip('/')}> tag (attribute value "
                    f"could not be determined)",
        executable=False,
    )


def _raw_text_context(name, payload):
    terminator = re.search(
        r"</\s*" + re.escape(name) + r"\s*>\s*<", payload, re.IGNORECASE
    )
    closes = re.search(r"</\s*" + re.escape(name), payload, re.IGNORECASE)
    executable = bool(terminator)
    suspected = name == "script" and not executable
    if executable:
        description = (f"inside a <{name}> raw-text block; the payload closes "
                       f"the element and opens new markup")
    elif closes:
        description = (f"inside a <{name}> raw-text block; the payload closes "
                       f"the element but does not open new markup")
    else:
        description = (f"inside a <{name}> raw-text block; the payload cannot "
                       f"close the element")
    return ReflectionContext(
        context="raw_text",
        element=name,
        breakout=bool(closes),
        executable=executable,
        suspected=suspected,
        description=description,
    )
