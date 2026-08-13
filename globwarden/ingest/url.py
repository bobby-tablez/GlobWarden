"""Fetch a URL and turn it into `IngestedContent`.

Extraction strategy: **trafilatura**, chosen over a hand-rolled BeautifulSoup
heuristic because it's purpose-built for "main article text" extraction — it
already handles the hard parts (boilerplate/nav/ad stripping, paywalled-teaser
detection, metadata/title/date extraction, encoding sniffing) that a
from-scratch "strip nav/footer, take the largest text block" heuristic tends
to get subtly wrong on real-world blog/report HTML. The extra dependency is
small (no browser/JS engine) and pip-installable.

A BeautifulSoup-based heuristic is still kept as a fallback (`_bs4_fallback`)
for the rare case trafilatura returns nothing (e.g. a very short or
unusually-structured page) — see `_extract_html`.
"""

from __future__ import annotations

import datetime
import re

import requests

try:
    import trafilatura
except ImportError:  # pragma: no cover - exercised only if dependency missing
    trafilatura = None

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - exercised by the zero-extras CI smoke test
    BeautifulSoup = None

from globwarden.ingest.errors import FetchError, SizeLimitExceeded
from globwarden.ingest.pdf import MAX_PDF_BYTES, from_pdf
from globwarden.models import IngestedContent, SourceType

# Default UA is a standard, current browser string. Threat-intel/security blogs
# in particular tend to run aggressive anti-scraping WAFs that block on sight
# anything that self-identifies as a bot or contains "python-requests" -- a
# real, honestly-labeled UA was tried first and got blocked by real sources
# (e.g. securonix.com returns HTTP 403 to it but 200 to this one), so this is
# a deliberate usability-over-transparency tradeoff, not an oversight.
# Override with --user-agent / GLOBWARDEN_USER_AGENT if you want something
# else -- HONEST_USER_AGENT below is provided as a ready-to-use opt-in for
# anyone who'd rather identify honestly and accept that some sites will 403 it.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
HONEST_USER_AGENT = "GlobWarden/0.1 (+https://github.com/bobby-tablez/GlobWarden; threat-intel ingestion bot)"

# (connect timeout, read timeout) in seconds. Generous enough for a slow blog
# host, tight enough that a single dead/malicious server can't hang a CLI run
# indefinitely — this tool is meant to be used live, in a demo.
DEFAULT_TIMEOUT = (10, 20)

# Cap total downloaded bytes for a *non-PDF* URL fetch (an HTML page). A
# threat-intel report/blog post is realistically well under a few MB; 25MB
# gives generous headroom while still refusing to let a hostile/misconfigured
# server stream gigabytes at us.
#
# PDFs fetched by URL get the larger, PDF-specific `pdf.MAX_PDF_BYTES` cap
# instead (see `from_url` below) — a report downloaded directly by URL is
# held to the same size budget as the identical file loaded from local disk,
# not silently capped tighter just because it arrived over HTTP. The switch
# happens as soon as the response is known to be a PDF (by `Content-Type`
# header, checked before any body bytes are read, or by `%PDF-` magic bytes
# sniffed from the first chunk if the server mislabels the content type).
MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024

_CHUNK_SIZE = 64 * 1024
_PDF_MAGIC = b"%PDF-"


def from_url(
    url: str,
    *,
    timeout: tuple[float, float] = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
    max_pdf_bytes: int = MAX_PDF_BYTES,
    user_agent: str | None = None,
) -> IngestedContent:
    """Fetch `url` and return its content as `IngestedContent`.

    - Non-2xx responses raise `FetchError` (never silently return empty content).
    - A response larger than the applicable cap raises `SizeLimitExceeded`.
      Non-PDF responses are capped at `max_bytes`; a response confirmed (by
      `Content-Type` or `%PDF-` magic bytes) to be a PDF is capped at the
      larger `max_pdf_bytes` instead — the same cap `ingest.pdf.from_pdf`
      applies to a local file, so a report doesn't get held to a stricter
      limit merely for arriving over HTTP.
    - If the response's Content-Type is a PDF, the downloaded bytes are handed
      off to `ingest.pdf.from_pdf` and the returned content's `source_type`
      is `PDF` (not `URL`) — this is what "points directly to a PDF" means.
    - Otherwise the response is treated as HTML and the main article text is
      extracted (see module docstring for extractor choice).
    """
    headers = {"User-Agent": user_agent or DEFAULT_USER_AGENT, "Accept": "*/*"}

    try:
        response = requests.get(url, headers=headers, timeout=timeout, stream=True, allow_redirects=True)
    except requests.RequestException as exc:
        raise FetchError(f"Failed to fetch {url!r}: {exc}") from exc

    if not (200 <= response.status_code < 300):
        response.close()
        raise FetchError(f"Fetching {url!r} returned HTTP {response.status_code}, expected 2xx")

    content_type = response.headers.get("Content-Type", "").lower()
    # Content-Type is available from the response headers before any body
    # bytes are read, so a PDF declared up front gets the larger cap from the
    # very start — no need to buffer under the tighter cap first and retry.
    declared_pdf = "application/pdf" in content_type
    effective_max = max_pdf_bytes if declared_pdf else max_bytes

    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            if int(content_length) > effective_max:
                response.close()
                raise SizeLimitExceeded(
                    f"{url!r} declares Content-Length={content_length} bytes, exceeding the {effective_max}-byte ingestion cap"
                )
        except ValueError:
            pass  # malformed header, fall through to the streamed cap below

    body = bytearray()
    sniffed_pdf = False
    try:
        for chunk in response.iter_content(chunk_size=_CHUNK_SIZE):
            body.extend(chunk)
            # A server can mislabel Content-Type (or omit it); sniff the
            # magic bytes as soon as we have enough and, if it turns out to
            # be a PDF we hadn't already detected via the header, upgrade the
            # cap for the rest of the download rather than rejecting a
            # legitimately-sized PDF at the tighter generic-web cap.
            if not declared_pdf and not sniffed_pdf and len(body) >= len(_PDF_MAGIC):
                if bytes(body[: len(_PDF_MAGIC)]) == _PDF_MAGIC:
                    sniffed_pdf = True
                    effective_max = max(effective_max, max_pdf_bytes)
            if len(body) > effective_max:
                raise SizeLimitExceeded(
                    f"{url!r} exceeded the {effective_max}-byte ingestion cap while "
                    "streaming (no/incorrect Content-Length header)"
                )
    finally:
        response.close()

    fetched_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if declared_pdf or sniffed_pdf:
        content = from_pdf(bytes(body), source=url)
        content.metadata.update(
            {
                "fetched_at": fetched_at,
                "status_code": response.status_code,
                "content_type": content_type,
                "final_url": response.url,
                "via": "url",
            }
        )
        return content

    html = _decode(body, response)
    text, title, extractor = _extract_html(html, url)

    return IngestedContent(
        source=url,
        source_type=SourceType.URL,
        text=text,
        images=[],
        title=title,
        metadata={
            "fetched_at": fetched_at,
            "status_code": response.status_code,
            "content_type": content_type,
            "final_url": response.url,
            "extractor": extractor,
            "bytes_downloaded": len(body),
        },
    )


def _decode(body: bytearray, response: requests.Response) -> str:
    """Decode response bytes to text, preferring the server-declared/HTTP-sniffed
    encoding but never raising on bad bytes."""
    encoding = response.encoding or response.apparent_encoding or "utf-8"
    try:
        return bytes(body).decode(encoding, errors="replace")
    except (LookupError, TypeError):
        return bytes(body).decode("utf-8", errors="replace")


def _extract_html(html: str, url: str) -> tuple[str, str | None, str]:
    """Return (text, title, extractor_name)."""
    if trafilatura is not None:
        text = trafilatura.extract(
            html,
            url=url,
            include_comments=False,
            include_tables=True,
            favor_recall=True,
        )
        if text and text.strip():
            title = None
            try:
                metadata = trafilatura.extract_metadata(html)
                if metadata is not None:
                    title = metadata.title
            except Exception:
                title = None
            if not title:
                title = _bs4_title(html)
            return text.strip(), title, "trafilatura"

    # Fallback: trafilatura unavailable or returned nothing usable.
    text, title = _bs4_fallback(html)
    return text, title, "bs4-heuristic"


def _bs4_title(html: str) -> str | None:
    if BeautifulSoup is None:
        return None  # best-effort title enrichment only; never fatal on its own
    soup = BeautifulSoup(html, "html.parser")
    og_title = soup.find("meta", property="og:title")
    if og_title and og_title.get("content"):
        return og_title["content"].strip()
    if soup.title and soup.title.string:
        return soup.title.string.strip()
    return None


_BOILERPLATE_TAGS = ("script", "style", "nav", "footer", "header", "aside", "form", "noscript")

# Known this is NOT a general-purpose boilerplate remover — it's a "never
# crash, never obviously embarrass us" safety net for when trafilatura is
# unavailable/fails, not a substitute for it. Confirmed live (against a real
# Krebs on Security article) that without this, reader comments and ad
# markers get folded indistinguishably into the "article" text — a real
# correctness problem for a tool whose findings need traceability back to
# what the *source document* actually said, not a third party's reaction to
# it. This targets the common WordPress/Disqus/ad-network id/class patterns
# and a short list of literal junk lines seen in practice; it will not catch
# every site's markup, and callers should treat `metadata["extractor"] ==
# "bs4-heuristic"` as a lower-confidence result worth spot-checking against
# the source, same as the primary trafilatura path can't be 100% either.
_BOILERPLATE_CONTAINER_RE = re.compile(
    r"comment|disqus|advert|sponsor|promo|newsletter|"
    r"subscribe|social-share|share-buttons|related-post|cookie-notice|cookie-consent",
    re.IGNORECASE,
)

_JUNK_LINE_RE = re.compile(
    r"^(advertisement|comments?\s+(is|are)\s+closed\.?|share\s+this:?|"
    r"©.*|leave\s+a\s+(reply|comment).*)$",
    re.IGNORECASE,
)


def _bs4_fallback(html: str) -> tuple[str, str | None]:
    """Heuristic HTML->text extraction: strip obvious boilerplate tags and
    known comment/ad containers, then take the text of whichever remaining
    container has the most visible text (a decent proxy for "the article
    body" on pages without semantic markup), with a final pass to drop
    literal junk lines (ad markers, "comments are closed", etc.) that aren't
    reliably wrapped in an identifiable container."""
    if BeautifulSoup is None:
        raise FetchError(
            "Could not extract readable text from this page: trafilatura is "
            "unavailable or found nothing usable, and the bs4 fallback requires "
            "the optional 'web' extra, which isn't installed. "
            'Run: pip install "globwarden[web]"  (or "globwarden[all]").'
        )
    soup = BeautifulSoup(html, "html.parser")

    title = None
    og_title = soup.find("meta", property="og:title")
    if og_title and og_title.get("content"):
        title = og_title["content"].strip()
    elif soup.title and soup.title.string:
        title = soup.title.string.strip()

    for tag in soup.find_all(_BOILERPLATE_TAGS):
        tag.decompose()

    for tag in soup.find_all(id=_BOILERPLATE_CONTAINER_RE):
        tag.decompose()
    for tag in soup.find_all(class_=_BOILERPLATE_CONTAINER_RE):
        tag.decompose()

    candidates = soup.find_all(["article", "main", "div", "section", "body"])
    if not candidates:
        text = soup.get_text(separator="\n", strip=True)
    else:
        best = max(candidates, key=lambda t: len(t.get_text(strip=True)))
        text = best.get_text(separator="\n", strip=True)

    text = _strip_junk_lines(text)
    return text, title


def _strip_junk_lines(text: str) -> str:
    kept = [line for line in text.splitlines() if not _JUNK_LINE_RE.match(line.strip())]
    return "\n".join(kept)
