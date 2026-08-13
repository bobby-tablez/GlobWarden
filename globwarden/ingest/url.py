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

import base64
import datetime
import io
import re
import time
from urllib.parse import urljoin, urlparse

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

# --- Embedded <img> extraction (HTML/URL sources) --------------------------
#
# A blog-post/write-up ingested via `from_url` gets its *text* extracted (via
# trafilatura or the bs4 fallback), but the same page very often embeds a
# screenshot of an obfuscated command as an <img> rather than as text. This
# mirrors, at a smaller scale, what `ingest.pdf.from_pdf` already does for
# scanned/image-heavy PDF pages: find candidate images, cheaply filter out
# obvious non-content chrome (nav icons, avatars, tracking pixels, ad
# creative) *before* downloading anything, then download and validate a
# small, bounded number of the survivors.
#
# Every image kept here also becomes part of every downstream vision-LLM
# call, so the caps below are deliberately tight — this is meant to catch the
# occasional "screenshot of a PowerShell one-liner in a blog post" case, not
# to vacuum up every image on a media-heavy page.

# Per-image download cap. A legible code/terminal screenshot is realistically
# well under a few hundred KB; 5MB is generous headroom without letting one
# hostile/huge image response balloon a page fetch.
MAX_EMBEDDED_IMAGE_BYTES = 5 * 1024 * 1024

# Hard cap on how many *candidate* <img> URLs are even considered per page
# (after the cheap, no-download filter below), so a pathological page with
# hundreds of images can't blow up filtering cost. Candidates are taken in
# document order.
MAX_EMBEDDED_IMAGE_CANDIDATES = 20

# Hard cap on how many images are actually downloaded, validated, and kept
# per page. Kept deliberately small (well below MAX_EMBEDDED_IMAGE_CANDIDATES)
# since every kept image is sent to the vision LLM on every downstream call.
MAX_EMBEDDED_IMAGES_KEPT = 8

# Total wall-clock budget across every embedded-image download attempt for one
# page (not just the ones that succeed). Without this, a page whose images are
# all slow or hanging could burn up to MAX_EMBEDDED_IMAGE_CANDIDATES separate
# per-request timeouts in sequence -- worst case, tens of minutes added to a
# single scan, which is exactly the kind of latency this tool was already
# found to have too much of. Checked between candidates, not mid-download (an
# individual request is still bounded by `timeout`), so a single slow image
# can run past this budget but the next one won't be attempted.
MAX_EMBEDDED_IMAGES_TOTAL_SECONDS = 15.0

# An <img> tag whose HTML `width`/`height` attribute names a pixel dimension
# below this is almost certainly UI chrome (nav icon, avatar, badge), not a
# content screenshot -- filtered before any download. Attributes are often
# absent or wrong, so this is only ever a first-pass filter; the authoritative
# check is the decoded-pixel-dimension check below, once bytes are in hand.
MIN_HTML_IMAGE_DIMENSION = 200

# Once an image is actually downloaded and decoded, an image whose *real*
# pixel dimensions are still below this in either axis is discarded -- this
# is the authoritative size filter (HTML attributes can lie or be missing).
# 150px is small enough not to reject a real, modestly-sized inline
# screenshot, but comfortably excludes icons/avatars/badges that slipped past
# the cheaper attribute/filename filter above.
MIN_DECODED_IMAGE_DIMENSION = 150

# A base64 `data:` URI decoding to fewer bytes than this is almost always a
# tiny inline UI element (spinner, 1x1 tracking pixel, small icon) rather
# than a legible screenshot -- skipped without ever attempting a "download"
# (there's nothing to download; it's already inline).
MIN_DATA_URI_IMAGE_BYTES = 3 * 1024

# Cheap, no-download filename/path signal for common non-content image
# categories seen on real blog/report pages: nav icons, logos, author
# avatars, emoji, tracking pixels, badges, social-share buttons, sprite
# sheets, loading spinners.
_NON_CONTENT_IMAGE_RE = re.compile(
    r"icon|logo|avatar|emoji|pixel|tracking|tracker|badge|social|share|sprite|spinner|loader",
    re.IGNORECASE,
)

# A short list of common ad/tracker hostnames, checked against the resolved
# image URL's netloc. Not exhaustive by design -- this is a cheap extra
# signal, not a substitute for the filename/dimension filters above.
_NON_CONTENT_DOMAIN_RE = re.compile(
    r"doubleclick\.net|googlesyndication\.com|google-analytics\.com|"
    r"scorecardresearch\.com|quantserve\.com|adsystem",
    re.IGNORECASE,
)

# Non-raster/decorative extensions that are almost always UI chrome, not a
# content screenshot, when identifiable from the URL path alone (`.svg` icons
# in particular are essentially never a screenshot of a terminal/command).
_NON_CONTENT_EXTENSIONS = (".svg", ".ico")


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
    images, image_metadata = _extract_embedded_images(html, response.url, user_agent=user_agent, timeout=timeout)

    metadata = {
        "fetched_at": fetched_at,
        "status_code": response.status_code,
        "content_type": content_type,
        "final_url": response.url,
        "extractor": extractor,
        "bytes_downloaded": len(body),
    }
    metadata.update(image_metadata)

    return IngestedContent(
        source=url,
        source_type=SourceType.URL,
        text=text,
        images=images,
        title=title,
        metadata=metadata,
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

    _strip_boilerplate(soup)
    container = _find_main_container(soup)
    text = container.get_text(separator="\n", strip=True)

    text = _strip_junk_lines(text)
    return text, title


def _strip_boilerplate(soup) -> None:
    """Remove obvious boilerplate tags and known comment/ad/nav containers
    from `soup` in place. Shared by `_bs4_fallback` (text extraction) and
    `_collect_image_candidates` (embedded-image extraction) so both agree on
    what counts as "not the article" -- an <img> living inside a nav/footer/
    ad container is exactly the kind of non-content chrome (logo, social-share
    icon) the image filter also wants to exclude."""
    for tag in soup.find_all(_BOILERPLATE_TAGS):
        tag.decompose()
    for tag in soup.find_all(id=_BOILERPLATE_CONTAINER_RE):
        tag.decompose()
    for tag in soup.find_all(class_=_BOILERPLATE_CONTAINER_RE):
        tag.decompose()


def _find_main_container(soup):
    """Return whichever remaining container has the most visible text -- a
    decent proxy for "the article body" on pages without semantic markup.
    Falls back to `soup` itself if nothing matches. Shared by `_bs4_fallback`
    and `_collect_image_candidates`; trafilatura doesn't hand back a DOM, so
    this same bs4 heuristic is reused to locate candidate <img> tags even on
    the trafilatura-success text-extraction path (see `_extract_embedded_images`)."""
    candidates = soup.find_all(["article", "main", "div", "section", "body"])
    if not candidates:
        return soup
    return max(candidates, key=lambda t: len(t.get_text(strip=True)))


class _ImageCandidate:
    """A candidate embedded image after the cheap, no-download filter.

    Exactly one of `url` / `inline_bytes` is set: `url` for a normal <img
    src="..."> that still needs to be downloaded, `inline_bytes` for a
    `data:` URI that's already inline (nothing to download)."""

    __slots__ = ("url", "inline_bytes")

    def __init__(self, *, url: str | None = None, inline_bytes: bytes | None = None):
        self.url = url
        self.inline_bytes = inline_bytes


def _html_dimension_too_small(tag) -> bool:
    """True if the tag's `width`/`height` HTML attribute names a pixel value
    below `MIN_HTML_IMAGE_DIMENSION`. Non-numeric/percentage values (common
    for responsive images, e.g. width="100%") aren't a pixel measurement at
    all and are ignored rather than misinterpreted."""
    for attr in ("width", "height"):
        raw = tag.get(attr)
        if raw is None:
            continue
        raw = str(raw).strip()
        if not re.fullmatch(r"\d+(\.\d+)?", raw):
            continue  # not a plain pixel number (e.g. "100%", "auto") -- ignore, don't guess
        if 0 < float(raw) < MIN_HTML_IMAGE_DIMENSION:
            return True
    return False


def _data_uri_candidate(src: str) -> _ImageCandidate | None:
    """Decode a `data:` URI in place (there's nothing to "download"). Returns
    None if it's not a base64-encoded raster image or decodes to fewer than
    `MIN_DATA_URI_IMAGE_BYTES` (almost always a tiny inline UI element, not a
    legible screenshot)."""
    if ";base64," not in src:
        return None  # non-base64 data URIs are rare and typically inline SVG markup
    header, _, b64data = src.partition(",")
    if "svg" in header.lower():
        return None
    try:
        decoded = base64.b64decode(b64data, validate=False)
    except Exception:
        return None
    if len(decoded) < MIN_DATA_URI_IMAGE_BYTES:
        return None
    return _ImageCandidate(inline_bytes=decoded)


def _extract_img_src(tag) -> str | None:
    """Best-effort <img> source: `src`, falling back to `data-src` (common
    lazy-load pattern) and then the first URL in `srcset` if `src` is
    missing entirely."""
    src = tag.get("src") or tag.get("data-src")
    if src:
        return src.strip() or None
    srcset = tag.get("srcset")
    if srcset:
        first_entry = srcset.split(",")[0].strip()
        if first_entry:
            url_part = first_entry.split()[0].strip()
            return url_part or None
    return None


def _collect_image_candidates(html: str, base_url: str) -> list[_ImageCandidate]:
    """Locate candidate <img> tags within the page's main content container
    and cheaply filter out obvious non-content chrome -- *before* anything is
    downloaded. Mirrors `_bs4_fallback`'s container-selection logic (via the
    shared `_strip_boilerplate`/`_find_main_container` helpers) since
    trafilatura doesn't hand back a DOM for the trafilatura-success text path.
    Returns at most `MAX_EMBEDDED_IMAGE_CANDIDATES`, in document order."""
    if BeautifulSoup is None:
        return []  # best-effort enrichment only; never fatal on its own

    soup = BeautifulSoup(html, "html.parser")
    _strip_boilerplate(soup)
    container = _find_main_container(soup)
    if container is None:
        return []

    candidates: list[_ImageCandidate] = []
    for tag in container.find_all("img"):
        if len(candidates) >= MAX_EMBEDDED_IMAGE_CANDIDATES:
            break

        src = _extract_img_src(tag)
        if not src:
            continue

        if src.startswith("data:"):
            candidate = _data_uri_candidate(src)
            if candidate is not None:
                candidates.append(candidate)
            continue

        if _html_dimension_too_small(tag):
            continue

        resolved = urljoin(base_url, src)
        parsed = urlparse(resolved)
        path = parsed.path.lower()
        # Match the non-content filename regex against the filename alone
        # (the last path segment) -- not the full resolved URL. Matching the
        # whole URL means a plausible content-screenshot filename containing
        # a substring like "tracking" (e.g. "malware-tracking-dashboard.png")
        # or a query-string tracking param (e.g. "?ref=social") gets wrongly
        # rejected, and worse: if the article's own domain happens to contain
        # one of these words, every single image on the page is rejected.
        filename = path.rsplit("/", 1)[-1]
        if path.endswith(_NON_CONTENT_EXTENSIONS):
            continue
        if _NON_CONTENT_IMAGE_RE.search(filename):
            continue
        if _NON_CONTENT_DOMAIN_RE.search(parsed.netloc):
            continue

        candidates.append(_ImageCandidate(url=resolved))

    return candidates


_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"
_GIF_MAGICS = (b"GIF87a", b"GIF89a")
_BMP_MAGIC = b"BM"


def _looks_like_image_bytes(data: bytes) -> bool:
    """Cheap magic-byte sniff for the common raster formats -- no Pillow
    required. This is the one check that still runs even when Pillow (the
    'image' extra) isn't installed, so a non-image response (an HTML error
    page served with a 200 status, a truncated/corrupt download, etc.) can
    never be silently accepted into `IngestedContent.images` and forwarded to
    a vision LLM as if it were real screenshot content -- without it, the
    Pillow-missing path had zero validation at all."""
    if data.startswith((_PNG_MAGIC, _JPEG_MAGIC, *_GIF_MAGICS, _BMP_MAGIC)):
        return True
    return data.startswith(b"RIFF") and data[8:12] == b"WEBP"


def _passes_decoded_pixel_check(data: bytes) -> bool:
    """Authoritative size filter, run only once bytes are actually in hand:
    confirm `data` decodes as real image data and its *real* pixel
    dimensions clear `MIN_DECODED_IMAGE_DIMENSION`. Mirrors
    `ingest.image._validate_image`'s graceful-degradation pattern for the
    *pixel-dimension* check specifically -- if Pillow (the 'image' extra)
    isn't installed, only that part is skipped (return True), since embedded-
    image extraction is best-effort enrichment, not a hard requirement. The
    magic-byte check above always runs regardless of Pillow availability."""
    if not _looks_like_image_bytes(data):
        return False

    try:
        from PIL import Image
    except ImportError:
        return True  # Pillow ('image' extra) not installed -- magic bytes already confirmed a real image

    try:
        with Image.open(io.BytesIO(data)) as img:
            img.verify()
        with Image.open(io.BytesIO(data)) as img:
            width, height = img.size
    except Exception:
        return False

    return width >= MIN_DECODED_IMAGE_DIMENSION and height >= MIN_DECODED_IMAGE_DIMENSION


def _download_image_candidate(
    candidate: _ImageCandidate,
    *,
    user_agent: str | None,
    timeout: tuple[float, float],
) -> bytes | None:
    """Download (or, for an inline `data:` candidate, simply use) one
    candidate's bytes, capped at `MAX_EMBEDDED_IMAGE_BYTES` via the same
    streaming-with-cap pattern `from_url` uses for the main page fetch.
    Returns None on any failure (bad status, timeout, oversized, undecodable)
    -- a single broken/hostile image URL must never fail the whole page
    ingest, mirroring `ingest.pdf.from_pdf`'s per-page best-effort renders."""
    if candidate.inline_bytes is not None:
        data = candidate.inline_bytes
    else:
        headers = {"User-Agent": user_agent or DEFAULT_USER_AGENT, "Accept": "image/*,*/*"}
        try:
            response = requests.get(candidate.url, headers=headers, timeout=timeout, stream=True)
        except requests.RequestException:
            return None
        try:
            if not (200 <= response.status_code < 300):
                return None
            body = bytearray()
            for chunk in response.iter_content(chunk_size=_CHUNK_SIZE):
                body.extend(chunk)
                if len(body) > MAX_EMBEDDED_IMAGE_BYTES:
                    return None  # hostile/oversized response -- bail, don't buffer further
            data = bytes(body)
        except requests.RequestException:
            return None
        finally:
            response.close()

    if not data or not _passes_decoded_pixel_check(data):
        return None
    return data


def _extract_embedded_images(
    html: str,
    base_url: str,
    *,
    user_agent: str | None,
    timeout: tuple[float, float],
) -> tuple[list[bytes], dict]:
    """Find, filter, download, and validate embedded <img> content for a
    fetched HTML page (see module docstring section above for the full
    rationale). Never raises: a page with no images (or nothing surviving
    the filter) costs zero HTTP requests and returns `([], {...counts...})`
    exactly as before this feature existed; a broken individual image never
    fails the whole ingest.

    Returns `(images, metadata)` where `metadata` carries
    `embedded_images_found` (candidate count after the cheap filter) and
    `embedded_images_kept` (count actually downloaded and validated), for
    observability/tests without needing to inspect image bytes directly.

    Bounded by `MAX_EMBEDDED_IMAGES_TOTAL_SECONDS` in aggregate across every
    attempt (not just successful ones) -- a page whose images are all slow or
    unreachable stops being attempted once the budget is spent, rather than
    working through every remaining candidate at up to a full `timeout` each.
    """
    try:
        candidates = _collect_image_candidates(html, base_url)
    except Exception:
        candidates = []  # best-effort enrichment only; never fatal on its own

    images: list[bytes] = []
    deadline = time.monotonic() + MAX_EMBEDDED_IMAGES_TOTAL_SECONDS
    for candidate in candidates:
        if len(images) >= MAX_EMBEDDED_IMAGES_KEPT:
            break
        if time.monotonic() >= deadline:
            break
        try:
            data = _download_image_candidate(candidate, user_agent=user_agent, timeout=timeout)
        except Exception:
            data = None  # mirror pdf.py's per-page best-effort: one bad image, not the whole page
        if data:
            images.append(data)

    return images, {
        "embedded_images_found": len(candidates),
        "embedded_images_kept": len(images),
    }


def _strip_junk_lines(text: str) -> str:
    kept = [line for line in text.splitlines() if not _JUNK_LINE_RE.match(line.strip())]
    return "\n".join(kept)
