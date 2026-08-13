"""Extract text (and, where needed, page images) from a PDF.

Uses `pdfplumber` for both text extraction and page rasterization (it wraps
`pdfminer.six` and needs no external binary like poppler/ghostscript, which
keeps this dependency simple to install).

Scanned-page detection: PDFs from real threat-intel reporting are sometimes a
mix of real text pages and scanned/screenshotted pages (a campaign write-up
with an embedded screenshot of a terminal, for instance) that have little or
no extractable text layer. A page is flagged as needing a vision-capable LLM
(rasterized to a PNG, appended to `IngestedContent.images`, page number
recorded in `metadata["vision_fallback_pages"]`) if *either* of two
independent signals fires:

1. `page.extract_text()` yields fewer than `MIN_CHARS_PER_PAGE` characters
   (a near-blank/no-text-layer page), or
2. embedded raster images cover at least `IMAGE_AREA_RATIO_THRESHOLD` of the
   page's area (`page.images` bounding boxes vs. page area) — this is the one
   that matters most for this tool: a page that's mostly a diagram/terminal
   screenshot but has a short caption (which trivially clears the character
   threshold on its own) still needs vision, because the caption alone tells
   an LLM nothing about what the screenshot actually shows. Relying on
   character count alone silently drops exactly this page shape.

`metadata["vision_fallback_reasons"]` records, per flagged page number, which
signal(s) fired (`"sparse_text"`, `"large_image"`, or both) so downstream
code/rendering can distinguish "genuinely blank page" from "text page that
also happens to contain a large diagram we're sending to vision as well."
This module does not OCR anything itself — it only detects "this page needs
vision" and hands over the bytes.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

try:
    import pdfplumber
except ImportError:  # pragma: no cover - exercised by the zero-extras CI smoke test
    pdfplumber = None

from globwarden.ingest.errors import ParseError, SizeLimitExceeded, UnsupportedSourceError
from globwarden.models import IngestedContent, SourceType

# A "few tens of MB" cap per the architecture doc's safety requirement — real
# threat-intel report PDFs are almost always a few hundred KB to a handful of
# MB; 40MB gives generous headroom for image-heavy reports while still
# refusing a hostile oversized file outright rather than hanging on it.
MAX_PDF_BYTES = 40 * 1024 * 1024

# Hard cap on pages actually processed. Page *count* is a separate attack
# surface from byte size (a small file can still declare an absurd page
# count), so this bounds worst-case processing time independent of the byte
# cap above.
MAX_PAGES = 300

# A page with fewer extracted characters than this is treated as
# scanned/image-only. Real text pages in reports typically carry hundreds of
# characters; a genuinely near-blank page costs us at most one wasted
# fallback image, which is cheap compared to silently returning empty
# content for a page that actually had something on it.
MIN_CHARS_PER_PAGE = 20

# A page whose embedded raster image(s) cover at least this fraction of the
# page area is treated as needing vision fallback *regardless of how much
# caption/label text is on the page*. This is the second, independent signal
# (see module docstring): a page that's 90% a terminal-screenshot diagram
# with a 25-character caption easily clears MIN_CHARS_PER_PAGE on text alone,
# but the diagram — the actual evidence — would never reach the LLM without
# this check. 0.4 (40% of the page) is chosen to reliably catch "this page is
# dominated by a figure" while not flagging a normal text page that merely
# has one modest inline screenshot alongside real paragraph text.
IMAGE_AREA_RATIO_THRESHOLD = 0.4

# Cap on how many pages we'll actually rasterize to images per document, so a
# malicious all-scanned 300-page PDF can't force us to render (and hold in
# memory) hundreds of full-page PNGs.
MAX_FALLBACK_IMAGES = 30

# DPI for fallback page renders — legible for a vision-capable LLM without
# producing huge images.
IMAGE_RESOLUTION = 150


def from_pdf(
    path_or_bytes: str | Path | bytes | bytearray,
    *,
    source: str | None = None,
    max_bytes: int = MAX_PDF_BYTES,
) -> IngestedContent:
    """Extract text and (where needed) page images from a PDF.

    `path_or_bytes` may be a filesystem path (str/Path) or the raw PDF bytes
    already in memory (e.g. downloaded by `ingest.url.from_url`). `source`
    overrides the label recorded on the returned content's `.source` field —
    useful when the bytes came from a URL rather than a local file.
    """
    if pdfplumber is None:
        raise ParseError(
            "PDF parsing requires the optional 'pdf' extra, which isn't installed. "
            'Run: pip install "globwarden[pdf]"  (or "globwarden[all]" for every '
            "input type)."
        )

    data, resolved_source = _read_input(path_or_bytes, source, max_bytes)

    try:
        pdf = pdfplumber.open(io.BytesIO(data))
    except Exception as exc:
        raise ParseError(f"Could not parse PDF from {resolved_source!r}: {exc}") from exc

    images: list[bytes] = []
    vision_fallback_pages: list[int] = []
    vision_fallback_reasons: dict[int, list[str]] = {}
    page_texts: list[str] = []

    with pdf:
        total_pages = len(pdf.pages)
        truncated = total_pages > MAX_PAGES
        pages_to_process = pdf.pages[:MAX_PAGES]

        for i, page in enumerate(pages_to_process, start=1):
            try:
                text = page.extract_text() or ""
            except Exception:
                text = ""

            reasons: list[str] = []
            if len(text.strip()) < MIN_CHARS_PER_PAGE:
                reasons.append("sparse_text")

            try:
                image_ratio = _image_area_ratio(page)
            except Exception:
                image_ratio = 0.0
            if image_ratio >= IMAGE_AREA_RATIO_THRESHOLD:
                reasons.append("large_image")

            if reasons:
                vision_fallback_pages.append(i)
                vision_fallback_reasons[i] = reasons
                if len(images) < MAX_FALLBACK_IMAGES:
                    try:
                        images.append(_render_page_to_png(page))
                    except Exception:
                        pass  # best-effort: a render failure shouldn't fail the whole ingest

            page_texts.append(f"[page {i}]\n{text}".rstrip())

    full_text = "\n\n".join(page_texts).strip()

    return IngestedContent(
        source=resolved_source,
        source_type=SourceType.PDF,
        text=full_text,
        images=images,
        title=_guess_title(full_text),
        metadata={
            "pages": total_pages,
            "pages_processed": len(pages_to_process),
            "truncated": truncated,
            "vision_fallback_pages": vision_fallback_pages,
            "vision_fallback_reasons": vision_fallback_reasons,
            "bytes": len(data),
        },
    )


def _read_input(
    path_or_bytes: str | Path | bytes | bytearray,
    source: str | None,
    max_bytes: int,
) -> tuple[bytes, str]:
    if isinstance(path_or_bytes, (bytes, bytearray)):
        data = bytes(path_or_bytes)
        if len(data) > max_bytes:
            raise SizeLimitExceeded(f"PDF data is {len(data)} bytes, exceeding the {max_bytes}-byte ingestion cap")
        return data, source or "<bytes>"

    path = Path(path_or_bytes)
    if not path.is_file():
        raise UnsupportedSourceError(f"PDF path does not exist or is not a file: {path}")

    size = path.stat().st_size
    if size > max_bytes:
        raise SizeLimitExceeded(f"{path} is {size} bytes, exceeding the {max_bytes}-byte PDF ingestion cap")

    return path.read_bytes(), source or str(path)


def _render_page_to_png(page) -> bytes:
    page_image = page.to_image(resolution=IMAGE_RESOLUTION)
    buf = io.BytesIO()
    page_image.original.save(buf, format="PNG")
    return buf.getvalue()


def _image_area_ratio(page) -> float:
    """Fraction of the page's area covered by embedded raster images, per
    `page.images` bounding boxes (`pdfplumber` exposes `x0`/`x1`/`top`/
    `bottom` per embedded image, no rasterization needed to compute this).
    Overlapping images are summed rather than unioned (a cheap approximation
    that only ever over-estimates coverage, which is fine here — the
    consequence of a false positive is one extra vision-fallback image, the
    consequence of a false negative is silently dropped visual evidence, so
    this errs in the safer direction). Result is clamped to [0.0, 1.0].
    """
    page_area = float(page.width) * float(page.height)
    if page_area <= 0:
        return 0.0

    total = 0.0
    for img in page.images:
        x0 = max(0.0, min(float(img.get("x0", 0.0)), float(page.width)))
        x1 = max(0.0, min(float(img.get("x1", 0.0)), float(page.width)))
        top = max(0.0, min(float(img.get("top", 0.0)), float(page.height)))
        bottom = max(0.0, min(float(img.get("bottom", 0.0)), float(page.height)))
        width = max(0.0, x1 - x0)
        height = max(0.0, bottom - top)
        total += width * height

    return min(total / page_area, 1.0)


# Lines that look like a classification banner ("TLP:CLEAR", "UNCLASSIFIED"),
# a running header, or a bare page number — short, entirely
# uppercase/digits/punctuation, no lowercase letters at all. Confirmed live
# against a real CISA advisory that this is precisely the first line of the
# extracted text on that whole class of formal report ("TLP:CLEAR" was picked
# as the title before this check existed). Deliberately conservative (an
# all-caps *real* title, rare but possible, would still be skipped in favor
# of a later line) since a wrong short-banner title is worse than a slightly
# too-cautious skip.
_BANNER_LINE_RE = re.compile(r"^[A-Z0-9][A-Z0-9 :/\-.,'\"()#]{0,39}$")


def _looks_like_banner_line(line: str) -> bool:
    if not line:
        return True
    if line.isdigit():
        return True
    return bool(_BANNER_LINE_RE.match(line))


def _guess_title(full_text: str) -> str | None:
    """Best-effort title guess: the first non-empty, reasonably short line of
    extracted text that doesn't look like a classification banner/header/page
    number (skipping the synthetic "[page N]" markers this module inserts).
    PDFs rarely expose a reliable title via document metadata, so this
    heuristic is deliberately simple rather than trusting XMP/Info
    dictionaries that are routinely wrong or missing."""
    for line in full_text.splitlines():
        line = line.strip()
        if not line or line.startswith("[page "):
            continue
        if _looks_like_banner_line(line):
            continue
        if len(line) <= 150:
            return line
        return None
    return None
