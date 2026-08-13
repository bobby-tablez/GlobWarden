"""Shared fixtures for the ingest test suite: real synthetic PDFs (built with
reportlab, not mocked) and a real synthetic PNG (built with Pillow), so the
PDF/image parsing tests exercise the actual libraries against actual files
rather than mocking them away.
"""

from __future__ import annotations

import io

import pytest


def _build_text_pdf() -> bytes:
    """A small, real, two-page PDF with genuinely extractable text on both
    pages (built with reportlab)."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(72, 720, "GlobWarden synthetic test report")
    c.drawString(72, 700, "Wildcard Get-Alias to Invoke-Expression obfuscation example")
    c.drawString(72, 680, "gal *-ex | iex")
    c.showPage()
    c.drawString(72, 720, "Second page of the synthetic report")
    c.drawString(72, 700, "T1027.010 sample content for unit tests")
    c.showPage()
    c.save()
    return buf.getvalue()


def _build_scanned_pdf() -> bytes:
    """A small, real two-page PDF where page 1 has a real text layer and page
    2 is *only* a rasterized image (no text layer at all) — the classic
    "scanned page" shape the vision-fallback path needs to detect."""
    from PIL import Image, ImageDraw
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    img = Image.new("RGB", (600, 800), "white")
    draw = ImageDraw.Draw(img)
    draw.text((50, 50), "scanned page - no text layer", fill="black")
    img_buf = io.BytesIO()
    img.save(img_buf, format="PNG")
    img_buf.seek(0)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(72, 720, "Page one has a real extractable text layer.")
    c.showPage()
    c.drawImage(ImageReader(img_buf), 0, 0, width=letter[0], height=letter[1])
    c.showPage()
    c.save()
    return buf.getvalue()


def _build_png() -> bytes:
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (200, 100), "white")
    draw = ImageDraw.Draw(img)
    draw.rectangle((10, 10, 190, 90), outline="black")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _build_diagram_page(caption: str | None) -> bytes:
    """A real, single-page PDF that's ~90% a full-page diagram (built as a
    real raster image, not text) with an optional short caption underneath —
    the exact page shape a threat-intel report uses to show an
    obfuscation-technique screenshot/terminal capture. This is what
    regression-tests the image-area vision-fallback signal: a caption long
    enough to clear the old character-count-only threshold on its own must
    NOT be enough, by itself, to suppress vision fallback for a
    diagram-dominated page."""
    from PIL import Image, ImageDraw
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    diagram = Image.new("RGB", (600, 800), "white")
    draw = ImageDraw.Draw(diagram)
    draw.rectangle((20, 20, 580, 780), outline="black", width=5)
    draw.text((100, 400), "obfuscation technique diagram", fill="black")
    img_buf = io.BytesIO()
    diagram.save(img_buf, format="PNG")
    img_buf.seek(0)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawImage(ImageReader(img_buf), 50, 100, width=500, height=650)
    if caption:
        c.drawString(72, 60, caption)
    c.showPage()
    c.save()
    return buf.getvalue()


def _build_banner_title_pdf() -> bytes:
    """A real PDF shaped like a real-world CISA/US-CERT advisory: a
    classification banner as the literal first line of text, then the actual
    document title, then body text — the exact shape that made the naive
    "first line of text" title guesser pick 'TLP:CLEAR' as the title."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(72, 750, "TLP:CLEAR")
    c.drawString(72, 720, "CISA Shares Lessons Learned from an Incident Response Engagement")
    c.drawString(72, 690, "Some advisory body text goes here for the report.")
    c.showPage()
    c.save()
    return buf.getvalue()


def _build_large_valid_pdf(width_px: int = 2900, height_px: int = 2900) -> bytes:
    """A real, fully valid, parseable PDF sized deliberately between the
    generic URL cap (25MB) and the PDF-specific cap (40MB) — built the same
    way the critic's live repro did: one real full-page raster image of
    random (incompressible) noise, embedded via reportlab, so the resulting
    file is genuinely ~30MB and genuinely parses, not a fake padded blob."""
    import os

    from PIL import Image
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    raw = os.urandom(width_px * height_px * 3)
    img = Image.frombytes("RGB", (width_px, height_px), raw)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawImage(ImageReader(img), 0, 0, width=letter[0], height=letter[1])
    c.drawString(72, 750, "Large synthetic report page")
    c.showPage()
    c.save()
    return buf.getvalue()


@pytest.fixture(scope="session")
def text_pdf_bytes() -> bytes:
    return _build_text_pdf()


@pytest.fixture(scope="session")
def scanned_pdf_bytes() -> bytes:
    return _build_scanned_pdf()


@pytest.fixture(scope="session")
def diagram_with_short_caption_pdf_bytes() -> bytes:
    """Full-page diagram + a 25-char caption ("Figure 1. Attack diagram.")
    that comfortably clears the old MIN_CHARS_PER_PAGE=20 threshold alone."""
    return _build_diagram_page("Figure 1. Attack diagram.")


@pytest.fixture(scope="session")
def diagram_with_no_caption_pdf_bytes() -> bytes:
    """Same diagram, zero caption text — the case that already worked before
    this fix (sparse-text signal alone was sufficient), kept as a control."""
    return _build_diagram_page(None)


@pytest.fixture(scope="session")
def banner_title_pdf_bytes() -> bytes:
    return _build_banner_title_pdf()


@pytest.fixture(scope="session")
def sample_png_bytes() -> bytes:
    return _build_png()


@pytest.fixture(scope="session")
def large_valid_pdf_bytes() -> bytes:
    """~30MB real, valid PDF — between the 25MB generic URL cap and the 40MB
    PDF cap. Session-scoped since building it costs a few seconds; only paid
    once regardless of how many tests use it."""
    return _build_large_valid_pdf()
