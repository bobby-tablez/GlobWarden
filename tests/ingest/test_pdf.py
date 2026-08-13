"""Tests for globwarden.ingest.pdf against real (synthetic) PDF files —
built with reportlab in conftest.py, parsed with the real pdfplumber-backed
`from_pdf`. Nothing here mocks the PDF library itself."""

from __future__ import annotations

from pathlib import Path

import pytest

from globwarden.ingest.errors import ParseError, SizeLimitExceeded, UnsupportedSourceError
from globwarden.ingest.pdf import MAX_PDF_BYTES, from_pdf
from globwarden.models import SourceType


def test_from_pdf_raises_clear_error_when_pdfplumber_not_installed(monkeypatch, text_pdf_bytes):
    """Regression for the final-integration critique's release-blocking bug:
    a plain `pip install globwarden` (no 'pdf' extra) must fail with a clear,
    actionable ParseError naming the extra to install -- never a raw
    ModuleNotFoundError bubbling out of a hard module-level import, and never
    breaking `globwarden.ingest`'s own importability for every source type."""
    import globwarden.ingest.pdf as pdf_module

    monkeypatch.setattr(pdf_module, "pdfplumber", None)
    with pytest.raises(ParseError, match=r"globwarden\[pdf\]"):
        from_pdf(text_pdf_bytes, source="synthetic-report.pdf")


def test_extracts_text_from_real_pdf_bytes(text_pdf_bytes):
    result = from_pdf(text_pdf_bytes, source="synthetic-report.pdf")

    assert result.source_type == SourceType.PDF
    assert result.source == "synthetic-report.pdf"
    assert "Wildcard Get-Alias to Invoke-Expression" in result.text
    assert "gal *-ex | iex" in result.text
    assert "Second page of the synthetic report" in result.text
    assert result.metadata["pages"] == 2
    assert result.metadata["vision_fallback_pages"] == []
    assert result.images == []


def test_from_pdf_accepts_a_file_path(tmp_path: Path, text_pdf_bytes):
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(text_pdf_bytes)

    result = from_pdf(pdf_path)

    assert result.source == str(pdf_path)
    assert "GlobWarden synthetic test report" in result.text


def test_scanned_page_triggers_vision_fallback_image(scanned_pdf_bytes):
    result = from_pdf(scanned_pdf_bytes, source="scanned.pdf")

    assert result.metadata["pages"] == 2
    # Page 1 has real text and should NOT be flagged for vision fallback.
    assert 1 not in result.metadata["vision_fallback_pages"]
    # Page 2 is image-only and MUST be flagged and rendered.
    assert result.metadata["vision_fallback_pages"] == [2]
    assert len(result.images) == 1
    # The captured fallback image must be real, decodable PNG bytes, not a
    # placeholder / empty blob.
    assert result.images[0].startswith(b"\x89PNG\r\n\x1a\n")

    import io

    from PIL import Image

    with Image.open(io.BytesIO(result.images[0])) as img:
        img.verify()

    # Extracted text must still contain page 1's real content, and must NOT
    # silently claim page 2 had usable text.
    assert "Page one has a real extractable text layer." in result.text


def test_from_pdf_rejects_oversized_bytes():
    with pytest.raises(SizeLimitExceeded):
        from_pdf(b"x" * (MAX_PDF_BYTES + 1), source="huge.pdf")


def test_from_pdf_rejects_oversized_file(tmp_path: Path):
    big = tmp_path / "huge.pdf"
    # sparse-ish write is fine; we only need the byte count on disk to exceed the cap
    with open(big, "wb") as f:
        f.seek(MAX_PDF_BYTES + 1024)
        f.write(b"\0")
    with pytest.raises(SizeLimitExceeded):
        from_pdf(big)


def test_from_pdf_missing_path_raises(tmp_path: Path):
    missing = tmp_path / "does-not-exist.pdf"
    with pytest.raises(UnsupportedSourceError):
        from_pdf(missing)


def test_from_pdf_garbage_bytes_raise_parse_error():
    with pytest.raises(ParseError):
        from_pdf(b"this is not a pdf file at all", source="garbage.pdf")


def test_title_guessed_from_first_text_line(text_pdf_bytes):
    result = from_pdf(text_pdf_bytes, source="synthetic-report.pdf")
    assert result.title == "GlobWarden synthetic test report"


# --- Regression tests: HIGH-severity fixes from CRITIQUE-B.md -------------


def test_diagram_page_with_caption_still_triggers_vision_fallback(
    diagram_with_short_caption_pdf_bytes,
):
    """Regression for CRITIQUE-B §1d/§3 HIGH: a full-page diagram with a
    25-char caption ("Figure 1. Attack diagram.") comfortably clears the old
    character-count-only MIN_CHARS_PER_PAGE=20 threshold, so before the fix
    this page was silently never rasterized/flagged — the diagram (the
    actual evidence) never reached the vision-capable LLM path. The
    image-area-ratio signal must catch it independently of caption length."""
    result = from_pdf(diagram_with_short_caption_pdf_bytes, source="diagram-caption.pdf")

    assert result.metadata["vision_fallback_pages"] == [1]
    assert "large_image" in result.metadata["vision_fallback_reasons"][1]
    assert len(result.images) == 1
    assert result.images[0].startswith(b"\x89PNG\r\n\x1a\n")
    # The caption text itself is still correctly extracted as real text.
    assert "Figure 1. Attack diagram." in result.text


def test_diagram_page_with_no_caption_still_flagged_via_sparse_text(
    diagram_with_no_caption_pdf_bytes,
):
    """Control: the same diagram with no caption at all was already correctly
    flagged before this fix (sparse-text signal alone was sufficient) — make
    sure that path still works and now also correctly attributes the
    large-image reason (both signals fire on a captionless diagram page)."""
    result = from_pdf(diagram_with_no_caption_pdf_bytes, source="diagram-no-caption.pdf")

    assert result.metadata["vision_fallback_pages"] == [1]
    reasons = result.metadata["vision_fallback_reasons"][1]
    assert "sparse_text" in reasons
    assert "large_image" in reasons
    assert len(result.images) == 1


def test_normal_text_page_not_flagged_by_image_ratio_check(text_pdf_bytes):
    """No-regression check: a normal text-only page (no embedded images at
    all) must not be affected by the new image-area-ratio signal."""
    result = from_pdf(text_pdf_bytes, source="synthetic-report.pdf")
    assert result.metadata["vision_fallback_pages"] == []
    assert result.metadata["vision_fallback_reasons"] == {}


def test_title_guesser_skips_tlp_classification_banner(banner_title_pdf_bytes):
    """Regression for CRITIQUE-B §1b/§3 MEDIUM: reproduced live on a real CISA
    advisory — the naive "first line of text" title guesser picked the
    'TLP:CLEAR' classification banner as the title instead of the real
    document title on the next line."""
    result = from_pdf(banner_title_pdf_bytes, source="cisa-advisory.pdf")

    assert result.title == "CISA Shares Lessons Learned from an Incident Response Engagement"
    assert "TLP:CLEAR" in result.text  # still present in the body text, just not the title
