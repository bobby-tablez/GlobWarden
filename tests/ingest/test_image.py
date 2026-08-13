"""Tests for globwarden.ingest.image."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from globwarden.ingest.errors import SizeLimitExceeded, UnsupportedSourceError
from globwarden.ingest.image import MAX_IMAGE_BYTES, from_image
from globwarden.models import SourceType


def test_from_image_raises_clear_error_when_pillow_not_installed(monkeypatch, tmp_path: Path, sample_png_bytes):
    """Regression for the final-integration critique's release-blocking bug
    (same class of issue found for pdfplumber/bs4): a plain `pip install
    globwarden` (no 'image' extra) must fail with a clear, actionable
    UnsupportedSourceError naming the extra to install -- never a raw
    ModuleNotFoundError, and never a misleading 'does not look like a valid
    image' message that implies the file itself (not a missing dependency)
    is the problem."""
    p = tmp_path / "screenshot.png"
    p.write_bytes(sample_png_bytes)

    monkeypatch.setitem(sys.modules, "PIL", None)
    with pytest.raises(UnsupportedSourceError, match=r"globwarden\[image\]"):
        from_image(str(p))


def test_from_image_reads_real_png(tmp_path: Path, sample_png_bytes):
    p = tmp_path / "screenshot.png"
    p.write_bytes(sample_png_bytes)

    result = from_image(str(p))

    assert result.source_type == SourceType.IMAGE
    assert result.source == str(p)
    assert result.text == ""
    assert result.images == [sample_png_bytes]
    assert result.title == "screenshot.png"
    assert result.metadata["bytes"] == len(sample_png_bytes)


def test_from_image_missing_file_raises(tmp_path: Path):
    with pytest.raises(UnsupportedSourceError):
        from_image(str(tmp_path / "nope.png"))


def test_from_image_rejects_non_image_content(tmp_path: Path):
    p = tmp_path / "fake.png"
    p.write_bytes(b"this is definitely not image data")

    with pytest.raises(UnsupportedSourceError):
        from_image(str(p))


def test_from_image_rejects_oversized_file(tmp_path: Path):
    p = tmp_path / "huge.png"
    with open(p, "wb") as f:
        f.seek(MAX_IMAGE_BYTES + 1024)
        f.write(b"\0")

    with pytest.raises(SizeLimitExceeded):
        from_image(str(p))
