"""Tests for globwarden.ingest.text: raw-string vs. file-path detection, and
TEXT vs. CODE classification by extension."""

from __future__ import annotations

from pathlib import Path

import pytest

from globwarden.ingest.errors import SizeLimitExceeded
from globwarden.ingest.text import MAX_TEXT_BYTES, from_text
from globwarden.models import SourceType


def test_raw_string_content_is_text():
    result = from_text("Get-Alias g* | iex some payload string content here")

    assert result.source_type == SourceType.TEXT
    assert result.source == "<raw text>"
    assert "Get-Alias" in result.text
    assert result.metadata["origin"] == "raw_string"


def test_multiline_raw_string_is_never_treated_as_a_path():
    content = "line one\nline two\nline three, definitely not a filesystem path"
    result = from_text(content)
    assert result.source_type == SourceType.TEXT
    assert result.text == content


def test_plain_txt_file_is_text(tmp_path: Path):
    p = tmp_path / "notes.txt"
    p.write_text("some plain text notes about a technique")

    result = from_text(str(p))

    assert result.source_type == SourceType.TEXT
    assert result.source == str(p)
    assert "some plain text notes" in result.text
    assert result.metadata["origin"] == "file"


@pytest.mark.parametrize("ext", [".py", ".ps1", ".sh", ".js"])
def test_recognized_code_extensions_classified_as_code(tmp_path: Path, ext):
    p = tmp_path / f"script{ext}"
    p.write_text("echo hello")

    result = from_text(str(p))

    assert result.source_type == SourceType.CODE
    assert result.metadata["extension"] == ext


def test_unrecognized_extension_falls_back_to_text(tmp_path: Path):
    p = tmp_path / "data.csv"
    p.write_text("a,b,c\n1,2,3")

    result = from_text(str(p))

    assert result.source_type == SourceType.TEXT


def test_from_text_accepts_path_object(tmp_path: Path):
    p = tmp_path / "script.py"
    p.write_text("print('hi')")

    result = from_text(p)

    assert result.source_type == SourceType.CODE
    assert result.source == str(p)


def test_oversized_raw_string_rejected():
    with pytest.raises(SizeLimitExceeded):
        from_text("x" * (MAX_TEXT_BYTES + 1))


def test_oversized_file_rejected(tmp_path: Path):
    p = tmp_path / "huge.txt"
    with open(p, "wb") as f:
        f.seek(MAX_TEXT_BYTES + 1024)
        f.write(b"\0")

    with pytest.raises(SizeLimitExceeded):
        from_text(str(p))


def test_string_that_looks_like_a_nonexistent_path_is_treated_as_text(tmp_path: Path):
    missing = str(tmp_path / "does-not-exist.ps1")
    result = from_text(missing)
    # The path doesn't exist on disk, so it must be treated as literal content.
    assert result.source_type == SourceType.TEXT
    assert result.text == missing
