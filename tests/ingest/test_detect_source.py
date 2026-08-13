"""Tests for globwarden.ingest.detect_source.load — the auto-detection entry
point the rest of GlobWarden calls. This is the module's most important
function, so it gets the broadest test coverage: URL vs. local file vs. raw
text, and correct dispatch by file extension."""

from __future__ import annotations

from pathlib import Path

import responses

from globwarden.ingest.detect_source import load
from globwarden.models import SourceType


@responses.activate
def test_load_dispatches_http_url_to_url_loader():
    responses.add(
        responses.GET,
        "https://example.test/blog-post",
        body="<html><head><title>T</title></head><body><article><p>"
        "some obfuscation technique description that is long enough to "
        "survive extraction heuristics reliably in this unit test"
        "</p></article></body></html>",
        status=200,
        content_type="text/html",
    )

    result = load("https://example.test/blog-post")

    assert result.source_type == SourceType.URL


@responses.activate
def test_load_dispatches_https_url_to_url_loader():
    responses.add(
        responses.GET,
        "https://example.test/report",
        body="<html><body><p>content</p></body></html>",
        status=200,
        content_type="text/html",
    )
    result = load("https://example.test/report")
    assert result.source_type == SourceType.URL


def test_load_bare_domain_without_scheme_is_not_treated_as_url(tmp_path, monkeypatch):
    # No scheme -> ambiguous with a relative path -> must NOT hit the network.
    # Since "example.com/report" isn't an existing file either, it should
    # fall through to raw text.
    result = load("example.com/report")
    assert result.source_type == SourceType.TEXT
    assert result.text == "example.com/report"


def test_load_pdf_file_dispatches_to_pdf_loader(tmp_path: Path, text_pdf_bytes):
    p = tmp_path / "report.pdf"
    p.write_bytes(text_pdf_bytes)

    result = load(str(p))

    assert result.source_type == SourceType.PDF
    assert "GlobWarden synthetic test report" in result.text


def test_load_image_file_dispatches_to_image_loader(tmp_path: Path, sample_png_bytes):
    p = tmp_path / "diagram.png"
    p.write_bytes(sample_png_bytes)

    result = load(str(p))

    assert result.source_type == SourceType.IMAGE
    assert result.images == [sample_png_bytes]


def test_load_code_file_dispatches_to_text_loader_as_code(tmp_path: Path):
    p = tmp_path / "payload.ps1"
    p.write_text("gal g* | iex")

    result = load(str(p))

    assert result.source_type == SourceType.CODE
    assert "gal g* | iex" in result.text


def test_load_plain_text_file_dispatches_to_text_loader(tmp_path: Path):
    p = tmp_path / "notes.txt"
    p.write_text("some analyst notes")

    result = load(str(p))

    assert result.source_type == SourceType.TEXT


def test_load_raw_text_argument_falls_through_to_text():
    result = load("This is raw threat intel text pasted directly on the CLI, not a path or URL.")

    assert result.source_type == SourceType.TEXT
    assert result.source == "<raw text>"


def test_load_nonexistent_path_like_string_treated_as_raw_text():
    # Looks path-shaped but doesn't exist -> must not raise, must be text.
    result = load("/this/path/definitely/does/not/exist/on/this/machine.txt")
    assert result.source_type == SourceType.TEXT


def test_load_multiline_content_never_misdetected_as_url_or_path():
    content = "line1\nhttps://example.test/looks-like-a-url-but-isnt-the-whole-input\nline3"
    result = load(content)
    assert result.source_type == SourceType.TEXT
    assert result.text == content
