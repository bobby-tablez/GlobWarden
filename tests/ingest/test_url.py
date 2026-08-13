"""Tests for globwarden.ingest.url.

Unit tests mock HTTP with the `responses` library (fast, deterministic, no
network). One test at the bottom, marked `live`, actually fetches a real,
stable, public Wikipedia page to prove extraction works end-to-end against
real HTML — no credentials/paid service involved. It's skipped automatically
if there's no network available in the current environment, so it never
breaks an offline test run.
"""

from __future__ import annotations

import socket

import pytest
import requests
import responses

from globwarden.ingest import url as url_module
from globwarden.ingest.errors import FetchError, SizeLimitExceeded
from globwarden.ingest.url import MAX_DOWNLOAD_BYTES, from_url
from globwarden.models import SourceType

SAMPLE_HTML = """
<html>
<head>
<title>Example Report Title</title>
<meta property="og:title" content="Example Report Title (OG)">
</head>
<body>
<nav>Site navigation link soup, not the article</nav>
<header>Header junk</header>
<article>
<h1>Example Report Title</h1>
<p>This report describes a wildcard alias resolution technique used to
obfuscate PowerShell commands, where an analyst uses Get-Alias with a
wildcard pattern to resolve a short alias into a full cmdlet invocation,
defeating simple substring-based detections that look for the literal
cmdlet name.</p>
<p>The technique maps to MITRE ATT&CK T1027.010 and was observed being used
to pipe the resolved alias directly into Invoke-Expression, executing
attacker-controlled code without ever typing the literal string
"Invoke-Expression" in the visible command line.</p>
</article>
<footer>Footer junk, copyright 2024</footer>
</body>
</html>
"""


def test_default_user_agent_is_not_self_identifying_as_a_bot():
    """Regression: the original default UA self-identified as a bot
    ('GlobWarden/... threat-intel ingestion bot ... python-requests') and a
    real source (securonix.com) was confirmed live to return HTTP 403 to it
    while returning 200 to a standard browser UA -- security/threat-intel
    blogs are exactly the kind of site that runs aggressive anti-scraping
    WAFs blocking on sight anything that looks like a scraper. Also
    regression-locks that HONEST_USER_AGENT (the opt-in alternative) points
    at the real repo, not the placeholder URL used before the repo existed."""
    assert "python-requests" not in url_module.DEFAULT_USER_AGENT.lower()
    assert "bot" not in url_module.DEFAULT_USER_AGENT.lower()
    assert "mozilla" in url_module.DEFAULT_USER_AGENT.lower()
    assert "github.com/bobby-tablez/globwarden" in url_module.HONEST_USER_AGENT.lower()


@responses.activate
def test_from_url_sends_default_user_agent_by_default():
    responses.add(
        responses.GET,
        "https://example.test/report",
        body=SAMPLE_HTML,
        status=200,
        content_type="text/html; charset=utf-8",
    )
    from_url("https://example.test/report")
    assert responses.calls[0].request.headers["User-Agent"] == url_module.DEFAULT_USER_AGENT


@responses.activate
def test_from_url_user_agent_override_is_actually_sent():
    responses.add(
        responses.GET,
        "https://example.test/report",
        body=SAMPLE_HTML,
        status=200,
        content_type="text/html; charset=utf-8",
    )
    from_url("https://example.test/report", user_agent="MyCustomAgent/1.0")
    sent = responses.calls[0].request.headers["User-Agent"]
    assert sent == "MyCustomAgent/1.0"
    assert sent != url_module.DEFAULT_USER_AGENT


@responses.activate
def test_from_url_extracts_html_article_text():
    responses.add(
        responses.GET,
        "https://example.test/report",
        body=SAMPLE_HTML,
        status=200,
        content_type="text/html; charset=utf-8",
    )

    result = from_url("https://example.test/report")

    assert result.source_type == SourceType.URL
    assert result.source == "https://example.test/report"
    assert "wildcard alias resolution" in result.text
    assert "T1027.010" in result.text
    # Boilerplate must not leak into the extracted body text.
    assert "Site navigation link soup" not in result.text
    assert "Footer junk" not in result.text
    assert result.title is not None
    assert "Example Report Title" in result.title
    assert result.metadata["status_code"] == 200
    assert result.metadata["extractor"] in ("trafilatura", "bs4-heuristic")


@responses.activate
def test_from_url_non_2xx_raises_fetch_error():
    responses.add(responses.GET, "https://example.test/missing", status=404)

    with pytest.raises(FetchError):
        from_url("https://example.test/missing")


@responses.activate
def test_from_url_connection_error_raises_fetch_error():
    responses.add(
        responses.GET,
        "https://example.test/down",
        body=requests.exceptions.ConnectionError("connection refused"),
    )

    with pytest.raises(FetchError):
        from_url("https://example.test/down")


@responses.activate
def test_from_url_respects_content_length_cap():
    responses.add(
        responses.GET,
        "https://example.test/huge",
        status=200,
        headers={"Content-Length": str(MAX_DOWNLOAD_BYTES + 1)},
        body="x" * 100,  # body itself is small; the declared header is what should trip the cap
        content_type="text/html",
    )

    with pytest.raises(SizeLimitExceeded):
        from_url("https://example.test/huge")


@responses.activate
def test_from_url_pdf_content_type_dispatches_to_pdf_path(text_pdf_bytes):
    responses.add(
        responses.GET,
        "https://example.test/report.pdf",
        body=text_pdf_bytes,
        status=200,
        content_type="application/pdf",
    )

    result = from_url("https://example.test/report.pdf")

    assert result.source_type == SourceType.PDF
    assert "GlobWarden synthetic test report" in result.text


@responses.activate
def test_from_url_detects_pdf_by_magic_bytes_even_without_content_type(text_pdf_bytes):
    responses.add(
        responses.GET,
        "https://example.test/download",
        body=text_pdf_bytes,
        status=200,
        content_type="application/octet-stream",
    )

    result = from_url("https://example.test/download")

    assert result.source_type == SourceType.PDF


# --- Regression tests: HIGH-severity fixes from CRITIQUE-B.md -------------


@responses.activate
def test_from_url_pdf_gets_pdf_specific_cap_not_generic_url_cap(text_pdf_bytes):
    """Regression for CRITIQUE-B §1f/§3 HIGH: a PDF response used to be
    capped at the generic web-page byte cap (`max_bytes`) before its
    Content-Type was ever consulted, so a legitimate PDF between the generic
    cap and the larger PDF-specific cap was rejected. Uses a deliberately
    tiny generic cap (well under the fixture's size) and a generous PDF cap
    to prove the PDF cap — not the generic one — is what actually applies,
    without needing a multi-megabyte body in this fast unit test (see
    `test_from_url_real_30mb_pdf_succeeds_under_default_caps` below for the
    full-scale, real-byte-count version of this same regression)."""
    responses.add(
        responses.GET,
        "https://example.test/report.pdf",
        body=text_pdf_bytes,
        status=200,
        content_type="application/pdf",
    )
    tiny_generic_cap = 50
    generous_pdf_cap = 10 * 1024 * 1024
    assert len(text_pdf_bytes) > tiny_generic_cap  # the fixture must actually exceed it

    result = from_url(
        "https://example.test/report.pdf",
        max_bytes=tiny_generic_cap,
        max_pdf_bytes=generous_pdf_cap,
    )

    assert result.source_type == SourceType.PDF


@responses.activate
def test_from_url_non_pdf_still_bound_by_generic_cap():
    """No-regression check: the PDF-cap fix must not loosen the cap for
    non-PDF responses — an oversized HTML page is still rejected at the
    (tiny, in this test) generic cap, never promoted to the PDF cap."""
    responses.add(
        responses.GET,
        "https://example.test/huge-page",
        body="<html><body>" + ("x" * 200) + "</body></html>",
        status=200,
        content_type="text/html",
    )

    with pytest.raises(SizeLimitExceeded):
        from_url(
            "https://example.test/huge-page",
            max_bytes=50,
            max_pdf_bytes=10 * 1024 * 1024,
        )


@responses.activate
def test_from_url_pdf_via_sniffed_magic_bytes_also_gets_upgraded_cap(text_pdf_bytes):
    """Same regression as above, but for a PDF response with a mislabeled/
    missing Content-Type — the magic-byte sniff must upgrade the cap
    mid-stream too, not just the Content-Type-declared path."""
    responses.add(
        responses.GET,
        "https://example.test/download",
        body=text_pdf_bytes,
        status=200,
        content_type="application/octet-stream",
    )
    tiny_generic_cap = 50
    assert len(text_pdf_bytes) > tiny_generic_cap

    result = from_url(
        "https://example.test/download",
        max_bytes=tiny_generic_cap,
        max_pdf_bytes=10 * 1024 * 1024,
    )

    assert result.source_type == SourceType.PDF


@responses.activate
def test_from_url_real_30mb_pdf_succeeds_under_default_caps(large_valid_pdf_bytes):
    """Full-scale version of the cap regression, using the *actual* default
    caps (no overrides) and a genuinely ~30MB, real, valid, parseable PDF —
    the same scale and construction the critic used to find this bug live.
    Confirms real request/response mechanics (streaming, Content-Length
    absent, magic-byte-independent Content-Type path) all still hold at
    realistic size, not just via mocked-small proxies."""
    assert MAX_DOWNLOAD_BYTES < len(large_valid_pdf_bytes) < url_module.MAX_PDF_BYTES

    responses.add(
        responses.GET,
        "https://example.test/big-report.pdf",
        body=large_valid_pdf_bytes,
        status=200,
        content_type="application/pdf",
    )

    result = from_url("https://example.test/big-report.pdf")

    assert result.source_type == SourceType.PDF
    assert result.metadata["pages"] == 1


@responses.activate
def test_bs4_fallback_strips_comments_and_ad_markers_not_just_nav():
    """Regression for CRITIQUE-B §1c/§3 MEDIUM: forcing the bs4 fallback path
    (trafilatura unavailable) against a page shaped like the real Krebs on
    Security article the critic tested — reader comments in a
    WordPress-style '#comments' container, a literal "Advertisement" marker,
    and a "Comments are closed." footer line — must no longer be folded
    indistinguishably into the extracted article text."""
    html = """
    <html><head><title>Real Article</title></head>
    <body>
    <nav>site nav</nav>
    <article>
    <p>This is the real reporting body text about an obfuscation technique
    used in a recent campaign, described in enough detail to be a realistic
    article body for this regression test.</p>
    </article>
    <div id="comments-area" class="comments">
    <p>READER COMMENT: EXACTLY HOW are LG and Samsung allowing this junk</p>
    </div>
    <div class="advertisement-banner">Advertisement</div>
    <p>Comments are closed.</p>
    <p>&copy; Krebs on Security - Mastodon</p>
    </body></html>
    """
    responses.add(
        responses.GET,
        "https://example.test/krebs-style-article",
        body=html,
        status=200,
        content_type="text/html",
    )

    original_trafilatura = url_module.trafilatura
    url_module.trafilatura = None
    try:
        result = from_url("https://example.test/krebs-style-article")
    finally:
        url_module.trafilatura = original_trafilatura

    assert result.metadata["extractor"] == "bs4-heuristic"
    assert "READER COMMENT" not in result.text
    assert "Advertisement" not in result.text
    assert "Comments are closed" not in result.text
    assert "Mastodon" not in result.text
    assert "real reporting body text" in result.text


def _has_network() -> bool:
    try:
        socket.create_connection(("en.wikipedia.org", 443), timeout=3).close()
        return True
    except OSError:
        return False


def test_bs4_fallback_raises_clear_error_when_bs4_not_installed(monkeypatch):
    """Regression for the final-integration critique's release-blocking bug:
    a plain `pip install globwarden` (no 'web' extra) means neither
    trafilatura nor bs4 is present. The bs4 fallback must fail with a clear,
    actionable FetchError naming the extra to install -- never a raw
    ModuleNotFoundError, and never breaking `globwarden.ingest`'s own
    importability for every source type."""
    monkeypatch.setattr(url_module, "trafilatura", None)
    monkeypatch.setattr(url_module, "BeautifulSoup", None)
    with pytest.raises(FetchError, match=r"globwarden\[web\]"):
        url_module._extract_html("<html><body><p>hi</p></body></html>", "https://example.com")


def test_bs4_title_degrades_gracefully_without_bs4(monkeypatch):
    """Title enrichment is a nice-to-have on the trafilatura-success path --
    it must never be fatal just because bs4 (an optional dependency) is
    absent."""
    monkeypatch.setattr(url_module, "BeautifulSoup", None)
    assert url_module._bs4_title("<html><title>hi</title></html>") is None


@pytest.mark.skipif(not _has_network(), reason="no network access available in this environment")
def test_from_url_live_wikipedia_fetch():
    """Real, live, public, free URL — no auth/paid service. Proves the
    extraction path actually works against real-world HTML, not just the
    hand-crafted fixture above."""
    result = from_url("https://en.wikipedia.org/wiki/Python_(programming_language)")

    assert result.source_type == SourceType.URL
    assert result.metadata["status_code"] == 200
    assert len(result.text) > 500
    assert "python" in result.text.lower()
    assert result.title is not None
    assert "python" in result.title.lower()
