"""Tests for globwarden.ingest.url.

Unit tests mock HTTP with the `responses` library (fast, deterministic, no
network). One test at the bottom, marked `live`, actually fetches a real,
stable, public Wikipedia page to prove extraction works end-to-end against
real HTML — no credentials/paid service involved. It's skipped automatically
if there's no network available in the current environment, so it never
breaks an offline test run.
"""

from __future__ import annotations

import io
import socket

import pytest
import requests
import responses

from globwarden.ingest import url as url_module
from globwarden.ingest.errors import FetchError, SizeLimitExceeded
from globwarden.ingest.url import MAX_DOWNLOAD_BYTES, from_url
from globwarden.models import SourceType


def _build_content_png(width: int = 400, height: int = 300) -> bytes:
    """A real, decodable PNG large enough (by decoded pixel dimensions) to
    clear `MIN_DECODED_IMAGE_DIMENSION` -- stands in for "a legible embedded
    screenshot of an obfuscated command," as opposed to a tiny icon/avatar."""
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    draw.rectangle((10, 10, width - 10, height - 10), outline="black")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


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


# --- Embedded <img> extraction ---------------------------------------------


@responses.activate
def test_from_url_downloads_large_embedded_img_in_article_body():
    """A real, content-sized screenshot embedded as an <img> in the article
    body (the "screenshot of a PowerShell one-liner in a blog post" shape
    this feature exists for) must be downloaded and land in
    `IngestedContent.images`."""
    png_bytes = _build_content_png(800, 600)
    html = """
    <html><head><title>Report With Screenshot</title></head>
    <body>
    <nav>nav junk, not the article</nav>
    <article>
    <p>This report describes an obfuscation technique used to hide a
    PowerShell one-liner, with a terminal capture included below showing the
    exact command as it was observed on the compromised host.</p>
    <img src="/media/screenshot-obfuscated-command.png" width="800" height="600" alt="terminal capture">
    <p>The screenshot above shows the resolved alias being piped directly
    into Invoke-Expression, matching MITRE ATT&CK T1027.010.</p>
    </article>
    </body></html>
    """
    responses.add(
        responses.GET,
        "https://example.test/report",
        body=html,
        status=200,
        content_type="text/html",
    )
    responses.add(
        responses.GET,
        "https://example.test/media/screenshot-obfuscated-command.png",
        body=png_bytes,
        status=200,
        content_type="image/png",
    )

    result = from_url("https://example.test/report")

    assert result.images == [png_bytes]
    assert result.metadata["embedded_images_found"] == 1
    assert result.metadata["embedded_images_kept"] == 1
    assert len(responses.calls) == 2  # the page, then the one image


@responses.activate
def test_from_url_skips_icon_sized_images_without_downloading_them():
    """Icon-shaped images -- one filtered by a tiny HTML width/height
    attribute, one by an obvious non-content filename pattern -- must never
    even be requested: the cheap, no-download filter should reject both
    before any HTTP call is made for them."""
    html = """
    <html><head><title>Article With Icons</title></head>
    <body>
    <article>
    <p>Real article paragraph text describing an obfuscation technique in
    enough detail to be a realistic body for this regression test.</p>
    <img src="/img/nav-icon.png" width="16" height="16" alt="icon">
    <img src="/img/social-share.png" alt="share this post">
    <p>Additional real paragraph text continues the article body here, well
    past any minimum-length heuristics an extractor might apply.</p>
    </article>
    </body></html>
    """
    responses.add(
        responses.GET,
        "https://example.test/icons-article",
        body=html,
        status=200,
        content_type="text/html",
    )
    # Registered (but must never be called) so a stray request would be
    # counted in responses.calls rather than silently raising inside the
    # implementation's own error handling and masking the bug.
    responses.add(
        responses.GET,
        "https://example.test/img/nav-icon.png",
        body=_build_content_png(),
        status=200,
        content_type="image/png",
    )
    responses.add(
        responses.GET,
        "https://example.test/img/social-share.png",
        body=_build_content_png(),
        status=200,
        content_type="image/png",
    )

    result = from_url("https://example.test/icons-article")

    assert result.images == []
    assert result.metadata["embedded_images_found"] == 0
    assert result.metadata["embedded_images_kept"] == 0
    assert len(responses.calls) == 1  # only the page itself, neither icon was fetched


@responses.activate
def test_from_url_caps_number_of_embedded_images_downloaded():
    """A page with more candidate images than
    `url_module.MAX_EMBEDDED_IMAGES_KEPT` must only download/keep up to the
    cap, taking candidates in document order and stopping once the cap is
    reached rather than attempting every candidate."""
    cap = url_module.MAX_EMBEDDED_IMAGES_KEPT
    n_images = cap + 2
    png_bytes = _build_content_png(400, 300)

    img_tags = "\n".join(
        f'<img src="/media/screenshot-{i}.png" width="400" height="300" alt="screenshot {i}">' for i in range(n_images)
    )
    html = f"""
    <html><head><title>Report With Many Screenshots</title></head>
    <body><article>
    <p>Real article text describing several obfuscation technique variants,
    each illustrated below with its own terminal capture screenshot.</p>
    {img_tags}
    <p>Closing paragraph of real article body text.</p>
    </article></body></html>
    """
    responses.add(
        responses.GET,
        "https://example.test/many-screenshots",
        body=html,
        status=200,
        content_type="text/html",
    )
    for i in range(n_images):
        responses.add(
            responses.GET,
            f"https://example.test/media/screenshot-{i}.png",
            body=png_bytes,
            status=200,
            content_type="image/png",
        )

    result = from_url("https://example.test/many-screenshots")

    assert len(result.images) == cap
    assert result.metadata["embedded_images_found"] == n_images
    assert result.metadata["embedded_images_kept"] == cap
    assert len(responses.calls) == 1 + cap  # the page, then only the first `cap` images


@responses.activate
def test_from_url_with_no_img_tags_makes_no_image_requests():
    """A page with zero <img> tags at all must behave exactly as it did
    before this feature existed: `images == []`, zero extra HTTP requests."""
    responses.add(
        responses.GET,
        "https://example.test/report",
        body=SAMPLE_HTML,
        status=200,
        content_type="text/html; charset=utf-8",
    )

    result = from_url("https://example.test/report")

    assert result.images == []
    assert result.metadata["embedded_images_found"] == 0
    assert result.metadata["embedded_images_kept"] == 0
    assert len(responses.calls) == 1  # only the page itself


@responses.activate
def test_from_url_broken_embedded_image_does_not_fail_whole_fetch():
    """One image URL that 404s must not fail the whole `from_url` call --
    the page's text is still returned successfully, just without that one
    image."""
    html = """
    <html><head><title>Report With A Dead Screenshot Link</title></head>
    <body><article>
    <p>This report describes a wildcard alias resolution technique used to
    obfuscate PowerShell commands, illustrated below with a terminal capture
    that unfortunately no longer resolves.</p>
    <img src="/media/gone.png" width="800" height="600" alt="terminal capture">
    <p>The technique maps to MITRE ATT&CK T1027.010.</p>
    </article></body></html>
    """
    responses.add(
        responses.GET,
        "https://example.test/dead-image-report",
        body=html,
        status=200,
        content_type="text/html",
    )
    responses.add(
        responses.GET,
        "https://example.test/media/gone.png",
        status=404,
    )

    result = from_url("https://example.test/dead-image-report")

    assert "wildcard alias resolution" in result.text
    assert "T1027.010" in result.text
    assert result.images == []
    assert result.metadata["embedded_images_found"] == 1
    assert result.metadata["embedded_images_kept"] == 0


@responses.activate
def test_from_url_non_content_filter_only_checks_filename_not_full_url():
    """Regression: the non-content filename filter (icon/logo/tracking/etc.)
    used to be checked against the *entire resolved URL* -- domain, path, and
    query string -- not just the filename. That meant an otherwise-clean
    content-screenshot filename with an unrelated tracking/campaign query
    param appended (very common on real CDN-served blog images, e.g.
    "?utm_source=social&utm_campaign=share") got wrongly rejected purely
    because of the query string. The filter must only look at the filename
    (the last path segment), not the query string or domain."""
    png_bytes = _build_content_png(800, 600)
    html = """
    <html><head><title>Report</title></head>
    <body><article>
    <p>Real article text describing an obfuscation technique, illustrated
    below with a terminal capture screenshot.</p>
    <img src="/media/obfuscated-command-capture.png?utm_source=social&amp;utm_campaign=share" width="800" height="600">
    <p>Closing paragraph of real article body text.</p>
    </article></body></html>
    """
    responses.add(
        responses.GET,
        "https://example.test/query-string-report",
        body=html,
        status=200,
        content_type="text/html",
    )
    responses.add(
        responses.GET,
        "https://example.test/media/obfuscated-command-capture.png?utm_source=social&utm_campaign=share",
        body=png_bytes,
        status=200,
        content_type="image/png",
    )

    result = from_url("https://example.test/query-string-report")

    assert result.images == [png_bytes]
    assert result.metadata["embedded_images_kept"] == 1


@responses.activate
def test_from_url_stops_attempting_images_once_time_budget_is_spent(monkeypatch):
    """Regression: with no aggregate time budget, a page whose images are all
    slow could burn a full per-request timeout on every single candidate in
    sequence. A tiny budget forces the loop to stop attempting further
    candidates once it's spent, even though the cap on kept images hasn't
    been reached."""
    monkeypatch.setattr(url_module, "MAX_EMBEDDED_IMAGES_TOTAL_SECONDS", 0.15)

    def _slow_image_response(request):
        import time

        time.sleep(0.1)
        return (200, {"Content-Type": "image/png"}, _build_content_png())

    html = """
    <html><head><title>Report With Slow Images</title></head>
    <body><article>
    <p>Real article text describing an obfuscation technique, illustrated
    below with several terminal capture screenshots.</p>
    <img src="/media/slow-1.png" width="800" height="600">
    <img src="/media/slow-2.png" width="800" height="600">
    <img src="/media/slow-3.png" width="800" height="600">
    <img src="/media/slow-4.png" width="800" height="600">
    <img src="/media/slow-5.png" width="800" height="600">
    <p>Closing paragraph of real article body text.</p>
    </article></body></html>
    """
    responses.add(responses.GET, "https://example.test/slow-images-report", body=html, status=200, content_type="text/html")
    for i in range(1, 6):
        responses.add_callback(responses.GET, f"https://example.test/media/slow-{i}.png", callback=_slow_image_response)

    result = from_url("https://example.test/slow-images-report")

    # 5 candidates found, but the 0.15s budget (each attempt costs ~0.1s)
    # should cut the loop off well before all 5 are attempted.
    assert result.metadata["embedded_images_found"] == 5
    assert result.metadata["embedded_images_kept"] < 5


class TestImageByteValidation:
    """Direct unit tests for the magic-byte + Pillow-degradation validation
    logic, isolated from the HTTP layer."""

    def test_real_png_passes(self):
        assert url_module._passes_decoded_pixel_check(_build_content_png(400, 300)) is True

    def test_non_image_garbage_is_rejected(self):
        assert url_module._passes_decoded_pixel_check(b"not an image, just text pretending to be one") is False

    def test_html_error_page_bytes_are_rejected(self):
        # The realistic failure mode this regression guards against: a
        # misconfigured server returns an HTML error page with a 200 status
        # and an image Content-Type header -- the bytes themselves are not
        # image data and must never be forwarded to a vision LLM as if they
        # were.
        fake_error_page = b"<html><body><h1>404 Not Found</h1></body></html>"
        assert url_module._passes_decoded_pixel_check(fake_error_page) is False

    def test_non_image_garbage_is_rejected_even_without_pillow(self, monkeypatch):
        # Regression: previously, with Pillow unavailable, validation was
        # skipped entirely (return True unconditionally) -- any bytes at all,
        # image or not, were accepted. The magic-byte check must still catch
        # non-image content even when Pillow can't be imported.
        import builtins

        real_import = builtins.__import__

        def _blocked_import(name, *args, **kwargs):
            if name == "PIL" or name.startswith("PIL."):
                raise ImportError("simulated: Pillow not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _blocked_import)

        assert url_module._passes_decoded_pixel_check(b"not an image at all") is False

    def test_real_png_still_accepted_without_pillow(self, monkeypatch):
        # And the flip side: real image bytes are still accepted when Pillow
        # is unavailable -- only the authoritative pixel-dimension check is
        # skipped, not the magic-byte sniff.
        import builtins

        real_import = builtins.__import__
        real_png = _build_content_png(400, 300)

        def _blocked_import(name, *args, **kwargs):
            if name == "PIL" or name.startswith("PIL."):
                raise ImportError("simulated: Pillow not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _blocked_import)

        assert url_module._passes_decoded_pixel_check(real_png) is True
