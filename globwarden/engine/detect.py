"""Obfuscation-finding extraction: `IngestedContent` -> `list[ObfuscationFinding]`.

Calls the configured LLM provider with `prompts.DETECTION_SYSTEM_PROMPT` plus the
content's text (and images, for vision-capable providers), then parses and
validates the response defensively — LLMs do not reliably return perfectly valid
JSON even when asked to.

Chunking strategy (see `_chunk_text` docstring for the full tradeoff discussion):
long text content is split into overlapping character-based chunks so a single
call never blows past typical context limits; each chunk is sent as an
independent detection call and the resulting findings are merged and re-numbered.
"""

from __future__ import annotations

import logging

from globwarden.engine._parsing import JSONExtractionError, extract_json_object
from globwarden.engine.prompts import DETECTION_SYSTEM_PROMPT, DETECTION_USER_PROMPT_TEMPLATE
from globwarden.llm.base import LLMProvider
from globwarden.models import IngestedContent, ObfuscationCategory, ObfuscationFinding

logger = logging.getLogger(__name__)

# Character budget per chunk. This is a deliberately conservative, model-agnostic
# proxy for "tokens" (roughly 4 chars/token for English/code text, so ~12000 chars
# is ~3000 tokens) — good enough to stay well clear of small local-model context
# windows (e.g. an 8k-context Ollama model) without needing per-provider tokenizer
# awareness in the engine layer.
DEFAULT_MAX_CHUNK_CHARS = 12_000
# Overlap between consecutive chunks, so a technique whose description/example
# straddles a chunk boundary is still likely to appear whole in at least one chunk.
DEFAULT_CHUNK_OVERLAP_CHARS = 500


class DetectionError(Exception):
    """Raised when a detection call's response cannot be recovered as usable
    findings at all (as opposed to individual malformed findings, which are
    skipped with a warning rather than raising)."""


def _chunk_text(
    text: str,
    max_chars: int = DEFAULT_MAX_CHUNK_CHARS,
    overlap: int = DEFAULT_CHUNK_OVERLAP_CHARS,
) -> list[str]:
    """Split `text` into overlapping chunks of at most `max_chars` characters.

    Strategy: naive character-window slicing with overlap, not sentence/paragraph-
    aware splitting. This is a deliberate simplicity-over-precision tradeoff:

    - Pro: trivial to reason about, provider-agnostic (no tokenizer dependency),
      guarantees a hard upper bound on prompt size regardless of input shape.
    - Con: a chunk boundary can fall in the middle of a code block or sentence.
      The overlap window mitigates but does not eliminate this — a technique
      whose only description spans more than `overlap` characters across a
      boundary can still be missed or reported twice (see dedup note below).
    - Con: cross-chunk context is lost. If paragraph 1 sets up "the following
      three examples all use technique X" and the examples themselves land in a
      later chunk, the LLM analyzing that later chunk in isolation may not know
      to attribute them to X. For a tool whose primary inputs are blog-post/report
      -length content (typically well under one chunk) this is a rare edge case,
      not the common path — but it's a real, honest limitation for very long
      reports (e.g. a 50-page PDF ingested as one big text blob).
    - Duplicate findings across overlapping chunks are possible (the same example
      snippet appearing in two adjacent chunks' overlap region and being reported
      twice). `find_obfuscation` does not deduplicate by content — it renumbers
      ids sequentially across all chunks and returns everything. This is a
      conscious "don't drop signal" choice: a human analyst reviewing output can
      recognize and discard a near-duplicate far more reliably than this tool can
      auto-merge them without risking false negatives.

    If `text` fits in a single chunk, returns `[text]` (or `[""]` for empty text,
    so callers always get at least one chunk to send).
    """
    if not text:
        return [""]
    if len(text) <= max_chars:
        return [text]

    chunks: list[str] = []
    start = 0
    text_len = len(text)
    step = max_chars - overlap
    if step <= 0:  # pragma: no cover - defensive, overlap should always be < max_chars
        step = max_chars

    while start < text_len:
        end = min(start + max_chars, text_len)
        chunks.append(text[start:end])
        if end >= text_len:
            break
        start += step

    return chunks


def _validate_finding(raw: dict, fallback_id: str) -> ObfuscationFinding | None:
    """Validate and coerce a single raw finding dict into an `ObfuscationFinding`.

    Returns None (and logs a warning) rather than raising, so one malformed entry
    in an otherwise-good response doesn't discard every other finding.
    """
    if not isinstance(raw, dict):
        logger.warning("Skipping non-object finding entry: %r", raw)
        return None

    category_raw = raw.get("category")
    try:
        category = ObfuscationCategory(category_raw)
    except ValueError:
        logger.warning(
            "Skipping finding %r: category %r is not a valid ObfuscationCategory",
            raw.get("id", fallback_id),
            category_raw,
        )
        return None

    technique_name = raw.get("technique_name")
    description = raw.get("description")
    if not technique_name or not description:
        logger.warning(
            "Skipping finding %r: missing required technique_name/description",
            raw.get("id", fallback_id),
        )
        return None

    confidence_raw = raw.get("confidence", 0.5)
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    example_snippet = raw.get("example_snippet") or None
    attack_mapping = raw.get("attack_mapping") or "T1027.010 (parent: T1027)"
    source_ref = raw.get("source_ref") or None

    return ObfuscationFinding(
        id=fallback_id,
        category=category,
        technique_name=str(technique_name),
        description=str(description),
        example_snippet=str(example_snippet) if example_snippet else None,
        confidence=confidence,
        attack_mapping=str(attack_mapping),
        source_ref=str(source_ref) if source_ref else None,
    )


def _detect_in_chunk(
    content: IngestedContent,
    chunk_text: str,
    provider: LLMProvider,
    chunk_note: str,
    include_images: bool,
) -> list[dict]:
    """Run one detection call against a single chunk and return raw finding dicts
    (not yet validated against the dataclass/enum — that happens in the caller so
    ids can be assigned globally across all chunks)."""
    user_prompt = DETECTION_USER_PROMPT_TEMPLATE.format(
        source=content.source,
        chunk_note=chunk_note,
        content=chunk_text if chunk_text else "(no extracted text — see attached image(s), if any)",
    )
    images = content.images if (include_images and content.images) else None
    response = provider.complete(
        system_prompt=DETECTION_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        images=images,
        json_mode=True,
    )

    try:
        parsed = extract_json_object(response.text)
    except JSONExtractionError as exc:
        raise DetectionError(
            f"Provider '{provider.name}' returned a response that could not be "
            f"parsed as JSON for source '{content.source}': {exc}"
        ) from exc

    if not isinstance(parsed, dict) or "findings" not in parsed:
        raise DetectionError(
            f"Provider '{provider.name}' returned valid JSON but it did not match "
            f"the expected {{'findings': [...]}} shape for source '{content.source}'. "
            f"Got top-level keys: {list(parsed.keys()) if isinstance(parsed, dict) else type(parsed)}"
        )

    findings_raw = parsed["findings"]
    if not isinstance(findings_raw, list):
        raise DetectionError(
            f"Provider '{provider.name}' returned a 'findings' value that is not "
            f"a list (got {type(findings_raw).__name__}) for source '{content.source}'."
        )
    return findings_raw


def find_obfuscation(content: IngestedContent, provider: LLMProvider) -> list[ObfuscationFinding]:
    """Extract T1027.010-style obfuscation findings from ingested content.

    Long `content.text` is chunked (see `_chunk_text`) so each provider call stays
    within a conservative character budget; findings from all chunks are merged
    and re-numbered sequentially ("f1", "f2", ...) in the order encountered.

    Images (if present on `content` and the provider supports vision) are attached
    to every chunk's call — simplest correct behavior, though it does mean
    multi-chunk text content re-sends the same image bytes on each call. For the
    common case (short-to-medium report content, one chunk) this has no cost.

    Raises `DetectionError` if a chunk's response cannot be recovered as usable
    JSON at all. Individual malformed *findings* within an otherwise-parseable
    response are skipped with a logged warning, not treated as a hard failure.
    """
    chunks = _chunk_text(content.text)
    multi_chunk = len(chunks) > 1

    all_raw_findings: list[dict] = []
    for i, chunk in enumerate(chunks):
        chunk_note = (
            f"\nNote: this is chunk {i + 1} of {len(chunks)} from a longer document. "
            "Only report techniques actually present in THIS chunk's text.\n"
            if multi_chunk
            else ""
        )
        raw_findings = _detect_in_chunk(
            content,
            chunk,
            provider,
            chunk_note,
            include_images=True,
        )
        all_raw_findings.extend(raw_findings)

    findings: list[ObfuscationFinding] = []
    for i, raw in enumerate(all_raw_findings, start=1):
        finding = _validate_finding(raw, fallback_id=f"f{i}")
        if finding is not None:
            finding.id = f"f{len(findings) + 1}"
            findings.append(finding)

    return findings
