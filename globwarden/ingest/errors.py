"""Shared exception types for the ingestion layer.

Every loader in `globwarden/ingest/` raises one of these (never a bare
`Exception`/`requests.RequestException`/etc.) so callers up the pipeline
(the CLI) can catch a single, predictable family and print a clean error
instead of a raw traceback.
"""

from __future__ import annotations


class IngestError(Exception):
    """Base class for all ingestion failures."""


class FetchError(IngestError):
    """Raised when fetching a URL fails outright or returns a non-2xx status."""


class SizeLimitExceeded(IngestError):
    """Raised when a remote response or local file exceeds the configured
    size cap. Exists specifically so a hostile/oversized input (a 10GB fake
    PDF, a zip-bombed page, etc.) fails fast with a clear message instead of
    exhausting memory or hanging the tool."""


class UnsupportedSourceError(IngestError):
    """Raised when a source can't be classified or handled at all (e.g. an
    unreadable local path, or an image file that isn't actually an image)."""


class ParseError(IngestError):
    """Raised when a source was fetched/read successfully but its content
    could not be parsed into usable text (e.g. a corrupt PDF)."""
