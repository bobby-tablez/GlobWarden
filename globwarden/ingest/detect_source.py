"""Auto-detect what kind of source a single string argument refers to, and
dispatch to the right loader.

This is the function the CLI actually calls (`globwarden scan <source>`):
`ingest.detect_source.load(source) -> IngestedContent`. Detection order,
each check strictly narrowing what's left:

1. **URL** — has an http(s) scheme (`urllib.parse.urlparse`, not a regex
   guess). A bare `example.com/report` with no scheme is deliberately *not*
   treated as a URL — that's ambiguous with a relative file path, and
   guessing wrong here would silently send a local path out over the network
   or vice versa. Callers who mean a URL should include the scheme, which is
   the normal way people paste URLs anyway.
2. **Existing local file path** — `Path(source).expanduser().is_file()`.
   Dispatched by extension:
   - `.pdf` -> `ingest.pdf.from_pdf`
   - a recognized image extension -> `ingest.image.from_image`
   - anything else -> `ingest.text.from_text` (which further splits into
     `TEXT` vs `CODE` by extension)
3. **Otherwise** — treated as raw text content passed directly on the command
   line, and handed to `ingest.text.from_text` as a raw string.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from globwarden.ingest.image import IMAGE_EXTENSIONS, from_image
from globwarden.ingest.pdf import from_pdf
from globwarden.ingest.text import from_text
from globwarden.ingest.url import from_url
from globwarden.models import IngestedContent

# Schemes we treat as "this is a URL, fetch it over the network." Deliberately
# narrow (no ftp/file/etc.) since those aren't things the rest of the pipeline
# knows how to handle, and a stray "file://" argument is far more likely to be
# a mistaken path than an intentional URL.
_URL_SCHEMES = {"http", "https"}


def load(source: str, *, user_agent: str | None = None) -> IngestedContent:
    """Detect what `source` is and load it into `IngestedContent`.

    `source` is a single string: a URL, a local file path, or raw text
    content. This is the one function the rest of GlobWarden's pipeline
    calls to turn a CLI argument into ingested content.

    `user_agent`, if given, overrides `ingest.url.DEFAULT_USER_AGENT` for URL
    fetches only -- ignored for every other source type.
    """
    if not isinstance(source, str):
        raise TypeError(f"load() expects a str, got {type(source).__name__}")

    if _looks_like_url(source):
        return from_url(source, user_agent=user_agent)

    path = _existing_file_path(source)
    if path is not None:
        extension = path.suffix.lower()
        if extension == ".pdf":
            return from_pdf(path)
        if extension in IMAGE_EXTENSIONS:
            return from_image(path)
        return from_text(path)

    # Not a URL, not a path on disk: treat the argument as literal content.
    return from_text(source)


def _looks_like_url(source: str) -> bool:
    if "\n" in source:
        return False  # multi-line input can't be a URL argument
    try:
        parsed = urlparse(source)
    except ValueError:
        return False
    return parsed.scheme.lower() in _URL_SCHEMES and bool(parsed.netloc)


def _existing_file_path(source: str) -> Path | None:
    if "\n" in source or "\x00" in source or not source.strip():
        return None
    if len(source) > 4096:  # longer than any real filesystem path (PATH_MAX)
        return None
    try:
        candidate = Path(source).expanduser()
        if candidate.is_file():
            return candidate
    except OSError:
        return None
    return None
