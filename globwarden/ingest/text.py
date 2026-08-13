"""Load plain text or code/script content, from either a file path or a raw
string passed directly.

`from_text` has to figure out, given a single argument, whether it's "a path
to a file on disk" or "the actual content, already in hand." The rule: if the
argument is an existing file on disk (and doesn't contain characters no real
path would — a newline, a NUL byte), it's a path; otherwise it's treated as
the raw content itself. This mirrors the same "is it a path or not" judgment
call `detect_source.load` makes for the whole pipeline, kept local here so
`from_text` is independently correct even if called directly.
"""

from __future__ import annotations

from pathlib import Path

from globwarden.ingest.errors import SizeLimitExceeded
from globwarden.models import IngestedContent, SourceType

# Real scripts/reports are essentially always well under this; 20MB guards
# against accidentally pointing this at a huge log dump or being handed an
# enormous raw string.
MAX_TEXT_BYTES = 20 * 1024 * 1024

# Extensions treated as CODE rather than plain TEXT. This only changes how
# the finding-detection prompt frames the content later in the pipeline (e.g.
# "here is a script" vs. "here is prose") — not core ingestion behavior — so
# the list favors coverage of common script/source types over completeness.
CODE_EXTENSIONS = {
    ".py",
    ".ps1",
    ".psm1",
    ".psd1",
    ".sh",
    ".bash",
    ".zsh",
    ".js",
    ".mjs",
    ".ts",
    ".jsx",
    ".tsx",
    ".rb",
    ".go",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".cs",
    ".java",
    ".php",
    ".pl",
    ".bat",
    ".cmd",
    ".vbs",
    ".vba",
    ".sql",
    ".lua",
    ".rs",
}

# Path candidates longer than this can't be real filesystem paths on any
# common OS (PATH_MAX is 4096 on Linux, 1024 on macOS/BSD) — used to skip a
# wasted stat() call on long raw-text input.
_MAX_PLAUSIBLE_PATH_LEN = 4096


def from_text(path_or_string: str | Path) -> IngestedContent:
    """Load text/code content from a file path or a raw string.

    Returns `source_type=CODE` when loading from a file whose extension is a
    recognized script/source extension (see `CODE_EXTENSIONS`), otherwise
    `TEXT`. Raw strings (not resolvable to an existing file) are always
    `TEXT` — there's no extension to key off of.
    """
    path = _as_existing_file_path(path_or_string)

    if path is not None:
        return _from_file(path)

    content = str(path_or_string)
    encoded_len = len(content.encode("utf-8", errors="replace"))
    if encoded_len > MAX_TEXT_BYTES:
        raise SizeLimitExceeded(
            f"raw text content is {encoded_len} bytes, exceeding the {MAX_TEXT_BYTES}-byte text ingestion cap"
        )

    return IngestedContent(
        source="<raw text>",
        source_type=SourceType.TEXT,
        text=content,
        images=[],
        title=None,
        metadata={"bytes": encoded_len, "origin": "raw_string"},
    )


def _from_file(path: Path) -> IngestedContent:
    size = path.stat().st_size
    if size > MAX_TEXT_BYTES:
        raise SizeLimitExceeded(f"{path} is {size} bytes, exceeding the {MAX_TEXT_BYTES}-byte text ingestion cap")

    raw_bytes = path.read_bytes()
    text = raw_bytes.decode("utf-8", errors="replace")
    extension = path.suffix.lower()
    source_type = SourceType.CODE if extension in CODE_EXTENSIONS else SourceType.TEXT

    return IngestedContent(
        source=str(path),
        source_type=source_type,
        text=text,
        images=[],
        title=path.name,
        metadata={"bytes": len(raw_bytes), "extension": extension, "origin": "file"},
    )


def _as_existing_file_path(path_or_string: str | Path) -> Path | None:
    if isinstance(path_or_string, Path):
        return path_or_string if path_or_string.is_file() else None

    if not isinstance(path_or_string, str):
        return None

    # Raw content essentially never survives these checks: multi-line text
    # obviously isn't a path, and content longer than any real path is cheap
    # to reject without touching the filesystem.
    if "\n" in path_or_string or "\x00" in path_or_string:
        return None
    if len(path_or_string) > _MAX_PLAUSIBLE_PATH_LEN or not path_or_string.strip():
        return None

    try:
        candidate = Path(path_or_string).expanduser()
        if candidate.is_file():
            return candidate
    except OSError:
        return None
    return None
