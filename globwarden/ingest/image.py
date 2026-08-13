"""Load a standalone image file (a screenshot of a terminal, a campaign
diagram, etc.) into `IngestedContent` for the vision-capable LLM path.

There's no OCR or text extraction here by design — that's the vision-capable
provider's job downstream. This module's only responsibilities are: read the
bytes, sanity-check that they're actually decodable image data, and enforce
the size cap.
"""

from __future__ import annotations

import io
from pathlib import Path

from globwarden.ingest.errors import SizeLimitExceeded, UnsupportedSourceError
from globwarden.models import IngestedContent, SourceType

# Real screenshots/diagrams in a report are almost always a few hundred KB to
# a few MB; 20MB is generous headroom while still refusing an absurdly large
# or maliciously oversized file outright.
MAX_IMAGE_BYTES = 20 * 1024 * 1024

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".tif"}


def from_image(path: str | Path) -> IngestedContent:
    """Read an image file's bytes into `IngestedContent.images`.

    `text` is left empty (there's nothing to extract without OCR) and
    `source_type` is always `IMAGE`.
    """
    p = Path(path)
    if not p.is_file():
        raise UnsupportedSourceError(f"Image path does not exist or is not a file: {p}")

    size = p.stat().st_size
    if size > MAX_IMAGE_BYTES:
        raise SizeLimitExceeded(f"{p} is {size} bytes, exceeding the {MAX_IMAGE_BYTES}-byte image ingestion cap")

    data = p.read_bytes()
    _validate_image(data, p)

    return IngestedContent(
        source=str(p),
        source_type=SourceType.IMAGE,
        text="",
        images=[data],
        title=p.name,
        metadata={"bytes": len(data), "extension": p.suffix.lower()},
    )


def _validate_image(data: bytes, path: Path) -> None:
    """Confirm this is decodable image data before it's handed off downstream.
    We only ever *decode* (Pillow's verify()) — never execute or eval file
    content, per the project's hard safety requirement."""
    try:
        from PIL import Image
    except ImportError as exc:
        raise UnsupportedSourceError(
            "Image ingestion requires the optional 'image' extra, which isn't "
            'installed. Run: pip install "globwarden[image]"  (or "globwarden[all]").'
        ) from exc

    try:
        with Image.open(io.BytesIO(data)) as img:
            img.verify()
    except Exception as exc:
        raise UnsupportedSourceError(f"{path} does not look like a valid image: {exc}") from exc
