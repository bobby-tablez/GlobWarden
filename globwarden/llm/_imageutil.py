"""Tiny internal helper: sniff an image's MIME type from its magic bytes.

Shared by the cloud providers so vision payloads carry a correct
`media_type`/`mime_type` instead of guessing "image/png" for everything.
Not part of the public LLM interface — leading underscore is deliberate.
"""

from __future__ import annotations


def sniff_image_mime_type(data: bytes) -> str:
    """Best-effort MIME type detection from magic bytes. Defaults to image/png."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "image/gif"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return "image/webp"
    return "image/png"
