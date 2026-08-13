"""GlobWarden ingestion layer.

Turns a URL, local PDF, raw text, code file, or image into a clean
`globwarden.models.IngestedContent` object for the rest of the pipeline.

The single entry point the CLI should call is `detect_source.load(source)`,
which auto-detects which of the four concrete loaders below applies.
"""

from globwarden.ingest.detect_source import load
from globwarden.ingest.image import from_image
from globwarden.ingest.pdf import from_pdf
from globwarden.ingest.text import from_text
from globwarden.ingest.url import from_url

__all__ = ["load", "from_url", "from_pdf", "from_text", "from_image"]
