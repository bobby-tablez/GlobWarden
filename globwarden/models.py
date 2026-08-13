"""Shared data models for GlobWarden.

Every module in this package codes against these exact shapes — do not redefine
them elsewhere. See `_briefs/00-ARCHITECTURE.md` for the authoritative contract
this file implements.
"""

from dataclasses import dataclass, field
from enum import Enum


class SourceType(str, Enum):
    URL = "url"
    PDF = "pdf"
    TEXT = "text"
    IMAGE = "image"
    CODE = "code"


@dataclass
class IngestedContent:
    source: str  # original URL/path/identifier
    source_type: SourceType
    text: str  # extracted plain text (empty for pure-image sources)
    images: list[bytes] = field(default_factory=list)  # raw bytes, for vision providers
    title: str | None = None
    metadata: dict = field(default_factory=dict)  # e.g. {"pages": 12, "fetched_at": "..."}


class ObfuscationCategory(str, Enum):
    CHARACTER_MASKING = "character_masking"  # backtick split, case rand., homoglyphs, reorder
    WILDCARD_RESOLUTION = "wildcard_resolution"  # Get-Alias/Get-Command glob resolution -> invoke
    STRING_CONCATENATION = "string_concatenation"  # split/rejoin to defeat substring match
    ENV_VAR_INDIRECTION = "env_var_indirection"  # building commands from environment variables
    ENCODED_CRADLE = "encoded_cradle"  # -EncodedCommand/base64/download-execute chains
    OTHER = "other"  # real finding that doesn't fit cleanly above


@dataclass
class ObfuscationFinding:
    id: str  # short stable id, e.g. "f1" — cross-references generated rules
    category: ObfuscationCategory
    technique_name: str  # human-readable, e.g. "Wildcard Get-Alias to Invoke-Expr"
    description: str  # 1-3 sentences, in the tool's own words
    example_snippet: str | None  # the obfuscated example, verbatim from source, if present
    confidence: float  # 0.0-1.0, the LLM's/pipeline's self-reported confidence
    attack_mapping: str  # e.g. "T1027.010 (parent: T1027)"
    source_ref: str | None = None  # page number / URL fragment / line range, if determinable


class RuleType(str, Enum):
    REGEX = "regex"
    KQL = "kql"
    SPL = "spl"
    YARA_L = "yara_l"
    SIGMA = "sigma"


@dataclass
class GeneratedRule:
    finding_id: str  # cross-references ObfuscationFinding.id
    rule_type: RuleType
    content: str  # the actual rule/pattern text
    explanation: str  # short, plain-language "what this catches and why"
    valid: bool = True  # did it pass syntactic validation (compiles/parses)?
    validation_note: str | None = None  # why invalid, if valid=False — never silently drop a rule
