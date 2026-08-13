"""Sanity tests for the shared dataclasses in globwarden/models.py.

These aren't really "LLM layer" tests, but models.py lives at the root of
the package and Builder A owns writing it first per the architecture doc, so
a quick shape-conformance check belongs somewhere — this is as good a place
as any and costs nothing to run.
"""

from globwarden.models import (
    GeneratedRule,
    IngestedContent,
    ObfuscationCategory,
    ObfuscationFinding,
    RuleType,
    SourceType,
)


def test_ingested_content_defaults():
    content = IngestedContent(source="https://example.com", source_type=SourceType.URL, text="hello")
    assert content.images == []
    assert content.title is None
    assert content.metadata == {}


def test_ingested_content_images_and_metadata_are_independent_instances():
    a = IngestedContent(source="a", source_type=SourceType.TEXT, text="")
    b = IngestedContent(source="b", source_type=SourceType.TEXT, text="")
    a.images.append(b"x")
    a.metadata["k"] = "v"
    assert b.images == []
    assert b.metadata == {}


def test_obfuscation_finding_shape():
    finding = ObfuscationFinding(
        id="f1",
        category=ObfuscationCategory.WILDCARD_RESOLUTION,
        technique_name="Wildcard Get-Alias to Invoke-Expression",
        description="desc",
        example_snippet="iex (gal i*x)",
        confidence=0.9,
        attack_mapping="T1027.010 (parent: T1027)",
    )
    assert finding.source_ref is None


def test_generated_rule_defaults():
    rule = GeneratedRule(
        finding_id="f1",
        rule_type=RuleType.REGEX,
        content=r"gal\s+i.*x",
        explanation="catches wildcard alias resolution",
    )
    assert rule.valid is True
    assert rule.validation_note is None


def test_enums_are_str_enums():
    assert SourceType.URL == "url"
    assert ObfuscationCategory.ENCODED_CRADLE == "encoded_cradle"
    assert RuleType.YARA_L == "yara_l"
