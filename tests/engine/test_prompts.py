"""Regression tests for the prompt templates themselves.

A prior review caught real drift between the Sigma few-shot in `prompts.py` and
the real, validated source rule it's claimed to be adapted from
(`sigma-t1027010-wildcard-alias-iex.yml`): the source rule's correctly-escaped
literal `i\\*x` had regressed to an unescaped `i*x` (a Sigma wildcard match, not
a literal-character match — a materially different, much broader match), plus
an invented, also-unescaped `i*rm` entry that never existed in the source rule
at all. These tests pin the fix so it can't silently regress again.
"""

from globwarden.engine.prompts import build_generation_system_prompt
from globwarden.models import RuleType


def test_sigma_few_shot_escapes_literal_wildcard_characters():
    sigma_prompt = build_generation_system_prompt([RuleType.SIGMA])

    # Correctly-escaped literal '*' must be present — matches the real source
    # rule's 'i\*x' entry.
    assert "i\\*x" in sigma_prompt

    # The old, buggy unescaped variants must not reappear. An unescaped '*' in a
    # Sigma |contains string value is Sigma's own WILDCARD operator, not a
    # literal character — regressing back to 'i*x' silently broadens the match
    # semantics of the one concrete example the LLM sees for this technique
    # family. 'i*rm' was never in the real source rule at all.
    assert "'i*x'" not in sigma_prompt
    assert "'i*rm'" not in sigma_prompt

    # The requirements section should teach the escaping rule explicitly, not
    # just happen to get it right in the one example.
    assert "wildcard" in sigma_prompt.lower()
    assert "\\*" in sigma_prompt
    assert "\\?" in sigma_prompt


def test_combined_prompt_only_includes_requested_formats():
    regex_only = build_generation_system_prompt([RuleType.REGEX])
    assert "### regex" in regex_only
    assert "### kql" not in regex_only
    assert "### sigma" not in regex_only

    two_formats = build_generation_system_prompt([RuleType.KQL, RuleType.SIGMA])
    assert "### kql" in two_formats
    assert "### sigma" in two_formats
    assert "### regex" not in two_formats
    assert "### spl" not in two_formats


def test_combined_prompt_asks_for_matching_expression_not_a_full_rule():
    """GlobWarden's scope is a matching expression per format, not a complete
    standalone rule -- every requested-format section should say so, and the
    Sigma section specifically should ask for the detection block only."""
    prompt = build_generation_system_prompt([RuleType.KQL, RuleType.SIGMA])
    assert "never a complete standalone rule" in prompt.lower()
    assert "not a full query" in prompt.lower()  # KQL section
    assert "detection:` block" in prompt.lower() or "detection: block" in prompt.lower()  # Sigma section
    # Sigma section explicitly excludes full-rule wrapper fields.
    assert "do not include" in prompt.lower()
    assert "logsource" in prompt.lower()
