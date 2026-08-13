"""Regression tests for the prompt templates themselves.

A prior review caught real drift between the Sigma few-shot in `prompts.py` and
the real, validated source rule it's claimed to be adapted from
(`sigma-t1027010-wildcard-alias-iex.yml`): the source rule's correctly-escaped
literal `i\\*x` had regressed to an unescaped `i*x` (a Sigma wildcard match, not
a literal-character match — a materially different, much broader match), plus
an invented, also-unescaped `i*rm` entry that never existed in the source rule
at all. These tests pin the fix so it can't silently regress again.
"""

from globwarden.engine.prompts import RULE_GENERATION_PROMPTS
from globwarden.models import RuleType


def test_sigma_few_shot_escapes_literal_wildcard_characters():
    sigma_prompt = RULE_GENERATION_PROMPTS[RuleType.SIGMA]

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
