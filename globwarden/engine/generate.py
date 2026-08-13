"""Per-rule-type detection-content generation, with validate-before-return.

`generate_rules` calls the provider once per (finding, rule_type) pair using the
matching system prompt from `prompts.py`, parses the JSON response defensively,
and then actually validates the generated content before handing it back:

- REGEX: `re.compile()`'d for real. On failure, the LLM gets one retry with the
  compiler error fed back; if it still doesn't compile, the rule is returned with
  `valid=False` and a `validation_note` explaining why — never silently as if it
  were fine.
- SIGMA: parsed for real with `yaml.safe_load`, then checked for the required
  Sigma skeleton (title, logsource, detection, condition). Same validate-or-flag
  treatment, no retry (see handoff for why regex gets a retry and Sigma doesn't).
- KQL / SPL / YARA_L: full semantic validation isn't practical without a real
  backend (Sentinel/Splunk/Chronicle), so these get basic sanity checks —
  non-empty content, balanced brackets/parens/braces, and (for YARA-L) the
  presence of the minimal required rule keywords. Anything that fails is flagged,
  never silently returned as valid.

This validate-before-return behavior is treated as a hard requirement, not an
optional nicety — a `GeneratedRule` with `valid=True` is a real claim the CLI/UI
will display, and getting that claim wrong undermines the whole tool's
credibility as a detection-engineering assistant.
"""

from __future__ import annotations

import logging
import re

import yaml

from globwarden.engine._parsing import JSONExtractionError, extract_json_object
from globwarden.engine.prompts import (
    RULE_CONTENT_KEY,
    RULE_GENERATION_PROMPTS,
    rule_generation_user_prompt,
)
from globwarden.llm.base import LLMProvider
from globwarden.models import GeneratedRule, ObfuscationFinding, RuleType

logger = logging.getLogger(__name__)

_REQUIRED_SIGMA_KEYS = ("title", "logsource", "detection")


class GenerationError(Exception):
    """Raised when a generation call's response cannot be recovered as usable
    JSON at all (as opposed to content that parses fine but fails validation,
    which is returned as a `GeneratedRule(valid=False, ...)`, not raised)."""


def _call_and_parse(
    provider: LLMProvider,
    system_prompt: str,
    user_prompt: str,
    finding_id: str,
    rule_type: RuleType,
) -> dict:
    response = provider.complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        json_mode=True,
    )
    try:
        parsed = extract_json_object(response.text)
    except JSONExtractionError as exc:
        raise GenerationError(
            f"Provider '{provider.name}' returned a response that could not be "
            f"parsed as JSON while generating a {rule_type.value} rule for "
            f"finding '{finding_id}': {exc}"
        ) from exc

    if not isinstance(parsed, dict):
        # json.loads() happily accepts a top-level list, string, number, bool, or
        # null as valid JSON — none of those are the object shape every rule-gen
        # prompt asks for. Without this check, every per-type handler below would
        # crash with an unhandled AttributeError on `parsed.get(...)`. Treat this
        # the same as "not recoverable as usable JSON" (mirrors the equivalent
        # isinstance(parsed, dict) guard in detect.py's _detect_in_chunk).
        raise GenerationError(
            f"Provider '{provider.name}' returned valid JSON but it was not a "
            f"JSON object (got {type(parsed).__name__}) while generating a "
            f"{rule_type.value} rule for finding '{finding_id}'. Raw response "
            f"(first 200 chars): {response.text[:200]!r}"
        )

    return parsed


def _validate_regex(pattern: str) -> tuple[bool, str | None]:
    if not pattern or not pattern.strip():
        # re.compile("") happily succeeds — an empty pattern is syntactically
        # valid Python regex but functionally useless (matches at every
        # position, catches nothing meaningful). Without this explicit check, a
        # response that's missing the "pattern" key entirely (defaults to "" in
        # the caller) would silently come back valid=True as if it were a real,
        # working rule. Treat empty/missing exactly like a compile failure.
        return False, "Generated pattern was empty or missing from the LLM response."
    try:
        re.compile(pattern)
        return True, None
    except re.error as exc:
        return False, f"Pattern did not compile with Python's re module: {exc}"


def _validate_sigma(rule_yaml: str) -> tuple[bool, str | None]:
    try:
        parsed = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as exc:
        return False, f"Content is not valid YAML: {exc}"

    if not isinstance(parsed, dict):
        return False, "Parsed YAML is not a mapping (Sigma rules must be a YAML object)."

    missing = [key for key in _REQUIRED_SIGMA_KEYS if key not in parsed]
    if missing:
        return False, f"Missing required Sigma field(s): {', '.join(missing)}"

    detection = parsed.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        return False, "Sigma 'detection' block is missing a 'condition' key."

    return True, None


def _brackets_balanced(text: str) -> bool:
    pairs = {")": "(", "}": "{", "]": "["}
    openers = set(pairs.values())
    stack: list[str] = []
    for ch in text:
        if ch in openers:
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack[-1] != pairs[ch]:
                return False
            stack.pop()
    return not stack


def _validate_basic_sanity(content: str, rule_type: RuleType) -> tuple[bool, str | None]:
    if not content or not content.strip():
        return False, "Generated content was empty."

    if not _brackets_balanced(content):
        return False, "Generated content has unbalanced parentheses/braces/brackets."

    if rule_type is RuleType.YARA_L:
        lowered = content.lower()
        if "rule " not in lowered and not lowered.strip().startswith("rule"):
            return (
                False,
                "Generated content does not look like a YARA-L rule (missing 'rule' keyword).",
            )
        if "condition" not in lowered:
            return False, "Generated content is missing a YARA-L 'condition' section."

    return True, None


def _generate_regex_rule(
    finding: ObfuscationFinding,
    provider: LLMProvider,
    system_prompt: str,
    user_prompt: str,
) -> GeneratedRule:
    parsed = _call_and_parse(provider, system_prompt, user_prompt, finding.id, RuleType.REGEX)
    pattern = str(parsed.get("pattern", ""))
    explanation = str(parsed.get("explanation", ""))

    valid, note = _validate_regex(pattern)
    if not valid:
        # One retry: feed the compiler error back and ask the LLM to fix it.
        retry_prompt = (
            f"{user_prompt}\n\nYour previous attempt produced this pattern:\n{pattern}\n\n"
            f"It failed to compile with Python's re module: {note}\n"
            "Please fix the pattern and respond again with only the JSON object "
            "described in the system prompt."
        )
        try:
            retry_parsed = _call_and_parse(provider, system_prompt, retry_prompt, finding.id, RuleType.REGEX)
        except GenerationError:
            retry_parsed = None

        if retry_parsed is not None:
            retry_pattern = str(retry_parsed.get("pattern", ""))
            retry_valid, retry_note = _validate_regex(retry_pattern)
            if retry_valid:
                return GeneratedRule(
                    finding_id=finding.id,
                    rule_type=RuleType.REGEX,
                    content=retry_pattern,
                    explanation=str(retry_parsed.get("explanation", explanation)),
                    valid=True,
                    validation_note=None,
                )
            # Retry also failed — return the retry attempt, flagged invalid.
            return GeneratedRule(
                finding_id=finding.id,
                rule_type=RuleType.REGEX,
                content=retry_pattern,
                explanation=str(retry_parsed.get("explanation", explanation)),
                valid=False,
                validation_note=f"Failed to compile after one retry: {retry_note}",
            )

        return GeneratedRule(
            finding_id=finding.id,
            rule_type=RuleType.REGEX,
            content=pattern,
            explanation=explanation,
            valid=False,
            validation_note=note,
        )

    return GeneratedRule(
        finding_id=finding.id,
        rule_type=RuleType.REGEX,
        content=pattern,
        explanation=explanation,
        valid=True,
        validation_note=None,
    )


def _generate_sigma_rule(
    finding: ObfuscationFinding,
    provider: LLMProvider,
    system_prompt: str,
    user_prompt: str,
) -> GeneratedRule:
    parsed = _call_and_parse(provider, system_prompt, user_prompt, finding.id, RuleType.SIGMA)
    rule_yaml = str(parsed.get("rule_yaml", ""))
    explanation = str(parsed.get("explanation", ""))

    valid, note = _validate_sigma(rule_yaml)
    return GeneratedRule(
        finding_id=finding.id,
        rule_type=RuleType.SIGMA,
        content=rule_yaml,
        explanation=explanation,
        valid=valid,
        validation_note=note,
    )


def _generate_basic_checked_rule(
    finding: ObfuscationFinding,
    provider: LLMProvider,
    system_prompt: str,
    user_prompt: str,
    rule_type: RuleType,
) -> GeneratedRule:
    parsed = _call_and_parse(provider, system_prompt, user_prompt, finding.id, rule_type)
    content_key = RULE_CONTENT_KEY[rule_type]
    content = str(parsed.get(content_key, ""))
    explanation = str(parsed.get("explanation", ""))

    valid, note = _validate_basic_sanity(content, rule_type)
    return GeneratedRule(
        finding_id=finding.id,
        rule_type=rule_type,
        content=content,
        explanation=explanation,
        valid=valid,
        validation_note=note,
    )


def generate_rules(
    findings: list[ObfuscationFinding],
    rule_types: list[RuleType],
    provider: LLMProvider,
) -> list[GeneratedRule]:
    """Generate and validate detection content for every (finding, rule_type) pair.

    Every returned `GeneratedRule` has been through real syntactic validation for
    its format (see module docstring). A rule that fails validation is still
    returned — with `valid=False` and a `validation_note` — never silently
    dropped, so the caller/UI can show the analyst exactly what went wrong.

    Raises `GenerationError` only when a provider response cannot be recovered as
    JSON at all; content that parses but fails format-specific validation is
    reported via `valid=False`, not raised.
    """
    results: list[GeneratedRule] = []

    for finding in findings:
        for rule_type in rule_types:
            system_prompt = RULE_GENERATION_PROMPTS[rule_type]
            user_prompt = rule_generation_user_prompt(
                finding_technique_name=finding.technique_name,
                finding_description=finding.description,
                finding_example_snippet=finding.example_snippet,
                finding_category=finding.category.value,
                attack_mapping=finding.attack_mapping,
            )

            if rule_type is RuleType.REGEX:
                rule = _generate_regex_rule(finding, provider, system_prompt, user_prompt)
            elif rule_type is RuleType.SIGMA:
                rule = _generate_sigma_rule(finding, provider, system_prompt, user_prompt)
            else:
                rule = _generate_basic_checked_rule(finding, provider, system_prompt, user_prompt, rule_type)

            results.append(rule)

    return results
