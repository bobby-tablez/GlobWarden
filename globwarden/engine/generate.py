"""Detection-content generation, with validate-before-return.

`generate_rules` calls the provider once per finding — not once per (finding,
rule_type) pair — using `prompts.build_generation_system_prompt` to cover every
requested `RuleType` in a single combined JSON response, then validates each
format's content before handing it back:

- REGEX: `re.compile()`'d for real. On failure, the LLM gets one retry (using the
  narrow, single-purpose `REGEX_SYSTEM_PROMPT`, not the combined prompt) with the
  compiler error fed back; if it still doesn't compile, the rule is returned with
  `valid=False` and a `validation_note` explaining why — never silently as if it
  were fine.
- SIGMA: GlobWarden asks for just the `detection:` block (selection(s) + a
  `condition` key), not a full rule — parsed for real with `yaml.safe_load`, then
  checked for that minimal shape. Same validate-or-flag treatment, no retry.
- KQL / SPL / YARA_L: GlobWarden asks for a single matching line/clause, not a
  full query or rule. Full semantic validation isn't practical without a real
  backend (Sentinel/Splunk/Chronicle), so these get sanity checks — non-empty
  content, balanced brackets/parens/braces, and a check that the line actually
  looks like the kind of expression it claims to be (contains "regex" for
  KQL/SPL, references a UDM event-variable field for YARA-L). Anything that
  fails is flagged, never silently returned as valid.

This validate-before-return behavior is treated as a hard requirement, not an
optional nicety — a `GeneratedRule` with `valid=True` is a real claim the CLI/UI
will display, and getting that claim wrong undermines the whole tool's
credibility as a detection-engineering assistant.

Findings are independent of one another, so their generation calls (including
any regex retry) run concurrently via a thread pool — see `DEFAULT_MAX_CONCURRENCY`
— since every `LLMProvider.complete()` implementation is a blocking, stateless-
per-call HTTP request (no shared mutable state across calls), making thread-based
concurrency the correct, minimal-invasiveness way to cut wall-clock time without
touching any provider implementation.
"""

from __future__ import annotations

import concurrent.futures
import logging
import re

import yaml

from globwarden.engine._parsing import JSONExtractionError, extract_json_object
from globwarden.engine.prompts import (
    REGEX_SYSTEM_PROMPT,
    RULE_CONTENT_KEY,
    RULE_SECTION_KEY,
    build_generation_system_prompt,
    rule_generation_user_prompt,
)
from globwarden.llm.base import LLMProvider
from globwarden.models import GeneratedRule, ObfuscationFinding, RuleType

logger = logging.getLogger(__name__)

# Bounded thread-pool size for concurrent per-finding generation calls. Kept
# modest (rather than "one thread per finding") so a scan with many findings
# doesn't fan out into a burst large enough to trip a provider's rate limit —
# 5 concurrent in-flight calls is a reasonable default for a single-operator
# CLI tool, comfortably under typical per-minute request limits for the cloud
# providers this tool supports.
DEFAULT_MAX_CONCURRENCY = 5


class GenerationError(Exception):
    """Raised when a generation call's response cannot be recovered as usable
    JSON at all (as opposed to content that parses fine but fails validation,
    which is returned as a `GeneratedRule(valid=False, ...)`, not raised)."""


def _call_and_parse(
    provider: LLMProvider,
    system_prompt: str,
    user_prompt: str,
    finding_id: str,
    context: str,
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
            f"parsed as JSON while generating {context} for finding '{finding_id}': {exc}"
        ) from exc

    if not isinstance(parsed, dict):
        # json.loads() happily accepts a top-level list, string, number, bool, or
        # null as valid JSON — none of those are the object shape every rule-gen
        # prompt asks for. Without this check, section-extraction below would
        # crash with an unhandled AttributeError on `parsed.get(...)`. Treat this
        # the same as "not recoverable as usable JSON" (mirrors the equivalent
        # isinstance(parsed, dict) guard in detect.py's _detect_in_chunk).
        raise GenerationError(
            f"Provider '{provider.name}' returned valid JSON but it was not a "
            f"JSON object (got {type(parsed).__name__}) while generating {context} "
            f"for finding '{finding_id}'. Raw response (first 200 chars): {response.text[:200]!r}"
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


def _validate_sigma_detection_block(detection_yaml: str) -> tuple[bool, str | None]:
    try:
        parsed = yaml.safe_load(detection_yaml)
    except yaml.YAMLError as exc:
        return False, f"Content is not valid YAML: {exc}"

    if not isinstance(parsed, dict):
        return False, "Parsed YAML is not a mapping (a Sigma detection block must be a YAML object)."

    if "condition" not in parsed:
        return False, "Sigma detection block is missing a 'condition' key."

    selection_keys = [key for key in parsed if key != "condition"]
    if not selection_keys:
        return False, "Sigma detection block has a 'condition' but no selection(s) for it to reference."

    return True, None


def _brackets_balanced(text: str) -> bool:
    """Balance-check parens/braces/brackets, treating a backslash-escaped
    bracket (`\\(`, `\\)`, etc. -- the standard way a regex spells a literal
    bracket character) as literal text, not structure. Without this, a
    perfectly valid line whose regex legitimately matches a literal bracket
    (e.g. `regex ScriptBlockText="(?i)\\)"`, a real pattern for a technique
    that produces a stray literal paren) would be wrongly flagged invalid --
    unbalanced-looking structural brackets are still a real problem, but a
    backslash-escaped one inside the pattern is not."""
    pairs = {")": "(", "}": "{", "]": "["}
    openers = set(pairs.values())
    stack: list[str] = []
    backslash_run = 0
    for ch in text:
        if ch == "\\":
            backslash_run += 1
            continue
        escaped = backslash_run % 2 == 1
        backslash_run = 0
        if escaped:
            continue
        if ch in openers:
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack[-1] != pairs[ch]:
                return False
            stack.pop()
    return not stack


# Real operator syntax GlobWarden's prompts ask for, per format -- checked
# with word boundaries rather than a bare substring test, so e.g. a KQL/SPL
# line that merely contains "regex" inside an unrelated word/string (not as
# its own operator/command) doesn't pass a check whose whole point is
# confirming the line is actually regex-based.
_KQL_REGEX_OPERATOR_RE = re.compile(r"\bmatches\s+regex\b", re.IGNORECASE)
_SPL_REGEX_OPERATOR_RE = re.compile(r"\bregex\b", re.IGNORECASE)
# A UDM field path: `$<identifier>.<identifier>...`, e.g.
# `$e.target.process.command_line`. Requires the segment after `$` and after
# the `.` to each start with a letter/underscore (not a digit) -- without
# this, an unrelated `$100.50`-shaped substring (e.g. a dollar figure
# mentioned in passing) would satisfy a looser "$<anything>.<anything>" check.
_YARA_L_UDM_FIELD_RE = re.compile(r"\$[a-zA-Z_]\w*\.[a-zA-Z_]\w*")


def _validate_line(content: str, rule_type: RuleType) -> tuple[bool, str | None]:
    """Validate a single matching-line/clause (KQL, SPL, or YARA-L)."""
    if not content or not content.strip():
        return False, "Generated content was empty."

    if not _brackets_balanced(content):
        return False, "Generated content has unbalanced parentheses/braces/brackets."

    if rule_type is RuleType.KQL:
        if not _KQL_REGEX_OPERATOR_RE.search(content):
            return (
                False,
                "Generated KQL line does not look like a regex-matching clause (expected a 'matches regex' operator).",
            )
    elif rule_type is RuleType.SPL:
        if not _SPL_REGEX_OPERATOR_RE.search(content):
            return (
                False,
                "Generated SPL line does not look like a regex-matching clause (expected a 'regex' command/operator).",
            )
    elif rule_type is RuleType.YARA_L:
        if not _YARA_L_UDM_FIELD_RE.search(content):
            return (
                False,
                "Generated content does not look like a YARA-L UDM field reference "
                "(expected something like '$e.target.process.command_line...').",
            )

    return True, None


def _parse_section(parsed: dict, rule_type: RuleType) -> tuple[str, str]:
    """Pull (content, explanation) for one format out of a combined response."""
    section = parsed.get(RULE_SECTION_KEY[rule_type])
    if not isinstance(section, dict):
        return "", ""
    content_key = RULE_CONTENT_KEY[rule_type]
    return str(section.get(content_key, "")), str(section.get("explanation", ""))


def _finalize_regex_rule(
    finding: ObfuscationFinding,
    provider: LLMProvider,
    initial_pattern: str,
    initial_explanation: str,
) -> GeneratedRule:
    valid, note = _validate_regex(initial_pattern)
    if valid:
        return GeneratedRule(
            finding_id=finding.id,
            rule_type=RuleType.REGEX,
            content=initial_pattern,
            explanation=initial_explanation,
            valid=True,
            validation_note=None,
        )

    base_user_prompt = rule_generation_user_prompt(
        finding_technique_name=finding.technique_name,
        finding_description=finding.description,
        finding_example_snippet=finding.example_snippet,
        finding_category=finding.category.value,
        attack_mapping=finding.attack_mapping,
    )
    retry_prompt = (
        f"{base_user_prompt}\n\nYour previous attempt produced this pattern:\n{initial_pattern}\n\n"
        f"It failed to compile with Python's re module: {note}\n"
        "Please fix the pattern and respond again with only the JSON object "
        "described in the system prompt."
    )
    try:
        retry_parsed = _call_and_parse(provider, REGEX_SYSTEM_PROMPT, retry_prompt, finding.id, "a regex retry")
    except GenerationError:
        retry_parsed = None

    if retry_parsed is not None:
        retry_pattern = str(retry_parsed.get("pattern", ""))
        retry_valid, retry_note = _validate_regex(retry_pattern)
        return GeneratedRule(
            finding_id=finding.id,
            rule_type=RuleType.REGEX,
            content=retry_pattern,
            explanation=str(retry_parsed.get("explanation", initial_explanation)),
            valid=retry_valid,
            validation_note=None if retry_valid else f"Failed to compile after one retry: {retry_note}",
        )

    return GeneratedRule(
        finding_id=finding.id,
        rule_type=RuleType.REGEX,
        content=initial_pattern,
        explanation=initial_explanation,
        valid=False,
        validation_note=note,
    )


def _generate_for_finding(
    finding: ObfuscationFinding,
    rule_types: list[RuleType],
    provider: LLMProvider,
) -> list[GeneratedRule]:
    """Run the one combined generation call for `finding` and build every
    requested format's `GeneratedRule` from its section of the response."""
    system_prompt = build_generation_system_prompt(rule_types)
    user_prompt = rule_generation_user_prompt(
        finding_technique_name=finding.technique_name,
        finding_description=finding.description,
        finding_example_snippet=finding.example_snippet,
        finding_category=finding.category.value,
        attack_mapping=finding.attack_mapping,
    )
    context = f"a combined rule-generation response ({', '.join(rt.value for rt in rule_types)})"
    parsed = _call_and_parse(provider, system_prompt, user_prompt, finding.id, context)

    rules: list[GeneratedRule] = []
    for rule_type in rule_types:
        content, explanation = _parse_section(parsed, rule_type)

        if rule_type is RuleType.REGEX:
            rules.append(_finalize_regex_rule(finding, provider, content, explanation))
            continue

        if rule_type is RuleType.SIGMA:
            valid, note = _validate_sigma_detection_block(content)
        else:
            valid, note = _validate_line(content, rule_type)

        rules.append(
            GeneratedRule(
                finding_id=finding.id,
                rule_type=rule_type,
                content=content,
                explanation=explanation,
                valid=valid,
                validation_note=note,
            )
        )

    return rules


def generate_rules(
    findings: list[ObfuscationFinding],
    rule_types: list[RuleType],
    provider: LLMProvider,
    *,
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
) -> list[GeneratedRule]:
    """Generate and validate detection content for every finding.

    Every returned `GeneratedRule` has been through real syntactic validation for
    its format (see module docstring). A rule that fails validation is still
    returned — with `valid=False` and a `validation_note` — never silently
    dropped, so the caller/UI can show the analyst exactly what went wrong.

    One finding's rules for every requested format come from a single combined
    provider call (plus, for regex, an optional narrow retry) — not one call per
    (finding, rule_type) pair — and independent findings' calls run concurrently
    (bounded by `max_concurrency`). Output order matches `findings` order
    regardless of which call completes first.

    Raises `GenerationError` only when a provider response cannot be recovered as
    JSON at all; content that parses but fails format-specific validation is
    reported via `valid=False`, not raised.
    """
    if not findings or not rule_types:
        return []

    max_workers = max(1, min(max_concurrency, len(findings)))
    results_by_index: list[list[GeneratedRule] | None] = [None] * len(findings)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    first_exception: GenerationError | None = None
    try:
        future_to_index = {
            executor.submit(_generate_for_finding, finding, rule_types, provider): i for i, finding in enumerate(findings)
        }
        for future in concurrent.futures.as_completed(future_to_index):
            index = future_to_index[future]
            try:
                results_by_index[index] = future.result()
            except GenerationError as exc:
                # Fail fast: stop waiting on further results as soon as one
                # call is unrecoverable, rather than burning the full
                # remaining API budget on findings whose result will be
                # discarded anyway.
                first_exception = exc
                break
    finally:
        # cancel_futures=True drops any calls that haven't started yet (a
        # real savings when there are more findings than max_workers);
        # already-running calls still finish naturally since a thread can't
        # be forcibly interrupted mid-request.
        executor.shutdown(wait=True, cancel_futures=True)

    if first_exception is not None:
        raise first_exception

    results: list[GeneratedRule] = []
    for finding_rules in results_by_index:
        assert finding_rules is not None  # every future completed without raising, or we raised above
        results.extend(finding_rules)
    return results
