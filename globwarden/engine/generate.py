"""Detection-content generation, with validate-before-return and capped retry.

`generate_rules` calls the provider once per finding — not once per (finding,
rule_type) pair — using `prompts.build_generation_system_prompt` to cover every
requested `RuleType` in a single combined JSON response, then validates each
format's content before handing it back:

- REGEX: `re.compile()`'d for real.
- SIGMA: GlobWarden asks for just the `detection:` block (selection(s) + a
  `condition` key), not a full rule — parsed for real with `yaml.safe_load`, then
  checked for that minimal shape.
- KQL / SPL / YARA_L: GlobWarden asks for a single matching line/clause, not a
  full query or rule. Full semantic validation isn't practical without a real
  backend (Sentinel/Splunk/Chronicle), so these get sanity checks — non-empty
  content, balanced brackets/parens/braces, and a check that the line actually
  looks like the kind of expression it claims to be (contains "regex" for
  KQL/SPL, references a UDM event-variable field for YARA-L).

A format that fails validation gets retried — the failure reason fed back to
the model, using a narrow single-format prompt (`build_generation_system_prompt`
called with just that one `RuleType`, not the combined one used for the initial
call) — up to `DEFAULT_MAX_VALIDATION_RETRIES` times. A format that's still
invalid after exhausting its retries is returned as-is: `valid=False` and a
`validation_note` explaining why, never silently dropped and never silently
treated as if it were fine. A failed validation result the caller can't tell
apart from a working one is worse than no result at all, which is the whole
reason this retry loop exists — but it has to terminate, so the cap is a hard
requirement, not a suggestion.

This validate-before-return behavior is treated as a hard requirement, not an
optional nicety — a `GeneratedRule` with `valid=True` is a real claim the CLI/UI
will display, and getting that claim wrong undermines the whole tool's
credibility as a detection-engineering assistant.

A provider can also explicitly *refuse* to generate content for a specific
finding (a policy/safety decision, distinct from a truncated or malformed
response — see `llm.errors.ProviderRefusalError`). Confirmed live: this is
content-specific, not systemic, so it's handled differently from an
unparseable-JSON `GenerationError` — instead of aborting the whole scan, only
the affected finding's requested formats come back `valid=False` with a note
explaining why; every other finding's independent call is unaffected.

Findings are independent of one another, so their generation calls (including
any retries) run concurrently via a thread pool — see `DEFAULT_MAX_CONCURRENCY`
— since every `LLMProvider.complete()` implementation is a blocking, stateless-
per-call HTTP request (no shared mutable state across calls), making thread-based
concurrency the correct, minimal-invasiveness way to cut wall-clock time without
touching any provider implementation.
"""

from __future__ import annotations

import concurrent.futures
import logging
import re
from collections.abc import Callable

import yaml

from globwarden.engine._parsing import JSONExtractionError, extract_json_object
from globwarden.engine.prompts import (
    RULE_CONTENT_KEY,
    RULE_SECTION_KEY,
    build_generation_system_prompt,
    rule_generation_user_prompt,
)
from globwarden.llm.base import LLMProvider
from globwarden.llm.errors import ProviderRefusalError
from globwarden.models import GeneratedRule, ObfuscationFinding, RuleType

logger = logging.getLogger(__name__)

# Bounded thread-pool size for concurrent per-finding generation calls. Kept
# modest (rather than "one thread per finding") so a scan with many findings
# doesn't fan out into a burst large enough to trip a provider's rate limit —
# 5 concurrent in-flight calls is a reasonable default for a single-operator
# CLI tool, comfortably under typical per-minute request limits for the cloud
# providers this tool supports.
DEFAULT_MAX_CONCURRENCY = 5

# Cap on retry attempts per (finding, rule_type) when validation fails --
# total attempts for a format that keeps failing is 1 (initial) + this many.
# A failed-validation result is never useful to the analyst (that's the whole
# point of retrying it), but an uncapped retry loop against a model that
# simply can't produce a valid pattern for a given technique would spin
# forever burning API calls for a result that was never going to validate --
# 2 retries (3 attempts total) is enough to recover from a transient/one-off
# mistake without turning a single stubborn format into a runaway cost.
DEFAULT_MAX_VALIDATION_RETRIES = 2


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


def _validator_for(rule_type: RuleType) -> Callable[[str], tuple[bool, str | None]]:
    """One validator per format, all sharing the same (bool, note) signature
    so the retry loop below can stay generic across every `RuleType`."""
    if rule_type is RuleType.REGEX:
        return _validate_regex
    if rule_type is RuleType.SIGMA:
        return _validate_sigma_detection_block
    return lambda content: _validate_line(content, rule_type)


def _parse_section(parsed: dict, rule_type: RuleType) -> tuple[str, str]:
    """Pull (content, explanation) for one format out of a combined response."""
    section = parsed.get(RULE_SECTION_KEY[rule_type])
    if not isinstance(section, dict):
        return "", ""
    content_key = RULE_CONTENT_KEY[rule_type]
    return str(section.get(content_key, "")), str(section.get("explanation", ""))


def _finalize_with_retries(
    finding: ObfuscationFinding,
    provider: LLMProvider,
    rule_type: RuleType,
    initial_content: str,
    initial_explanation: str,
    max_retries: int,
) -> GeneratedRule:
    """Validate one format's content, retrying (feeding the failure reason
    back to the model) up to `max_retries` times if it doesn't pass. Every
    retry uses a narrow, single-format prompt -- `build_generation_system_prompt`
    called with just this one `RuleType` -- not the combined prompt the
    initial call used, so a retry costs one small, scoped call rather than
    re-running generation for every requested format again.

    Returns the last attempt's content either way: `valid=True` the moment
    one passes, or `valid=False` with the final validation_note once retries
    are exhausted -- never raises, since a still-invalid format after every
    retry is a legitimate, reportable outcome, not an error in the pipeline
    itself.
    """
    validator = _validator_for(rule_type)
    content, explanation = initial_content, initial_explanation
    valid, note = validator(content)

    base_user_prompt = rule_generation_user_prompt(
        finding_technique_name=finding.technique_name,
        finding_description=finding.description,
        finding_example_snippet=finding.example_snippet,
        finding_category=finding.category.value,
        attack_mapping=finding.attack_mapping,
    )
    retry_system_prompt = build_generation_system_prompt([rule_type])

    attempt = 0
    while not valid and attempt < max_retries:
        attempt += 1
        retry_prompt = (
            f"{base_user_prompt}\n\nYour previous attempt for this format produced:\n{content}\n\n"
            f"It failed validation: {note}\n"
            "Please fix it and respond again with only the JSON object described in the system prompt."
        )
        try:
            retry_parsed = _call_and_parse(
                provider,
                retry_system_prompt,
                retry_prompt,
                finding.id,
                f"a validation retry ({attempt}/{max_retries}) for {rule_type.value}",
            )
        except (GenerationError, ProviderRefusalError):
            # Can't recover further -- stop retrying and report the last
            # known (invalid) attempt rather than raising, since the earlier
            # combined call already succeeded and this format's own failure
            # is a legitimate, reportable outcome, not a pipeline error. A
            # refusal here is treated the same as unparseable JSON: give up
            # on fixing *this format*, not the whole finding -- the initial
            # combined response already has usable content for it.
            break
        content, explanation = _parse_section(retry_parsed, rule_type)
        valid, note = validator(content)

    if not valid and attempt > 0:
        # Distinguish "never worked, one shot" from "tried repeatedly and
        # still couldn't fix it" -- the retry count itself is useful context
        # for the analyst deciding whether to just fix it by hand.
        retry_word = "retry" if attempt == 1 else "retries"
        note = f"{note} (still invalid after {attempt} {retry_word})"

    return GeneratedRule(
        finding_id=finding.id,
        rule_type=rule_type,
        content=content,
        explanation=explanation,
        valid=valid,
        validation_note=note,
    )


def _generate_for_finding(
    finding: ObfuscationFinding,
    rule_types: list[RuleType],
    provider: LLMProvider,
    max_validation_retries: int,
) -> list[GeneratedRule]:
    """Run the one combined generation call for `finding`, then validate
    (and retry, per format, up to `max_validation_retries` times) every
    requested format's section of the response."""
    system_prompt = build_generation_system_prompt(rule_types)
    user_prompt = rule_generation_user_prompt(
        finding_technique_name=finding.technique_name,
        finding_description=finding.description,
        finding_example_snippet=finding.example_snippet,
        finding_category=finding.category.value,
        attack_mapping=finding.attack_mapping,
    )
    context = f"a combined rule-generation response ({', '.join(rt.value for rt in rule_types)})"
    try:
        parsed = _call_and_parse(provider, system_prompt, user_prompt, finding.id, context)
    except ProviderRefusalError as exc:
        # Content-specific, not systemic (see ProviderRefusalError's
        # docstring) -- confirmed live, a refusal on one finding's combined
        # call has no bearing on any other finding's independent call, so
        # this must not take down the whole scan's results the way an
        # unparseable-JSON GenerationError intentionally does (that case
        # really is a signal something's systemically wrong). Report every
        # requested format for *this finding* as invalid with a clear note,
        # exactly like a format that failed validation and exhausted its
        # retries -- never silently dropped, but scoped to the one finding
        # that actually had the problem.
        note = f"Provider declined to generate content for this finding (safety refusal): {exc}"
        return [
            GeneratedRule(finding_id=finding.id, rule_type=rt, content="", explanation="", valid=False, validation_note=note)
            for rt in rule_types
        ]

    rules: list[GeneratedRule] = []
    for rule_type in rule_types:
        content, explanation = _parse_section(parsed, rule_type)
        rules.append(_finalize_with_retries(finding, provider, rule_type, content, explanation, max_validation_retries))

    return rules


def generate_rules(
    findings: list[ObfuscationFinding],
    rule_types: list[RuleType],
    provider: LLMProvider,
    *,
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
    max_validation_retries: int = DEFAULT_MAX_VALIDATION_RETRIES,
) -> list[GeneratedRule]:
    """Generate and validate detection content for every finding.

    Every returned `GeneratedRule` has been through real syntactic validation for
    its format (see module docstring), with up to `max_validation_retries`
    retries per format if the first attempt fails. A rule that's still invalid
    after exhausting its retries is still returned — with `valid=False` and a
    `validation_note` — never silently dropped, so the caller/UI can show the
    analyst exactly what went wrong.

    One finding's rules for every requested format come from a single combined
    provider call (plus, per format, any validation retries) — not one call per
    (finding, rule_type) pair — and independent findings' calls run concurrently
    (bounded by `max_concurrency`). Output order matches `findings` order
    regardless of which call completes first.

    Raises `GenerationError` only when a provider response cannot be recovered as
    JSON at all; content that parses but fails format-specific validation is
    reported via `valid=False`, not raised. A provider refusal on one finding's
    initial call is also never raised out of here — see module docstring — it
    comes back as `valid=False` results for that finding only.
    """
    if not findings or not rule_types:
        return []

    max_workers = max(1, min(max_concurrency, len(findings)))
    results_by_index: list[list[GeneratedRule] | None] = [None] * len(findings)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    first_exception: GenerationError | None = None
    try:
        future_to_index = {
            executor.submit(_generate_for_finding, finding, rule_types, provider, max_validation_retries): i
            for i, finding in enumerate(findings)
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
