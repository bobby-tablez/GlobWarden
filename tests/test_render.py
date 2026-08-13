"""Tests for globwarden/render.py — the rich terminal rendering layer.

These exercise `render.py` directly with synthetic `models.py` dataclasses,
independent of `cli.py`/the LLM pipeline, so they stay fast and don't depend
on any other builder's module having landed.
"""

from __future__ import annotations

import io
import json

import pytest
from rich.console import Console

from globwarden import render
from globwarden.models import (
    GeneratedRule,
    IngestedContent,
    ObfuscationCategory,
    ObfuscationFinding,
    RuleType,
    SourceType,
)


def make_console(width: int = 100) -> Console:
    """A Console that writes to an in-memory buffer with no ANSI color codes,
    so assertions can just look for plain substrings."""
    return Console(file=io.StringIO(), width=width, color_system=None, highlight=False)


def output_of(console: Console) -> str:
    return console.file.getvalue()


@pytest.fixture
def finding() -> ObfuscationFinding:
    return ObfuscationFinding(
        id="f1",
        category=ObfuscationCategory.WILDCARD_RESOLUTION,
        technique_name="Wildcard Get-Alias to Invoke-Expression",
        description="Resolves iex via a wildcard Get-Alias lookup to dodge substring detections.",
        example_snippet="(Get-Alias i*x)[0].Definition | % { & $_ $cmd }",
        confidence=0.86,
        attack_mapping="T1027.010 (parent: T1027)",
        source_ref="p.4",
    )


@pytest.fixture
def valid_rule() -> GeneratedRule:
    return GeneratedRule(
        finding_id="f1",
        rule_type=RuleType.SIGMA,
        content="title: test\nlogsource:\n  category: x\ndetection:\n  condition: selection",
        explanation="Catches it.",
        valid=True,
    )


@pytest.fixture
def invalid_rule() -> GeneratedRule:
    return GeneratedRule(
        finding_id="f1",
        rule_type=RuleType.REGEX,
        content="Get-Alias\\s+[a-z*]{1,4}x(",
        explanation="Broken on purpose.",
        valid=False,
        validation_note="missing ), unterminated subpattern",
    )


# ---------------------------------------------------------------------------
# Banner / header
# ---------------------------------------------------------------------------


def test_banner_shows_name_and_version():
    console = make_console()
    render.banner(console, version="1.2.3")
    text = output_of(console)
    assert "GlobWarden" in text
    assert "T1027.010" in text
    assert "1.2.3" in text


def test_scan_header_shows_target_provider_and_rules():
    console = make_console()
    render.scan_header(
        console,
        source="demo",
        provider="fake",
        model="fake-mini",
        rule_types=[RuleType.REGEX, RuleType.SIGMA],
    )
    text = output_of(console)
    assert "demo" in text
    assert "fake" in text
    assert "fake-mini" in text
    assert "regex" in text
    assert "sigma" in text


def test_scan_header_marks_dry_run_skip():
    console = make_console()
    render.scan_header(
        console,
        source="demo",
        provider="fake",
        model=None,
        rule_types=[RuleType.REGEX],
        dry_run=True,
    )
    assert "dry run" in output_of(console)


def test_render_dry_run_notice():
    console = make_console()
    render.render_dry_run_notice(console)
    assert "dry run" in output_of(console).lower()


# ---------------------------------------------------------------------------
# Results view
# ---------------------------------------------------------------------------


def test_render_results_empty_shows_no_findings_panel():
    console = make_console()
    render.render_results(console, [], [])
    text = output_of(console)
    assert "no findings" in text.lower() or "No obfuscation techniques" in text
    assert "--verbose" in text  # the panel's own hint text


# ---------------------------------------------------------------------------
# Ingested-content preview -- shown when --verbose + no findings, so the
# no-findings panel's "try --verbose to see what was ingested" hint is
# actually true rather than a dead end (a real bug caught in review).
# ---------------------------------------------------------------------------


def test_render_ingested_preview_shows_source_type_and_text():
    console = make_console()
    content = IngestedContent(
        source="/nonexistent/path/report.pdf",
        source_type=SourceType.TEXT,
        text="/nonexistent/path/report.pdf",
        title=None,
    )
    render.render_ingested_preview(console, content)
    text = output_of(console)
    assert "/nonexistent/path/report.pdf" in text
    assert "text" in text.lower()
    assert "ingested content" in text.lower()


def test_render_ingested_preview_truncates_long_text():
    console = make_console()
    content = IngestedContent(source="demo", source_type=SourceType.TEXT, text="x" * 5000, title="Long report")
    render.render_ingested_preview(console, content)
    text = output_of(console)
    assert "5000" in text  # char count shown
    assert "…" in text  # truncation marker
    assert "Long report" in text


def test_render_ingested_preview_handles_empty_text():
    console = make_console()
    content = IngestedContent(source="demo", source_type=SourceType.IMAGE, text="")
    render.render_ingested_preview(console, content)
    assert "no extracted text" in output_of(console).lower()


def test_render_results_shows_finding_details(finding, valid_rule):
    console = make_console()
    render.render_results(console, [finding], [valid_rule])
    text = output_of(console)
    assert "Wildcard Get-Alias to Invoke-Expression" in text
    assert "T1027.010 (parent: T1027)" in text
    assert "86%" in text
    assert "Get-Alias" in text  # example snippet
    assert "p.4" in text  # source_ref
    assert "SIGMA" in text


def test_render_results_valid_rule_is_not_flagged(finding, valid_rule):
    console = make_console()
    render.render_results(console, [finding], [valid_rule])
    text = output_of(console)
    assert "VALIDATION FAILED" not in text


def test_render_results_invalid_rule_is_visibly_flagged(finding, invalid_rule):
    console = make_console()
    render.render_results(console, [finding], [invalid_rule])
    text = output_of(console)
    assert "VALIDATION FAILED" in text
    assert "unterminated subpattern" in text
    assert "✗" in text


def test_render_results_mixed_valid_and_invalid(finding, valid_rule, invalid_rule):
    console = make_console()
    render.render_results(console, [finding], [valid_rule, invalid_rule])
    text = output_of(console)
    assert "✓" in text
    assert "✗" in text


def test_render_results_dry_run_notes_missing_rules(finding):
    console = make_console()
    render.render_results(console, [finding], [], dry_run=True)
    text = output_of(console)
    assert "Wildcard Get-Alias to Invoke-Expression" in text
    assert "no rules generated" not in text  # dry_run suppresses the "missing rules" note


def test_render_results_non_dry_run_notes_missing_rules(finding):
    console = make_console()
    render.render_results(console, [finding], [], dry_run=False)
    assert "no rules generated" in output_of(console)


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------


def test_render_summary_counts(finding, valid_rule, invalid_rule):
    console = make_console()
    render.render_summary(console, [finding], [valid_rule, invalid_rule])
    text = output_of(console)
    assert "findings" in text
    assert "rules generated" in text
    # one finding, two rules, one valid one invalid
    lines = text.splitlines()
    joined = "\n".join(lines)
    assert "2" in joined  # rules generated
    assert "1" in joined  # passed / failed counts


# ---------------------------------------------------------------------------
# Providers table
# ---------------------------------------------------------------------------


def test_render_providers_table_shows_status_symbols():
    console = make_console()
    render.render_providers_table(
        console,
        {"openai": False, "ollama": True, "anthropic": None, "fake": True},
        default_provider="fake",
    )
    text = output_of(console)
    assert "openai" in text
    assert "ollama" in text
    assert "anthropic" in text
    assert "available" in text
    assert "unavailable" in text
    assert "unknown" in text
    assert "default" in text


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def test_render_error_shows_title_message_and_hint():
    console = make_console()
    render.render_error(console, title="ingest failed", message="could not read source", hint="try again")
    text = output_of(console)
    assert "ingest failed" in text
    assert "could not read source" in text
    assert "try again" in text


def test_render_error_verbose_shows_traceback():
    console = make_console()
    try:
        raise ValueError("boom")
    except ValueError:
        render.render_error(console, title="oops", message="boom", verbose=True)
    text = output_of(console)
    assert "Traceback" in text or "ValueError" in text


def test_render_error_non_verbose_hides_traceback():
    console = make_console()
    try:
        raise ValueError("boom")
    except ValueError:
        render.render_error(console, title="oops", message="boom", verbose=False)
    text = output_of(console)
    assert "Traceback" not in text


# ---------------------------------------------------------------------------
# Pipeline progress
# ---------------------------------------------------------------------------


def test_pipeline_progress_stage_updates():
    console = make_console()
    with render.pipeline_progress(console) as stage:
        stage.stage("ingesting…")
        stage.stage("detecting…")
        stage.finish("done.")
    text = output_of(console)
    assert "done." in text


# ---------------------------------------------------------------------------
# JSON / Markdown scriptable output
# ---------------------------------------------------------------------------


def test_to_json_round_trips(finding, valid_rule, invalid_rule):
    raw = render.to_json([finding], [valid_rule, invalid_rule], source="demo", provider="fake", model="fake-mini")
    data = json.loads(raw)  # must be parseable

    assert data["tool"] == "globwarden"
    assert data["source"] == "demo"
    assert data["provider"] == "fake"
    assert data["model"] == "fake-mini"

    assert data["summary"] == {
        "findings_count": 1,
        "rules_generated": 2,
        "rules_passed_validation": 1,
        "rules_failed_validation": 1,
    }

    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f["id"] == "f1"
    assert f["category"] == "wildcard_resolution"  # enum -> plain string
    assert f["confidence"] == pytest.approx(0.86)

    assert len(data["rules"]) == 2
    rule_types = {r["rule_type"] for r in data["rules"]}
    assert rule_types == {"sigma", "regex"}
    invalid = next(r for r in data["rules"] if not r["valid"])
    assert invalid["validation_note"] == "missing ), unterminated subpattern"


def test_to_json_empty_findings_round_trips():
    raw = render.to_json([], [], source="x", provider="fake", model=None)
    data = json.loads(raw)
    assert data["findings"] == []
    assert data["rules"] == []
    assert data["summary"]["findings_count"] == 0


def test_to_markdown_contains_expected_sections(finding, valid_rule, invalid_rule):
    text = render.to_markdown([finding], [valid_rule, invalid_rule], source="demo", provider="fake", model="fake-mini")
    assert text.startswith("# GlobWarden scan report")
    assert "Wildcard Get-Alias to Invoke-Expression" in text
    assert "```" in text
    assert "INVALID" in text
    assert "missing ), unterminated subpattern" in text


def test_to_markdown_no_findings():
    text = render.to_markdown([], [], source="demo", provider="fake", model=None)
    assert "No obfuscation techniques were identified" in text
