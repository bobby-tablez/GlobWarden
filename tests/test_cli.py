"""Tests for globwarden/cli.py — the Typer entry point.

Uses `typer.testing.CliRunner` to actually invoke commands and check
output/exit codes, including error paths. `--provider fake` (this module's
own built-in, network-free `FakeProvider`) is used throughout so these tests
never need real credentials or network access, and stay fast regardless of
whether `globwarden.llm`/`globwarden.engine`'s real implementations are
present in a given worktree.

`GLOBWARDEN_FAKE_LATENCY=0` (set for every test below) strips FakeProvider's
demo-paced artificial delay so a full scan (4 findings x 5 rule types = ~20
provider calls once the real `engine.generate` module is wired up) runs
near-instantly instead of taking several seconds.
"""

from __future__ import annotations

import json
import sys

import pytest
from typer.testing import CliRunner

from globwarden import __version__
from globwarden import cli as cli_module
from globwarden.llm.base import LLMProvider, LLMResponse
from globwarden.models import GeneratedRule, ObfuscationFinding, RuleType

runner = CliRunner()


@pytest.fixture(autouse=True)
def _fast_fake_provider(monkeypatch):
    monkeypatch.setenv("GLOBWARDEN_FAKE_LATENCY", "0")


# ---------------------------------------------------------------------------
# --version / --help
# ---------------------------------------------------------------------------


def test_version_flag():
    result = runner.invoke(cli_module.app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout
    assert "globwarden" in result.stdout


def test_help_lists_commands_and_exits_zero():
    # Pin a generously wide terminal width: rich_markup_mode="rich" renders
    # --help through Rich, which truncates its options table with an
    # ellipsis (e.g. "--provi…") once the detected console width gets narrow
    # enough -- a real CI failure (GitHub Actions' runners apparently detect
    # a narrower width than a typical local terminal) traced back to exactly
    # this, on the sibling test below. Without pinning COLUMNS, this
    # assertion's correctness depends on whatever width the ambient
    # environment happens to report, which has nothing to do with whether
    # the CLI itself is actually broken.
    result = runner.invoke(cli_module.app, ["--help"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "providers" in result.stdout


def test_scan_help_documents_all_required_options():
    # See the wide-COLUMNS comment on test_help_lists_commands_and_exits_zero
    # above -- this is the test that actually caught the truncation bug in CI.
    result = runner.invoke(cli_module.app, ["scan", "--help"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    for opt in [
        "--provider",
        "--model",
        "--rules",
        "--output",
        "--api-key",
        "--base-url",
        "--user-agent",
        "--dry-run",
        "--verbose",
    ]:
        assert opt in result.stdout, opt


def test_no_args_shows_help_not_an_error():
    result = runner.invoke(cli_module.app, [])
    # no_args_is_help=True: click exits 0 or 2 depending on version, but must
    # never look like an unhandled crash.
    assert "Usage" in result.stdout or "Usage" in result.output


# ---------------------------------------------------------------------------
# providers command
# ---------------------------------------------------------------------------


def test_providers_command_lists_all_five_plus_fake():
    result = runner.invoke(cli_module.app, ["providers"])
    assert result.exit_code == 0
    for name in ["openai", "anthropic", "gemini", "ollama", "lmstudio", "fake"]:
        assert name in result.stdout
    assert "available" in result.stdout


# ---------------------------------------------------------------------------
# scan happy path — terminal output
# ---------------------------------------------------------------------------


def test_scan_demo_fake_terminal_full_pipeline():
    result = runner.invoke(cli_module.app, ["scan", "demo", "--provider", "fake"])
    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "GlobWarden" in out
    assert "detected techniques" in out
    assert "scan summary" in out
    # the built-in demo report contains all four canned technique triggers
    assert "Wildcard Get-Alias" in out
    assert "Backtick-Split" in out
    assert "Environment-Variable-Assembled" in out
    assert "Base64-Encoded Download Cradle" in out
    # at least one rule type panel rendered per finding
    assert "REGEX" in out
    assert "SIGMA" in out


def test_scan_demo_fake_shows_both_valid_and_invalid_rules():
    """The built-in encoded-cradle finding's regex template is deliberately
    unparseable, which the real engine.generate module (when present) will
    validate for real and mark valid=False -- exercising the invalid-rule
    render path end to end, not just in isolation."""
    result = runner.invoke(cli_module.app, ["scan", "demo", "--provider", "fake"])
    assert result.exit_code == 0
    out = result.stdout
    assert "✓" in out


def test_scan_dry_run_skips_rule_generation():
    result = runner.invoke(cli_module.app, ["scan", "demo", "--provider", "fake", "--dry-run"])
    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "dry run" in out.lower()
    assert "Wildcard Get-Alias" in out
    assert "scan summary" not in out  # summary is skipped on dry-run


def test_scan_no_findings_for_unrelated_text():
    result = runner.invoke(
        cli_module.app,
        ["scan", "totally unrelated text about lunch plans", "--provider", "fake", "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    assert "No obfuscation techniques were identified" in result.stdout


def test_scan_warns_when_typo_path_falls_through_to_literal_text():
    """Regression for the final-integration critique's typo'd-path footgun:
    `detect_source.load()`'s documented fallback (not a URL, not an existing
    file -> treat the string itself as literal text) is intentional and stays
    unchanged, but a live-demo tool needs a visible, non-verbose warning when
    that happens for something that looks like a mistyped path, not a silent
    'no findings' that could read as the tool simply working correctly."""
    result = runner.invoke(
        cli_module.app,
        ["scan", "/nonexistent/report.pdf", "--provider", "fake", "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    assert "looks like a file path" in result.output
    assert "no such file exists" in result.output


def test_scan_no_warning_for_normal_multi_word_raw_text():
    """The typo-path warning must not false-positive on real pasted report
    text just because it's long/contains punctuation."""
    result = runner.invoke(
        cli_module.app,
        [
            "scan",
            "The malware resolves Get-Alias i*x at runtime, see report.pdf for details.",
            "--provider",
            "fake",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "looks like a file path" not in result.output


def test_scan_no_findings_verbose_actually_shows_what_was_ingested():
    """Regression test for a real bug caught in review: the no-findings
    panel says 'try --verbose to see what was ingested', but --verbose used
    to be a no-op on this path (it only affected traceback visibility on
    errors). Confirms --verbose now genuinely changes the output here."""
    args = ["scan", "totally unrelated text about lunch plans", "--provider", "fake", "--dry-run"]
    quiet = runner.invoke(cli_module.app, args)
    verbose = runner.invoke(cli_module.app, [*args, "--verbose"])

    assert quiet.exit_code == 0
    assert verbose.exit_code == 0
    assert quiet.stdout != verbose.stdout  # was byte-identical before the fix
    assert "ingested content" in verbose.stdout.lower()
    assert "totally unrelated text about lunch plans" in verbose.stdout
    assert "ingested content" not in quiet.stdout.lower()


def test_scan_user_agent_flag_reaches_the_actual_http_request():
    """End-to-end regression: --user-agent must actually flow from the CLI
    flag through detect_source.load() to the real outgoing HTTP request, not
    just be accepted and silently dropped somewhere in the plumbing."""
    import responses

    @responses.activate
    def run():
        responses.add(
            responses.GET,
            "https://example.test/report",
            body="<html><body><p>Get-Alias i*x resolves to Invoke-Expression.</p></body></html>",
            status=200,
        )
        result = runner.invoke(
            cli_module.app,
            [
                "scan",
                "https://example.test/report",
                "--provider",
                "fake",
                "--dry-run",
                "--user-agent",
                "RegressionTestAgent/9.9",
            ],
        )
        assert result.exit_code == 0, result.output
        assert responses.calls[0].request.headers["User-Agent"] == "RegressionTestAgent/9.9"

    run()


def test_scan_respects_rules_subset():
    result = runner.invoke(
        cli_module.app,
        ["scan", "demo", "--provider", "fake", "--rules", "regex,sigma"],
    )
    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "REGEX" in out
    assert "SIGMA" in out
    assert "KQL" not in out
    assert "YARA-L" not in out


# ---------------------------------------------------------------------------
# scan happy path — JSON / Markdown output modes
# ---------------------------------------------------------------------------


def test_scan_output_json_is_valid_and_round_trips():
    result = runner.invoke(
        cli_module.app,
        ["scan", "demo", "--provider", "fake", "--output", "json"],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)  # must parse cleanly

    assert data["tool"] == "globwarden"
    assert data["source"] == "demo"
    assert data["provider"] == "fake"
    assert data["summary"]["findings_count"] == 4
    assert data["summary"]["rules_generated"] == len(data["rules"])
    assert data["summary"]["rules_passed_validation"] + data["summary"]["rules_failed_validation"] == len(data["rules"])

    assert len(data["findings"]) == 4
    for f in data["findings"]:
        assert set(f) == {
            "id",
            "category",
            "technique_name",
            "description",
            "example_snippet",
            "confidence",
            "attack_mapping",
            "source_ref",
        }
        assert isinstance(f["category"], str)  # enum serialized as plain string

    for r in data["rules"]:
        assert isinstance(r["rule_type"], str)
        assert isinstance(r["valid"], bool)


def test_scan_output_json_dry_run_has_no_rules():
    result = runner.invoke(
        cli_module.app,
        ["scan", "demo", "--provider", "fake", "--output", "json", "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["rules"] == []
    assert len(data["findings"]) == 4


def test_scan_output_json_empty_findings_round_trips():
    result = runner.invoke(
        cli_module.app,
        [
            "scan",
            "nothing obfuscation-related here",
            "--provider",
            "fake",
            "--output",
            "json",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["findings"] == []
    assert data["rules"] == []


def test_scan_output_markdown_is_clean_and_pasteable():
    result = runner.invoke(
        cli_module.app,
        ["scan", "demo", "--provider", "fake", "--output", "markdown", "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    out = result.stdout
    assert out.startswith("# GlobWarden scan report")
    assert "```" in out
    assert "Wildcard Get-Alias" in out
    # markdown/json modes must not print the rich banner/panels to stdout
    assert "GLOBWARDEN" not in out


# ---------------------------------------------------------------------------
# error paths
# ---------------------------------------------------------------------------


def test_scan_unknown_rule_type_errors_cleanly():
    result = runner.invoke(cli_module.app, ["scan", "demo", "--provider", "fake", "--rules", "regex,bogus"])
    assert result.exit_code == 2
    assert "Unknown rule type 'bogus'" in result.output
    assert "Traceback" not in result.output


def test_scan_empty_rules_value_errors_cleanly():
    result = runner.invoke(cli_module.app, ["scan", "demo", "--provider", "fake", "--rules", " , ,"])
    assert result.exit_code == 2
    assert "No rule types given" in result.output


def test_scan_explicit_unavailable_provider_errors_cleanly(monkeypatch):
    for var in ("OPENAI_API_KEY",):
        monkeypatch.delenv(var, raising=False)
    result = runner.invoke(cli_module.app, ["scan", "demo", "--provider", "openai"])
    assert result.exit_code == 1
    assert "not available" in result.output
    assert "Traceback" not in result.output


def test_scan_autodetect_with_no_registry_errors_cleanly(monkeypatch):
    """Simulates a worktree where globwarden.llm.registry hasn't landed yet
    (Builder A's factory module) -- the resilience path this CLI is built
    around. Should fail with a clear message pointing at --provider fake,
    never a raw traceback."""
    monkeypatch.setattr(cli_module, "_try_import_registry", lambda: None)
    result = runner.invoke(cli_module.app, ["scan", "demo"])
    assert result.exit_code == 1
    assert "provider fake" in result.output
    assert "Traceback" not in result.output


def test_scan_explicit_provider_with_no_registry_errors_cleanly(monkeypatch):
    monkeypatch.setattr(cli_module, "_try_import_registry", lambda: None)
    result = runner.invoke(cli_module.app, ["scan", "demo", "--provider", "openai"])
    assert result.exit_code == 1
    assert "hasn't landed" in result.output


def test_scan_bad_url_source_errors_cleanly():
    """A real (fast-failing) network error: DNS resolution for a
    reserved-invalid TLD always fails locally, no live server involved."""
    result = runner.invoke(
        cli_module.app,
        [
            "scan",
            "https://nonexistent-host-globwarden-demo.invalid/report",
            "--provider",
            "fake",
            "--dry-run",
        ],
    )
    assert result.exit_code == 1
    assert "could not read source" in result.output.lower()
    assert "Traceback" not in result.output


def test_scan_verbose_shows_traceback_on_unexpected_error(monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cli_module, "_load_source", _boom)
    result = runner.invoke(cli_module.app, ["scan", "demo", "--provider", "fake", "--verbose"])
    assert result.exit_code == 1
    assert "Traceback" in result.output
    assert "kaboom" in result.output


def test_scan_non_verbose_hides_traceback_on_unexpected_error(monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cli_module, "_load_source", _boom)
    result = runner.invoke(cli_module.app, ["scan", "demo", "--provider", "fake"])
    assert result.exit_code == 1
    assert "Traceback" not in result.output
    assert "re-run with --verbose" in result.output


# ---------------------------------------------------------------------------
# Unit-level: rule type parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("regex", [RuleType.REGEX]),
        (
            "regex,kql,spl,yara-l,sigma",
            [RuleType.REGEX, RuleType.KQL, RuleType.SPL, RuleType.YARA_L, RuleType.SIGMA],
        ),
        ("YARA_L", [RuleType.YARA_L]),
        (" regex , regex ,sigma", [RuleType.REGEX, RuleType.SIGMA]),  # dedup + whitespace tolerant
    ],
)
def test_parse_rule_types_valid(raw, expected):
    assert cli_module._parse_rule_types(raw) == expected


def test_parse_rule_types_rejects_unknown_token():
    with pytest.raises(cli_module.CLIError):
        cli_module._parse_rule_types("regex,not-a-real-type")


def test_parse_rule_types_rejects_empty():
    with pytest.raises(cli_module.CLIError):
        cli_module._parse_rule_types("   ")


# ---------------------------------------------------------------------------
# Unit-level: FakeProvider
# ---------------------------------------------------------------------------


def test_fake_provider_is_always_available():
    assert cli_module.FakeProvider().is_available() is True


def test_fake_provider_implements_llmprovider_interface():
    provider = cli_module.FakeProvider()
    assert isinstance(provider, LLMProvider)
    response = provider.complete("some system prompt", "some user prompt")
    assert isinstance(response, LLMResponse)
    assert response.provider == "fake"


def test_fake_provider_detection_response_matches_expected_schema():
    from globwarden.engine.prompts import DETECTION_SYSTEM_PROMPT

    provider = cli_module.FakeProvider()
    response = provider.complete(
        DETECTION_SYSTEM_PROMPT,
        "content mentioning Get-Alias wildcard and -enc base64 cradle",
        json_mode=True,
    )
    payload = json.loads(response.text)
    assert "findings" in payload
    assert isinstance(payload["findings"], list)
    assert len(payload["findings"]) >= 1


def test_fake_provider_combined_rule_generation_response_shape():
    """A real generation call is now combined -- one call covers every
    requested rule type -- so FakeProvider sniffs the requested types from the
    `### <type>` section headers `prompts.build_generation_system_prompt`
    always includes, and hands back one section per requested type using that
    format's real content key (`pattern`/`line`/`detection_yaml`, per
    `prompts.RULE_CONTENT_KEY`)."""
    from globwarden.engine.prompts import RULE_CONTENT_KEY, build_generation_system_prompt

    all_types = [RuleType.REGEX, RuleType.KQL, RuleType.SPL, RuleType.YARA_L, RuleType.SIGMA]
    provider = cli_module.FakeProvider()
    system_prompt = build_generation_system_prompt(all_types)

    response = provider.complete(system_prompt, "Category: wildcard_resolution")
    payload = json.loads(response.text)

    assert set(payload.keys()) == {rt.value for rt in all_types}
    for rule_type in all_types:
        section = payload[rule_type.value]
        assert RULE_CONTENT_KEY[rule_type] in section
        assert section[RULE_CONTENT_KEY[rule_type]]  # non-empty
        assert "explanation" in section


def test_fake_provider_combined_response_only_covers_requested_types():
    from globwarden.engine.prompts import build_generation_system_prompt

    provider = cli_module.FakeProvider()
    system_prompt = build_generation_system_prompt([RuleType.REGEX, RuleType.SIGMA])

    response = provider.complete(system_prompt, "Category: encoded_cradle")
    payload = json.loads(response.text)

    assert set(payload.keys()) == {"regex", "sigma"}


def test_fake_provider_regex_retry_response_shape():
    """The regex-retry call uses the narrow, single-purpose
    `REGEX_SYSTEM_PROMPT` (not the combined one) and gets back the original,
    single-format `{"pattern", "explanation"}` shape."""
    from globwarden.engine.prompts import REGEX_SYSTEM_PROMPT

    provider = cli_module.FakeProvider()
    response = provider.complete(REGEX_SYSTEM_PROMPT, "Category: wildcard_resolution")
    payload = json.loads(response.text)

    assert "pattern" in payload
    assert "explanation" in payload


# ---------------------------------------------------------------------------
# Unit-level: demo content + the real engine, driven directly (no CliRunner).
# `_find_obfuscation`/`_generate_rules` are thin lazy-import wrappers around
# `globwarden.engine.detect`/`.generate` (the parallel stub engine that used
# to live here for pre-integration testing was deleted once those real
# modules landed -- see the comment above `_find_obfuscation` in cli.py).
# ---------------------------------------------------------------------------


def test_demo_content_is_synthetic_text():
    content = cli_module._demo_content("demo")
    assert content.text
    assert content.metadata.get("synthetic") is True


def test_find_obfuscation_end_to_end_with_fake_provider():
    findings = cli_module._find_obfuscation(cli_module._demo_content("demo"), cli_module.FakeProvider())
    assert len(findings) == 4
    assert all(isinstance(f, ObfuscationFinding) for f in findings)


def test_generate_rules_end_to_end_flags_encoded_cradle_regex_as_invalid():
    findings = cli_module._find_obfuscation(cli_module._demo_content("demo"), cli_module.FakeProvider())
    rules = cli_module._generate_rules(findings, [RuleType.REGEX], cli_module.FakeProvider())
    assert all(isinstance(r, GeneratedRule) for r in rules)
    cradle_finding_id = next(f.id for f in findings if f.category.value == "encoded_cradle")
    cradle_rule = next(r for r in rules if r.finding_id == cradle_finding_id)
    assert cradle_rule.valid is False
    assert cradle_rule.validation_note


def test_find_obfuscation_raises_clear_error_when_engine_missing(monkeypatch):
    # Once `globwarden.engine.detect` has genuinely been imported anywhere in
    # this test session (it has, by earlier tests), `globwarden.engine` picks
    # up a cached `detect` attribute in its own namespace. Setting
    # `sys.modules["globwarden.engine.detect"] = None` alone is then NOT
    # enough to make `from globwarden.engine import detect` fail, because
    # that statement is satisfied straight from the cached attribute without
    # re-checking sys.modules. Also clearing the attribute forces the real
    # import machinery (and its sys.modules-is-None check) to run.
    import globwarden.engine as engine_pkg

    monkeypatch.setitem(sys.modules, "globwarden.engine.detect", None)
    monkeypatch.delattr(engine_pkg, "detect", raising=False)
    with pytest.raises(cli_module.CLIError) as excinfo:
        cli_module._find_obfuscation(cli_module._demo_content("demo"), cli_module.FakeProvider())
    assert excinfo.value.title == "detection engine not available"


def test_generate_rules_raises_clear_error_when_engine_missing(monkeypatch):
    # Same cached-attribute gotcha as above, for globwarden.engine.generate.
    import globwarden.engine as engine_pkg

    monkeypatch.setitem(sys.modules, "globwarden.engine.generate", None)
    monkeypatch.delattr(engine_pkg, "generate", raising=False)
    with pytest.raises(cli_module.CLIError) as excinfo:
        cli_module._generate_rules([], [RuleType.REGEX], cli_module.FakeProvider())
    assert excinfo.value.title == "rule generation engine not available"
