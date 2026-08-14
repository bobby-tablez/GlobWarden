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
# --output-file
# ---------------------------------------------------------------------------


def test_output_file_terminal_mode_writes_plain_text_no_ansi(tmp_path):
    out_path = tmp_path / "report.txt"
    result = runner.invoke(
        cli_module.app,
        ["scan", "demo", "--provider", "fake", "--output-file", str(out_path)],
    )
    assert result.exit_code == 0, result.output
    assert out_path.exists()

    content = out_path.read_text()
    assert "Wildcard Get-Alias" in content
    assert "REGEX" in content
    # Same rich panel layout as the live terminal (box-drawing preserved)...
    assert "╭─" in content and "╰─" in content
    # ...but as clean plain text -- Rich auto-detects a real file isn't a
    # live terminal and skips ANSI escape codes entirely.
    assert "\x1b" not in content

    # A confirmation that a file was written -- somewhere in the captured
    # output (CliRunner mixes stdout/stderr into .output; the message itself
    # goes to the stderr-backed console specifically).
    assert str(out_path) in result.output

    # The actual panel content must not ALSO have gone to stdout -- once
    # redirected to a file, it isn't duplicated to the terminal.
    assert "Wildcard Get-Alias" not in result.stdout

    # Confirm the file reads at the fixed, portable width (not whatever
    # width the test runner's own terminal happens to report).
    longest_border = max((len(line) for line in content.splitlines() if line.strip().startswith(("╭─", "┏━"))), default=0)
    assert longest_border <= cli_module.FILE_OUTPUT_WIDTH + 1  # +1: box-drawing corner rounding

    # --output-file's confirmation line uses the resolved value of `output`,
    # not the file's own extension -- .txt was chosen deliberately here to
    # confirm the file extension itself has no bearing on which renderer runs.


def test_output_file_json_mode_writes_valid_json_not_to_stdout(tmp_path):
    out_path = tmp_path / "report.json"
    result = runner.invoke(
        cli_module.app,
        ["scan", "demo", "--provider", "fake", "--output", "json", "--output-file", str(out_path)],
    )
    assert result.exit_code == 0, result.output
    assert out_path.exists()

    data = json.loads(out_path.read_text())
    assert data["tool"] == "globwarden"
    assert data["summary"]["findings_count"] == 4

    # The JSON must not ALSO be echoed to stdout once it's been redirected
    # to a file.
    assert result.stdout.strip() == ""
    assert str(out_path) in result.output


def test_output_file_markdown_mode_writes_markdown_not_to_stdout(tmp_path):
    out_path = tmp_path / "report.md"
    result = runner.invoke(
        cli_module.app,
        ["scan", "demo", "--provider", "fake", "--output", "markdown", "--output-file", str(out_path)],
    )
    assert result.exit_code == 0, result.output
    assert out_path.exists()

    content = out_path.read_text()
    assert content.startswith("# GlobWarden scan report")
    assert "Wildcard Get-Alias" in content

    assert result.stdout.strip() == ""
    assert str(out_path) in result.output


def test_output_file_unwritable_path_errors_cleanly_not_a_crash(tmp_path):
    # A parent directory that doesn't exist -- open() fails, and that must
    # surface as a normal CLIError panel + exit code 1, never a raw traceback.
    bad_path = tmp_path / "does-not-exist" / "report.txt"
    result = runner.invoke(
        cli_module.app,
        ["scan", "demo", "--provider", "fake", "--output-file", str(bad_path)],
    )
    assert result.exit_code == 1
    assert "could not write --output-file" in result.output
    assert not bad_path.exists()


def test_output_file_render_time_exception_leaves_no_partial_file(tmp_path, monkeypatch):
    # Regression: a real review caught that an exception raised *during*
    # rendering (not just a failure to open the file) used to leave a
    # truncated, misleadingly-plausible-looking file sitting at the real
    # destination path, plus a raw Python traceback -- the exact "last
    # resort, never dump a raw traceback unasked" scenario every other
    # failure mode in this command is already hardened against. Force a
    # mid-render crash and confirm: clean exit 1, a normal error panel (not a
    # traceback), and no file at all left behind at either the real path or
    # the atomic-write temp path.
    out_path = tmp_path / "report.txt"

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated render-time crash")

    monkeypatch.setattr(cli_module.render, "render_summary", _boom)

    result = runner.invoke(
        cli_module.app,
        ["scan", "demo", "--provider", "fake", "--output-file", str(out_path)],
    )

    assert result.exit_code == 1
    assert "could not write --output-file" in result.output
    assert "Traceback (most recent call last)" not in result.output
    assert not out_path.exists()
    assert not out_path.with_name(out_path.name + ".tmp").exists()


def test_output_file_success_leaves_no_leftover_temp_file(tmp_path):
    out_path = tmp_path / "report.txt"
    result = runner.invoke(
        cli_module.app,
        ["scan", "demo", "--provider", "fake", "--output-file", str(out_path)],
    )
    assert result.exit_code == 0, result.output
    assert out_path.exists()
    assert not out_path.with_name(out_path.name + ".tmp").exists()


def test_no_output_file_behaves_exactly_as_before(tmp_path):
    # Omitting --output-file entirely must be indistinguishable from before
    # this feature existed: content goes to stdout, nothing written to disk.
    result = runner.invoke(cli_module.app, ["scan", "demo", "--provider", "fake"])
    assert result.exit_code == 0, result.output
    assert "Wildcard Get-Alias" in result.output
    assert list(tmp_path.iterdir()) == []


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


def test_fake_provider_single_type_retry_prompt_shape():
    """A validation retry (see `engine.generate._finalize_with_retries`) uses
    `build_generation_system_prompt` with a *one-element* rule_types list --
    not a separate standalone prompt -- so FakeProvider must produce a
    correctly-shaped combined-style response (one nested section, keyed by
    that single format) for it too."""
    from globwarden.engine.prompts import RULE_CONTENT_KEY, build_generation_system_prompt

    provider = cli_module.FakeProvider()
    retry_prompt = build_generation_system_prompt([RuleType.REGEX])
    response = provider.complete(retry_prompt, "Category: wildcard_resolution")
    payload = json.loads(response.text)

    assert set(payload.keys()) == {"regex"}
    assert RULE_CONTENT_KEY[RuleType.REGEX] in payload["regex"]
    assert "explanation" in payload["regex"]


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
