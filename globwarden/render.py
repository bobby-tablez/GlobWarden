"""Rich terminal rendering for GlobWarden.

This module owns every pixel the user sees: the startup banner, the live
pipeline progress indicator, the per-finding/per-rule results view, the
summary table, and the plain-text JSON/Markdown output modes.

Design note: every function takes an explicit `rich.console.Console` (or
constructs a fresh one) rather than relying on a single module-level
singleton. Rich resolves `Console().file` against `sys.stdout` at print
time, so this also plays nicely with `typer.testing.CliRunner` /
`click.testing.CliRunner`, which temporarily swap out `sys.stdout` for the
duration of an invocation.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager

from rich import box
from rich.console import Console, Group, RenderableType
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from globwarden.models import GeneratedRule, IngestedContent, ObfuscationFinding, RuleType

__all__ = [
    "banner",
    "scan_header",
    "pipeline_progress",
    "render_results",
    "render_summary",
    "render_providers_table",
    "render_error",
    "render_dry_run_notice",
    "render_ingested_preview",
    "to_json",
    "to_markdown",
]

# --------------------------------------------------------------------------
# Palette — dark/terminal-hacker aesthetic. Kept as named constants so the
# whole tool can be re-themed from one place if that's ever wanted.
#
# Matches the amber/cyan palette used everywhere else in this project's brand
# (assets/banner.svg, docs/index.html) — an earlier version of this file used
# a phosphor-green/cyan pair instead, which didn't match. Cyan stays reserved
# for MITRE ATT&CK/framework-specific tags specifically (matching the same
# semantic convention used in docs/index.html), not as a general second
# accent.
# --------------------------------------------------------------------------
BRAND = "#f2a53c"  # amber
BRAND_DIM = "#7d551f"
ACCENT = "#62d2e8"  # cyan — reserved for ATT&CK / technical tags specifically
WARN = "#ffb454"
BAD = "#ff5c57"
MUTED = "grey62"
FAINT = "grey42"

_LEXER_BY_RULE_TYPE = {
    RuleType.REGEX: "text",
    RuleType.KQL: "text",
    RuleType.SPL: "text",
    RuleType.YARA_L: "yara",
    RuleType.SIGMA: "yaml",
}

_RULE_LABEL = {
    RuleType.REGEX: "REGEX",
    RuleType.KQL: "KQL  (Microsoft Sentinel)",
    RuleType.SPL: "SPL  (Splunk)",
    RuleType.YARA_L: "YARA-L  (Chronicle / Google SecOps)",
    RuleType.SIGMA: "SIGMA",
}

_CATEGORY_LABEL = {
    "character_masking": "Character Masking",
    "wildcard_resolution": "Wildcard / Glob Resolution",
    "string_concatenation": "String Concatenation",
    "env_var_indirection": "Env Var Indirection",
    "encoded_cradle": "Encoded Download Cradle",
    "other": "Other / Uncategorized",
}


def _category_label(category) -> str:
    value = category.value if hasattr(category, "value") else str(category)
    return _CATEGORY_LABEL.get(value, value.replace("_", " ").title())


def _rule_type_value(rule_type) -> str:
    return rule_type.value if hasattr(rule_type, "value") else str(rule_type)


def _rule_type_display(rule_type) -> str:
    """Human-facing spelling for a rule type -- 'yara-l' (hyphen), matching
    the `--rules` CLI flag's own spelling, rather than the enum's raw
    underscore-separated `.value` (which JSON/Markdown output still use
    verbatim, since that's the stable machine-readable form)."""
    return _rule_type_value(rule_type).replace("_", "-")


# --------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------


def banner(console: Console, *, version: str = "0.3.2") -> None:
    """Print the startup banner. Deliberately not full figlet ASCII art —
    a tight, well-kerned wordmark in a heavy-bordered panel reads sharper
    on a projector than a hand-drawn font, and it can't come out lopsided
    at an unexpected terminal width."""
    mark = Text("◈", style=f"bold {BRAND}")
    wordmark = Text()
    for i, ch in enumerate("GLOBWARDEN"):
        wordmark.append(ch, style=f"bold {BRAND}" if i % 2 == 0 else f"bold {ACCENT}")
        wordmark.append(" ")

    title_line = Text.assemble(mark, "  ", wordmark)
    tagline = Text(
        "one obfuscated pattern in — regex-based detection logic out, in five query languages",
        style=f"italic {MUTED}",
    )
    meta = Text.assemble(
        ("T1027.010", f"bold {ACCENT}"),
        (" command obfuscation  ·  ", FAINT),
        (f"v{version}", MUTED),
    )

    body = Group(title_line, Text(""), tagline, Text(""), meta)
    console.print(
        Panel(
            body,
            box=box.HEAVY,
            border_style=BRAND_DIM,
            padding=(1, 4),
            title="[bold]GlobWarden[/bold]",
            title_align="left",
            subtitle="[dim]feed it a report, get detection content[/dim]",
            subtitle_align="right",
        )
    )


def scan_header(
    console: Console,
    *,
    source: str,
    provider: str,
    model: str | None,
    rule_types: list,
    dry_run: bool = False,
) -> None:
    rule_str = ", ".join(_rule_type_display(rt) for rt in rule_types)
    table = Table.grid(padding=(0, 2))
    table.add_column(style=f"bold {MUTED}", justify="right")
    table.add_column(style="bold white")
    table.add_row("target", escape(source))
    table.add_row("provider", f"[{BRAND}]{provider}[/{BRAND}]" + (f" ({model})" if model else ""))
    table.add_row("rule types", rule_str if not dry_run else f"{rule_str} [dim](skipped — dry run)[/dim]")
    console.print(table)
    console.print(Rule(style=BRAND_DIM))


def render_ingested_preview(console: Console, content: IngestedContent) -> None:
    """Shown after a no-findings result when `--verbose` is passed, so the
    no-findings panel's own "try --verbose to see what was ingested" line
    is actually true rather than a dead-end hint. Also doubles as a quick
    sanity check for the case a source string looked like a file path but
    didn't exist and got silently read as literal text instead: the preview
    will visibly show a raw path string as the "ingested" content."""
    source_type = content.source_type.value if hasattr(content.source_type, "value") else str(content.source_type)
    text = content.text or ""
    preview = text[:600].strip()
    truncated = len(text) > 600

    grid = Table.grid(padding=(0, 1))
    grid.add_column(style=f"bold {MUTED}", justify="right", width=12)
    grid.add_column(ratio=1)
    grid.add_row("source", escape(content.source))
    grid.add_row("type", source_type)
    if content.title:
        grid.add_row("title", escape(content.title))
    grid.add_row("chars", str(len(text)))
    if content.images:
        grid.add_row("images", str(len(content.images)))
    grid.add_row("", "")
    if preview:
        grid.add_row("text", Text(preview + (" …" if truncated else ""), style=FAINT))
    else:
        grid.add_row("text", Text("(no extracted text)", style=FAINT))

    console.print(
        Panel(
            grid,
            title="[bold]ingested content (--verbose)[/bold]",
            border_style=FAINT,
            box=box.ROUNDED,
        )
    )


def render_dry_run_notice(console: Console) -> None:
    console.print(
        Text(
            "dry run — rule generation skipped, showing detected techniques only",
            style=f"italic {WARN}",
        )
    )
    console.print()


# --------------------------------------------------------------------------
# Live pipeline progress
# --------------------------------------------------------------------------


class StageProgress:
    """Thin wrapper around a single indeterminate `rich.progress.Progress`
    task so `cli.py` can narrate pipeline stages without knowing anything
    about rich internals."""

    def __init__(self, progress: Progress, task_id: TaskID) -> None:
        self._progress = progress
        self._task_id = task_id

    def stage(self, description: str) -> None:
        self._progress.update(self._task_id, description=description)

    def finish(self, description: str = "done.") -> None:
        self._progress.update(self._task_id, description=description)
        self._progress.refresh()


@contextmanager
def pipeline_progress(console: Console) -> Iterator[StageProgress]:
    """Context manager driving the ingest -> detect -> generate spinner.

    Matters a lot for a live demo: LLM calls take a few seconds, and a
    frozen terminal reads as broken. This keeps a spinner + elapsed timer
    moving the whole time.
    """
    progress = Progress(
        SpinnerColumn(style=BRAND),
        TextColumn("[bold]{task.description}[/bold]"),
        BarColumn(bar_width=24, style=FAINT, complete_style=BRAND, pulse_style=BRAND),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )
    with progress:
        task_id = progress.add_task("starting…", total=None)
        yield StageProgress(progress, task_id)


# --------------------------------------------------------------------------
# Results view
# --------------------------------------------------------------------------


def _confidence_bar(confidence: float, width: int = 10) -> Text:
    confidence = max(0.0, min(1.0, confidence))
    filled = round(confidence * width)
    color = BRAND if confidence >= 0.75 else (WARN if confidence >= 0.5 else BAD)
    bar = Text()
    bar.append("▰" * filled, style=color)
    bar.append("▱" * (width - filled), style=FAINT)
    bar.append(f"  {confidence * 100:.0f}%", style=f"bold {color}")
    return bar


def _finding_panel(finding: ObfuscationFinding, *, index: int, total: int) -> Panel:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style=f"bold {MUTED}", justify="right", width=12)
    grid.add_column(ratio=1)

    grid.add_row("category", f"[{ACCENT}]{escape(_category_label(finding.category))}[/{ACCENT}]")
    grid.add_row("att&ck", f"[bold {ACCENT}]{escape(finding.attack_mapping)}[/bold {ACCENT}]")

    conf_row = Table.grid()
    conf_row.add_column()
    conf_row.add_row(_confidence_bar(finding.confidence))
    grid.add_row("confidence", conf_row)

    grid.add_row("", "")
    grid.add_row("", Text(finding.description, style="white"))

    if finding.example_snippet:
        grid.add_row("", "")
        grid.add_row(
            "example",
            Syntax(
                finding.example_snippet,
                "powershell",
                theme="ansi_dark",
                background_color="default",
                word_wrap=True,
            ),
        )

    if finding.source_ref:
        grid.add_row("", "")
        grid.add_row("source", Text(finding.source_ref, style=FAINT))

    title_name = escape(finding.technique_name)
    title = f"[bold white][{index}/{total}][/bold white] [bold {BRAND}]{title_name}[/bold {BRAND}]"
    return Panel(
        grid,
        title=title,
        title_align="left",
        border_style=BRAND_DIM,
        box=box.ROUNDED,
        padding=(1, 2),
    )


def _rule_panel(rule: GeneratedRule) -> Panel:
    lexer = _LEXER_BY_RULE_TYPE.get(rule.rule_type, "text")
    label = _RULE_LABEL.get(rule.rule_type, _rule_type_value(rule.rule_type).upper())

    body_parts: list[RenderableType] = []

    if not rule.valid:
        body_parts.append(
            Text(
                f"⚠ VALIDATION FAILED — {rule.validation_note or 'reason not given'}",
                style=f"bold {BAD}",
            )
        )
        body_parts.append(Text(""))

    body_parts.append(
        Syntax(
            rule.content,
            lexer,
            theme="ansi_dark",
            background_color="default",
            word_wrap=True,
            indent_guides=False,
        )
    )
    body_parts.append(Text(""))
    body_parts.append(Text(rule.explanation, style=f"italic {MUTED}"))

    if rule.valid:
        title = f"[bold {BRAND}]✓ {label}[/bold {BRAND}]"
        border = BRAND_DIM
    else:
        title = f"[bold {BAD}]✗ {label}[/bold {BAD}]"
        border = BAD

    return Panel(
        Group(*body_parts),
        title=title,
        title_align="left",
        border_style=border,
        box=box.SQUARE,
        padding=(1, 2),
    )


def render_results(
    console: Console,
    findings: list[ObfuscationFinding],
    rules: list[GeneratedRule],
    *,
    dry_run: bool = False,
) -> None:
    if not findings:
        console.print(
            Panel(
                "No obfuscation techniques were identified in this source.\n"
                "This can be a true negative, or a sign the source didn't contain enough "
                "signal for the model to work with — try --verbose to see what was ingested.",
                border_style=WARN,
                title="[bold]no findings[/bold]",
                box=box.ROUNDED,
            )
        )
        return

    rules_by_finding: dict[str, list[GeneratedRule]] = defaultdict(list)
    for rule in rules:
        rules_by_finding[rule.finding_id].append(rule)

    console.print(Rule(f"[bold {BRAND}]detected techniques[/bold {BRAND}]", style=BRAND_DIM))
    console.print()

    total = len(findings)
    for i, finding in enumerate(findings, start=1):
        console.print(_finding_panel(finding, index=i, total=total))

        finding_rules = rules_by_finding.get(finding.id, [])
        if finding_rules:
            console.print()
            for rule in finding_rules:
                console.print(Padding(_rule_panel(rule), (0, 0, 0, 4)))
        elif not dry_run:
            console.print(Padding(Text("(no rules generated for this finding)", style=FAINT), (0, 0, 0, 4)))
        console.print()


def render_summary(console: Console, findings: list[ObfuscationFinding], rules: list[GeneratedRule]) -> None:
    table = Table(title="scan summary", box=box.ROUNDED, border_style=BRAND_DIM, title_style=f"bold {BRAND}")
    table.add_column("metric", style=f"bold {MUTED}")
    table.add_column("value", justify="right")

    valid_count = sum(1 for r in rules if r.valid)
    invalid_count = len(rules) - valid_count

    table.add_row("findings", str(len(findings)))
    table.add_row("rules generated", str(len(rules)))
    table.add_row("passed validation", f"[{BRAND}]{valid_count}[/{BRAND}]")
    table.add_row(
        "failed validation",
        f"[{BAD}]{invalid_count}[/{BAD}]" if invalid_count else f"[{BRAND}]0[/{BRAND}]",
    )

    if rules:
        by_type: dict[str, int] = defaultdict(int)
        for r in rules:
            by_type[_rule_type_value(r.rule_type)] += 1
        breakdown = "  ".join(f"{k}:{v}" for k, v in sorted(by_type.items()))
        table.add_row("by rule type", breakdown)

    console.print(table)


# --------------------------------------------------------------------------
# Providers table
# --------------------------------------------------------------------------

PROVIDER_META = {
    "openai": ("cloud", "OPENAI_API_KEY"),
    "anthropic": ("cloud", "ANTHROPIC_API_KEY"),
    "gemini": ("cloud", "GEMINI_API_KEY / GOOGLE_API_KEY"),
    "ollama": ("local", "server at http://localhost:11434"),
    "lmstudio": ("local", "server at http://localhost:1234"),
    "fake": ("demo", "no setup — built-in stub for testing/demos"),
}


def render_providers_table(
    console: Console,
    statuses: dict[str, bool | None],
    *,
    default_provider: str | None = None,
) -> None:
    table = Table(title="LLM providers", box=box.ROUNDED, border_style=BRAND_DIM, title_style=f"bold {BRAND}")
    table.add_column("provider", style="bold white")
    table.add_column("type", style=MUTED)
    table.add_column("status", justify="center")
    table.add_column("requires", style=MUTED)

    for name, available in statuses.items():
        kind, requires = PROVIDER_META.get(name, ("?", ""))
        if available is True:
            status = f"[bold {BRAND}]● available[/bold {BRAND}]"
        elif available is False:
            status = f"[{BAD}]○ unavailable[/{BAD}]"
        else:
            status = f"[{FAINT}]? unknown[/{FAINT}]"
        label = name
        if name == default_provider:
            label = f"{name} [dim](default)[/dim]"
        table.add_row(label, kind, status, requires)

    console.print(table)


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


def render_error(
    console: Console,
    *,
    title: str,
    message: str,
    hint: str | None = None,
    verbose: bool = False,
) -> None:
    body_parts: list[RenderableType] = [Text(message, style="white")]
    if hint:
        body_parts.append(Text(""))
        body_parts.append(Text(f"tip: {hint}", style=f"italic {MUTED}"))
    console.print(
        Panel(
            Group(*body_parts),
            title=f"[bold {BAD}]✗ {escape(title)}[/bold {BAD}]",
            title_align="left",
            border_style=BAD,
            box=box.HEAVY,
            padding=(1, 2),
        )
    )
    if verbose:
        console.print_exception(show_locals=False)


# --------------------------------------------------------------------------
# Scriptable output modes
# --------------------------------------------------------------------------


def _finding_to_dict(finding: ObfuscationFinding) -> dict:
    return {
        "id": finding.id,
        "category": finding.category.value if hasattr(finding.category, "value") else finding.category,
        "technique_name": finding.technique_name,
        "description": finding.description,
        "example_snippet": finding.example_snippet,
        "confidence": finding.confidence,
        "attack_mapping": finding.attack_mapping,
        "source_ref": finding.source_ref,
    }


def _rule_to_dict(rule: GeneratedRule) -> dict:
    return {
        "finding_id": rule.finding_id,
        "rule_type": rule.rule_type.value if hasattr(rule.rule_type, "value") else rule.rule_type,
        "content": rule.content,
        "explanation": rule.explanation,
        "valid": rule.valid,
        "validation_note": rule.validation_note,
    }


def _summary_dict(findings: list[ObfuscationFinding], rules: list[GeneratedRule]) -> dict:
    valid_count = sum(1 for r in rules if r.valid)
    return {
        "findings_count": len(findings),
        "rules_generated": len(rules),
        "rules_passed_validation": valid_count,
        "rules_failed_validation": len(rules) - valid_count,
    }


def to_json(
    findings: list[ObfuscationFinding],
    rules: list[GeneratedRule],
    *,
    source: str | None = None,
    provider: str | None = None,
    model: str | None = None,
) -> str:
    """Clean, scriptable JSON — pipe into jq, ticket automation, etc."""
    payload = {
        "tool": "globwarden",
        "source": source,
        "provider": provider,
        "model": model,
        "summary": _summary_dict(findings, rules),
        "findings": [_finding_to_dict(f) for f in findings],
        "rules": [_rule_to_dict(r) for r in rules],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


_MD_FENCE_LANG = {
    RuleType.REGEX: "text",
    RuleType.KQL: "kusto",
    RuleType.SPL: "text",
    RuleType.YARA_L: "yara",
    RuleType.SIGMA: "yaml",
}


def to_markdown(
    findings: list[ObfuscationFinding],
    rules: list[GeneratedRule],
    *,
    source: str | None = None,
    provider: str | None = None,
    model: str | None = None,
) -> str:
    """Clean Markdown — paste straight into a ticket or a PR description."""
    rules_by_finding: dict[str, list[GeneratedRule]] = defaultdict(list)
    for rule in rules:
        rules_by_finding[rule.finding_id].append(rule)

    lines: list[str] = ["# GlobWarden scan report", ""]
    if source:
        lines.append(f"**Source:** `{source}`  ")
    if provider:
        lines.append(f"**Provider:** `{provider}`" + (f" (`{model}`)" if model else "") + "  ")
    valid_count = sum(1 for r in rules if r.valid)
    lines.append(
        f"**Findings:** {len(findings)}  ·  **Rules generated:** {len(rules)}  "
        f"·  **Passed validation:** {valid_count}/{len(rules)}"
    )
    lines.append("")

    if not findings:
        lines.append("No obfuscation techniques were identified in this source.")
        return "\n".join(lines) + "\n"

    for i, finding in enumerate(findings, start=1):
        category = _category_label(finding.category)
        lines.append(f"## {i}. {finding.technique_name}")
        lines.append("")
        lines.append(f"- **Category:** {category}")
        lines.append(f"- **ATT&CK mapping:** {finding.attack_mapping}")
        lines.append(f"- **Confidence:** {finding.confidence * 100:.0f}%")
        if finding.source_ref:
            lines.append(f"- **Source ref:** {finding.source_ref}")
        lines.append("")
        lines.append(finding.description)
        lines.append("")
        if finding.example_snippet:
            lines.append("**Example:**")
            lines.append("```powershell")
            lines.append(finding.example_snippet)
            lines.append("```")
            lines.append("")

        for rule in rules_by_finding.get(finding.id, []):
            label = _RULE_LABEL.get(rule.rule_type, _rule_type_value(rule.rule_type).upper())
            status = "valid" if rule.valid else "**INVALID**"
            lines.append(f"### {label} ({status})")
            lines.append("")
            if not rule.valid and rule.validation_note:
                lines.append(f"> ⚠ {rule.validation_note}")
                lines.append("")
            fence_lang = _MD_FENCE_LANG.get(rule.rule_type, "text")
            lines.append(f"```{fence_lang}")
            lines.append(rule.content)
            lines.append("```")
            lines.append("")
            lines.append(rule.explanation)
            lines.append("")

    return "\n".join(lines) + "\n"
