"""GlobWarden CLI entry point.

Framework choice: `typer` on top of `rich`. `rich` is effectively required by
the brief ("beautifully, in color"); `typer` was picked over plain
`argparse` because it gives us free `--help` generation with rich markup,
automatic `Enum`-backed `Choice` validation for `--output`/`--provider`,
and clean multi-command structure (`scan`, `providers`) with very little
boilerplate — the one extra dependency buys real ergonomics for a
demo-facing CLI. `argparse` would have been an equally legitimate call
(zero extra dependency); this project already needs `rich`, so the added
surface area from `typer` is small.

Pipeline wiring: `scan()` calls, in order, `ingest.detect_source.load()`,
`engine.detect.find_obfuscation()`, and `engine.generate.generate_rules()`
exactly per `globwarden/models.py`. All three are real, committed
modules as of this build. Each call site still imports its module lazily
and raises a clear `CLIError` (not a raw traceback) on `ImportError`, so a
genuinely missing/broken module fails with an actionable message rather
than an `AttributeError` deep in the pipeline — but there is no longer a
parallel stub implementation standing in for `engine.detect`/`.generate`:
an earlier version of this file carried one (~600 lines) as a placeholder
before those modules landed; a post-integration review confirmed it had
gone fully dead (its `except ImportError` branch could never fire once
`globwarden/engine/` existed) and it was deleted rather than left as
unreachable weight. The one exception is `_demo_content()` (`globwarden
scan demo`), which is kept deliberately: a fixed, network-free,
dependency-free source is worth having on hand for a quick offline demo,
independent of `ingest`. See `FakeProvider` below for the equivalent on
the LLM side — it stays, because it's the live `--provider fake`
demo/test path, not a stub.
"""

from __future__ import annotations

import base64
import inspect
import json
import os
import re
import time
from enum import Enum
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.markup import escape

from globwarden import __version__, render
from globwarden.llm.base import LLMProvider, LLMResponse
from globwarden.models import (
    GeneratedRule,
    IngestedContent,
    ObfuscationFinding,
    RuleType,
    SourceType,
)

try:  # ingest/errors.py already exists (Builder B); import defensively anyway
    from globwarden.ingest.errors import IngestError as _IngestError
except ImportError:  # pragma: no cover - only hit if that module regresses

    class _IngestError(Exception):
        pass


try:  # llm/errors.py already exists (Builder A); import defensively anyway
    from globwarden.llm.errors import LLMError as _LLMError
except ImportError:  # pragma: no cover

    class _LLMError(Exception):
        pass


try:  # engine/detect.py, engine/generate.py (Builder C); import defensively too
    from globwarden.engine.detect import DetectionError as _DetectionError
except ImportError:  # pragma: no cover - only hit before Builder C's module lands

    class _DetectionError(Exception):
        pass


try:
    from globwarden.engine.generate import GenerationError as _GenerationError
except ImportError:  # pragma: no cover

    class _GenerationError(Exception):
        pass


REAL_PROVIDER_NAMES = ["openai", "anthropic", "gemini", "ollama", "lmstudio"]

_RULE_TYPE_ALIASES = {
    "regex": RuleType.REGEX,
    "kql": RuleType.KQL,
    "spl": RuleType.SPL,
    "yara-l": RuleType.YARA_L,
    "yara_l": RuleType.YARA_L,
    "yaral": RuleType.YARA_L,
    "sigma": RuleType.SIGMA,
}
DEFAULT_RULES = "regex,kql,spl,yara-l,sigma"


class OutputFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    markdown = "markdown"


# Fixed width used for --output-file's rendering of 'terminal'-style output.
# The live terminal path adapts to whatever width the user's actual terminal
# happens to be (which is why a wide monitor produces a very wide capture) --
# a saved file should instead be a stable, portable width that reads well in
# a normal editor/pager/PR diff regardless of who opens it or how wide their
# screen was at scan time.
FILE_OUTPUT_WIDTH = 120


class ProviderChoice(str, Enum):
    openai = "openai"
    anthropic = "anthropic"
    gemini = "gemini"
    ollama = "ollama"
    lmstudio = "lmstudio"
    fake = "fake"  # built-in network-free stub, see FakeProvider below


class CLIError(Exception):
    """A pipeline failure with a title/message/hint already worded for a
    human — the top-level command handler renders these with `render.render_error`
    instead of ever showing a raw traceback (unless --verbose/--debug)."""

    def __init__(self, title: str, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.title = title
        self.message = message
        self.hint = hint


app = typer.Typer(
    name="globwarden",
    help=(
        "Feed GlobWarden a threat-intel report — a URL, PDF, code file, image, or raw "
        "text — and it uses an LLM to identify command obfuscation techniques "
        "(MITRE ATT&CK T1027.010) and generate the matching regex/detection logic for "
        "them, formatted for up to five query languages at once: regex, KQL, SPL, "
        "YARA-L, and Sigma. Output is the matching expression itself, not a complete "
        "standalone rule — drop it into your own rule structure."
    ),
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"globwarden {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show GlobWarden's version and exit.",
    ),
) -> None:
    """GlobWarden — command-obfuscation-technique-focused detection logic, in five query languages."""


# ===========================================================================
# Canned content shared by FakeProvider (talks JSON, matching engine/prompts.py's
# schemas, for when the real globwarden.engine module is present) and the stub
# engine further down (talks dataclasses directly, for when it isn't). Both
# describe the same four illustrative T1027.010 techniques so a demo run is
# coherent regardless of which path ends up live.
# ===========================================================================

_CANNED_FINDINGS: list[dict] = [
    {
        "id": "f1",
        "category": "wildcard_resolution",
        "technique_name": "Wildcard Get-Alias Resolution to Invoke-Expression",
        "description": (
            "Command-line alias lookups are performed with a truncated wildcard "
            "pattern (e.g. `Get-Alias i*x`) instead of the literal alias name, "
            "resolving to iex at runtime and defeating substring-match detections "
            "written against the literal string."
        ),
        "example_snippet": "(Get-Alias i*x)[0].Definition | % { & $_ $cmd }",
        "confidence": 0.91,
        "attack_mapping": "T1027.010 (parent: T1027)",
        "source_ref": None,
        "_triggers": ("get-alias", "get-command", "wildcard"),
    },
    {
        "id": "f2",
        "category": "character_masking",
        "technique_name": "Backtick-Split Cmdlet Name",
        "description": (
            "PowerShell's backtick escape character is inserted inside a known-bad "
            "cmdlet/alias name to break up the literal string while leaving runtime "
            "behavior unchanged -- e.g. I`E`X still resolves and executes as IEX."
        ),
        "example_snippet": "I`E`X (New-Object Net.WebClient).DownloadString($u)",
        "confidence": 0.88,
        "attack_mapping": "T1027.010 (parent: T1027)",
        "source_ref": None,
        "_triggers": ("`", "backtick"),
    },
    {
        "id": "f3",
        "category": "env_var_indirection",
        "technique_name": "Environment-Variable-Assembled Command",
        "description": (
            "The invoked command is built at runtime by concatenating fragments "
            "stored in environment variables, so no single suspicious string "
            "appears together in the command line as written on disk or in a "
            "script block log."
        ),
        "example_snippet": "$c = $env:CX + $env:EC + $env:SUF; iex $c",
        "confidence": 0.68,
        "attack_mapping": "T1027.010 (parent: T1027)",
        "source_ref": None,
        "_triggers": ("$env:", "environment variable"),
    },
    {
        "id": "f4",
        "category": "encoded_cradle",
        "technique_name": "Base64-Encoded Download Cradle",
        "description": (
            "A -EncodedCommand/-enc invocation carries a base64-encoded UTF-16LE "
            "payload that downloads and executes a secondary stage, hiding the "
            "actual download-and-execute logic from plain-text command-line scans."
        ),
        "example_snippet": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3...",
        "confidence": 0.93,
        "attack_mapping": "T1027.010 (parent: T1027), T1140 (Deobfuscate/Decode)",
        "source_ref": None,
        "_triggers": ("-enc", "encodedcommand", "base64"),
    },
]

# One regex template per category (string-keyed, matching ObfuscationCategory's
# .value -- used by FakeProvider's JSON responses; a second, enum-keyed copy
# lives further down for the dataclass-building stub engine). The
# ENCODED_CRADLE pattern is *deliberately* left with an unterminated group
# (missing closing paren). When FakeProvider is paired with the real
# engine.generate module, this is genuinely re.compile()'d, genuinely fails,
# genuinely triggers that module's real one-retry-then-flag behavior, and is
# genuinely still broken after the retry (FakeProvider returns the same
# pattern again) -- so the "invalid rule" render path gets exercised through
# real validation code, not a cosmetic flag flip.
_REGEX_TEMPLATES_BY_VALUE: dict[str, str] = {
    "wildcard_resolution": r"(?i)get-(alias|command)\s+[a-z]{1,3}\*[a-z]{0,4}\b",
    "character_masking": r"(?i)i`?e`?x|in`?vo`?ke-`?ex`?pression",
    "string_concatenation": r"(?i)['\"][a-z]{1,4}['\"]\s*\+\s*['\"][a-z]{1,4}['\"]",
    "env_var_indirection": r"(?i)\$env:[a-z0-9_]+.{0,60}(iex|invoke-expression)",
    "encoded_cradle": r"(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}(",
    "other": r"(?i)invoke-expression|iex\b",
}


_RULE_TYPE_SECTION_ORDER = [RuleType.REGEX, RuleType.KQL, RuleType.SPL, RuleType.YARA_L, RuleType.SIGMA]


def _sniff_requested_rule_types(system_prompt: str) -> list[RuleType]:
    """Figure out which rule types a *combined* generation call is asking for,
    from the `### <type>` section headers `prompts.build_generation_system_prompt`
    always includes for each requested format -- so FakeProvider can hand back a
    schema-correct canned response covering exactly the formats that were asked
    for, same as a real provider would."""
    return [rt for rt in _RULE_TYPE_SECTION_ORDER if f"### {rt.value}" in system_prompt]


def _fake_finding_response_dict(finding: dict) -> dict:
    """Build one finding's JSON-response dict from its `_CANNED_FINDINGS`
    entry, base64-encoding `example_snippet` into `example_snippet_b64` --
    `_CANNED_FINDINGS` keeps the plain-text form for readability in this
    source file, but the real schema (`DETECTION_SYSTEM_PROMPT`) asks for
    base64, and FakeProvider should exercise that exact real decode path
    (`engine.detect._decode_example_snippet`), not a shortcut."""
    result = {k: v for k, v in finding.items() if not k.startswith("_") and k != "example_snippet"}
    snippet = finding.get("example_snippet")
    result["example_snippet_b64"] = base64.b64encode(snippet.encode("utf-8")).decode("ascii") if snippet else None
    return result


def _fake_findings_response(user_prompt: str) -> str:
    """Schema-correct canned response for a detection-pass call
    (`{"findings": [...]}`, matching `DETECTION_SYSTEM_PROMPT`). Only returns
    findings whose trigger keyword(s) actually appear in the prompt (which
    embeds the ingested content) -- content with no recognizable obfuscation
    signal gets an honest empty result, same as `DETECTION_SYSTEM_PROMPT`
    rule #2 asks of a real model."""
    lowered = user_prompt.lower()
    selected = [
        _fake_finding_response_dict(finding)
        for finding in _CANNED_FINDINGS
        if any(trigger in lowered for trigger in finding["_triggers"])
    ]
    return json.dumps({"findings": selected})


def _fake_pattern_and_explanation(user_prompt: str) -> tuple[str, str]:
    """Pick a canned regex pattern keyed off the `Category: ...` line that
    `prompts.rule_generation_user_prompt` always embeds in the user prompt.
    Used for both the initial combined call and any single-format validation
    retry (same underlying prompt-builder, just given a one-element
    `rule_types` list) -- deliberately returns the same (still-broken, for
    encoded_cradle) pattern every time, so FakeProvider exercises the real
    "genuinely still invalid after exhausting every retry" code path, not
    just a first-attempt failure that happens to fix itself. See
    `_REGEX_TEMPLATES_BY_VALUE`."""
    match = re.search(r"Category:\s*(\S+)", user_prompt)
    category = match.group(1) if match else "other"
    pattern = _REGEX_TEMPLATES_BY_VALUE.get(category, _REGEX_TEMPLATES_BY_VALUE["other"])
    explanation = "Flags the characteristic tokens of this technique in command-line/script-block telemetry."
    return pattern, explanation


def _fake_combined_rule_response(rule_types: list[RuleType], user_prompt: str) -> str:
    """Schema-correct canned response for a combined generation call covering
    every format in `rule_types` -- one section per requested type, matching
    `prompts.build_generation_system_prompt`'s schema (minimal matching
    expression per format, not a full standalone rule). `rule_types` may be a
    single element -- that's exactly the shape a validation retry uses (see
    `engine.generate._finalize_with_retries`), and this function already
    handles it correctly since it's the same prompt-builder either way."""
    pattern, explanation = _fake_pattern_and_explanation(user_prompt)

    payload: dict[str, dict] = {}
    for rule_type in rule_types:
        if rule_type is RuleType.REGEX:
            payload["regex"] = {"pattern": pattern, "explanation": explanation}
        elif rule_type is RuleType.KQL:
            line = f'ProcessCommandLine matches regex @"{pattern}"'
            payload["kql"] = {"line": line, "explanation": explanation}
        elif rule_type is RuleType.SPL:
            line = f'regex ScriptBlockText="{pattern}"'
            payload["spl"] = {"line": line, "explanation": explanation}
        elif rule_type is RuleType.YARA_L:
            line = f"$e.target.process.command_line = /{pattern}/ nocase"
            payload["yara_l"] = {"line": line, "explanation": explanation}
        elif rule_type is RuleType.SIGMA:
            detection = {"selection": {"CommandLine|re": pattern}, "condition": "selection"}
            payload["sigma"] = {
                "detection_yaml": yaml.safe_dump(detection, sort_keys=False),
                "explanation": explanation,
            }

    return json.dumps(payload)


def _fake_response_for(system_prompt: str, user_prompt: str) -> str:
    try:
        from globwarden.engine.prompts import DETECTION_SYSTEM_PROMPT
    except ImportError:
        return _fake_findings_response(user_prompt)

    stripped = system_prompt.strip()
    if stripped == DETECTION_SYSTEM_PROMPT.strip():
        return _fake_findings_response(user_prompt)

    # A validation retry uses the same combined-prompt builder as the
    # initial call, just with a one-element rule_types list -- the "###
    # <type>" marker sniff below handles both shapes identically.
    rule_types = _sniff_requested_rule_types(system_prompt)
    if rule_types:
        return _fake_combined_rule_response(rule_types, user_prompt)

    # Unrecognized prompt shape (e.g. prompts.py's wording changed without a
    # matching update here) -- fall back to a findings response rather than
    # crashing FakeProvider outright.
    return _fake_findings_response(user_prompt)


# ===========================================================================
# FakeProvider — a real LLMProvider implementation, used for --provider fake
# ===========================================================================


class FakeProvider(LLMProvider):
    """Network-free stub provider so the CLI/renderer can be fully exercised
    (and demoed live, e.g. with no wifi) without any of the real cloud/local
    provider backends being wired up. Not one of the five providers required
    by the architecture brief — a deliberate extra. Implements the real
    `LLMProvider` ABC, including a small artificial delay, so it exercises
    the exact same interface `engine/` will call in production and gives the
    progress spinner something honest to show."""

    name = "fake"
    DEFAULT_MODEL = "fake-mini"

    def __init__(self, *, model: str | None = None, latency: float | None = None) -> None:
        self.model = model or self.DEFAULT_MODEL
        if latency is not None:
            self._latency = latency
        else:
            # Overridable so the test suite (and anyone scripting a lot of
            # scans) doesn't have to sit through demo-paced artificial delay.
            self._latency = float(os.environ.get("GLOBWARDEN_FAKE_LATENCY", "0.35"))

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        images: list[bytes] | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        time.sleep(self._latency)  # simulate inference latency for a realistic demo pace
        return LLMResponse(
            text=_fake_response_for(system_prompt, user_prompt),
            model=self.model,
            provider=self.name,
            raw={
                "system_prompt": system_prompt[:200],
                "user_prompt": user_prompt[:200],
                "images": len(images or []),
                "json_mode": json_mode,
            },
        )

    def is_available(self) -> bool:
        return True


# ===========================================================================
# Built-in demo source — always works, no network, no other builder's module
# ===========================================================================

DEMO_SOURCE_TEXT = """\
GlobWarden Demo Report -- "SPECTRAL#LOOM" Campaign (synthetic, for demo purposes only)

During a recent intrusion an actor was observed staging a PowerShell-based
loader that leaned heavily on command-line obfuscation to slip past
substring-based EDR and SIEM detections.

Alias resolution abuse: rather than invoking Invoke-Expression or its iex
alias directly, the loader first resolved the alias via a truncated
wildcard lookup -- (Get-Alias i*x)[0].Definition -- then invoked the
resolved value indirectly through the call operator.

Character masking: in a second-stage script recovered from disk, the actor
split the same alias using PowerShell's backtick escape character
(I`E`X), which parses identically to IEX at runtime while breaking naive
literal-string matching.

Environment variable indirection: command fragments were staged into
environment variables ($env:CX, $env:EC, $env:SUF) earlier in the script
and concatenated immediately before execution, so no single line of the
script -- or the resulting process command line -- contains the full
suspicious string at once.

Encoded download cradle: the final stage was launched via
powershell -nop -w hidden -enc <base64>, where the base64 blob decodes to
a UTF-16LE Net.WebClient download-and-execute cradle pointed at
hxxp[://]update-cdn-assets[.]example[.]net/s2.ps1 (defanged, non-routable
example domain).

None of these four techniques are individually novel, but chained together
they were enough to evade command-line-substring detections that hadn't
been updated to account for MITRE ATT&CK T1027.010.
"""


def _demo_content(source: str) -> IngestedContent:
    return IngestedContent(
        source=source,
        source_type=SourceType.TEXT,
        text=DEMO_SOURCE_TEXT,
        title='GlobWarden built-in demo report ("SPECTRAL#LOOM", synthetic)',
        metadata={"demo": True, "synthetic": True},
    )


# Recognized-looking extensions that, combined with the string NOT resolving to
# an existing file, are a strong signal of a typo'd path rather than intentional
# raw-text content — real pasted report text essentially never looks like this
# (no whitespace, short, ends in one of these). Kept intentionally conservative
# (whitespace-free, <200 chars) so a real multi-sentence raw-text scan that
# happens to mention "report.pdf" mid-sentence is never misidentified.
_PATH_LIKE_EXTENSIONS = (
    ".pdf",
    ".txt",
    ".ps1",
    ".py",
    ".sh",
    ".js",
    ".md",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
)


def _warn_if_path_like_typo(source: str, console: Console) -> None:
    """Surface a visible (but non-fatal) warning when the source argument looks
    like a typo'd file path that fell through to being scanned as literal text,
    per the documented (and intentionally unchanged) fallback rule in
    `ingest.detect_source.load()`. This is a UX safety net at the CLI layer
    only — the ingestion library itself stays pure and its documented/tested
    fallback behavior is untouched."""
    stripped = source.strip()
    if not stripped or "\n" in stripped or len(stripped) > 200:
        return
    if not stripped.lower().endswith(_PATH_LIKE_EXTENSIONS):
        return
    if Path(stripped).expanduser().is_file():
        return  # genuinely resolves — not a typo, nothing to warn about
    console.print(
        f"[bold yellow]⚠[/bold yellow] '{stripped}' looks like a file path but "
        "no such file exists — scanning it as literal text instead. If this was "
        "meant to be a file, check the path (use --verbose to confirm what was "
        "actually ingested).",
    )


def _load_source(source: str, *, verbose: bool, console: Console | None = None, user_agent: str | None = None) -> IngestedContent:
    if source.strip().lower() == "demo":
        return _demo_content(source)

    if console is not None:
        _warn_if_path_like_typo(source, console)

    try:
        from globwarden.ingest import detect_source
    except ImportError as exc:
        raise CLIError(
            "ingestion module not available",
            "globwarden.ingest.detect_source could not be imported — this usually "
            "means the installed globwarden package is incomplete or corrupted "
            "(a missing OPTIONAL dependency like pdfplumber/bs4/Pillow would NOT "
            "cause this; those are checked lazily per-source-type and raise a "
            'clear, specific error naming the exact `pip install "globwarden[...]"` '
            "extra to add, not this one).",
            hint="Try `pip install --force-reinstall globwarden`, or `globwarden "
            "scan demo` for a fully working, network-free demo run in the meantime.",
        ) from exc

    try:
        return detect_source.load(source, user_agent=user_agent)
    except _IngestError as exc:
        raise CLIError("could not read source", str(exc) or exc.__class__.__name__) from exc
    except CLIError:
        raise
    except Exception as exc:
        raise CLIError(
            "unexpected ingestion failure",
            str(exc) or exc.__class__.__name__,
            hint="re-run with --verbose for the full traceback.",
        ) from exc


# ===========================================================================
# Detection/generation engine wiring. `globwarden.engine.detect`/`.generate`
# are real, committed modules (Builder C) as of this build -- no fallback
# stub lives here anymore. An earlier version of this file carried a ~600
# line parallel stub detect/generate engine so this workstream could be
# built and demoed before Builder C's module existed; a harsh-critic review
# confirmed that stub had gone fully dead (its `except ImportError` branch
# never fires once `globwarden/engine/` is present) and recommended cutting
# it rather than leaving it as unreachable weight in the file a reviewer
# has to read to understand the CLI. `FakeProvider` above still exercises
# the real engine end to end for `--provider fake` demos/tests, so nothing
# about the CLI's own demoability was lost by removing it. The lazy import
# + clear-error pattern is kept (matching `_load_source`'s treatment of
# `globwarden.ingest`) purely so a genuinely missing/broken engine module
# still fails with an actionable message instead of a bare AttributeError.
# ===========================================================================


def _find_obfuscation(content: IngestedContent, provider: LLMProvider) -> list[ObfuscationFinding]:
    try:
        from globwarden.engine import detect as detect_engine
    except ImportError as exc:
        raise CLIError(
            "detection engine not available",
            "globwarden.engine.detect isn't importable in this build.",
            hint="Reinstall/repair the globwarden package, or re-run with --verbose for details.",
        ) from exc
    return detect_engine.find_obfuscation(content, provider)


def _generate_rules(
    findings: list[ObfuscationFinding],
    rule_types: list[RuleType],
    provider: LLMProvider,
) -> list[GeneratedRule]:
    try:
        from globwarden.engine import generate as generate_engine
    except ImportError as exc:
        raise CLIError(
            "rule generation engine not available",
            "globwarden.engine.generate isn't importable in this build.",
            hint="Use --dry-run to see detected techniques without generating rules.",
        ) from exc
    return generate_engine.generate_rules(findings, rule_types, provider)


# ===========================================================================
# Provider resolution
# ===========================================================================


def _try_import_registry():
    try:
        from globwarden.llm import registry

        return registry
    except ImportError:
        return None


def _real_provider_names(registry_mod) -> list[str]:
    """Prefer the registry's own `list_providers()` (so a 6th provider added
    there, e.g. vLLM, shows up here for free); fall back to the five names
    the architecture brief requires if that function isn't there."""
    if registry_mod is not None:
        list_fn = getattr(registry_mod, "list_providers", None)
        if callable(list_fn):
            try:
                names = list(list_fn())
                if names:
                    return names
            except Exception:
                pass
    return list(REAL_PROVIDER_NAMES)


def _build_provider(
    registry_mod,
    name: str,
    *,
    model: str | None,
    api_key: str | None,
    base_url: str | None,
) -> LLMProvider:
    """Best-effort adapter to Builder A's `globwarden.llm.registry` factory.

    The architecture doc names `registry.py` a "provider factory" but doesn't
    pin an exact function signature, so this introspects whatever
    `get_provider` it finds and only passes the kwargs it actually accepts
    (or all of them, if it takes **kwargs) rather than hard-failing on a
    signature mismatch. If the real registry ends up shaped differently,
    this is the one function that needs adjusting.
    """
    get_provider = getattr(registry_mod, "get_provider", None)
    if get_provider is None:
        raise CLIError(
            "provider backend incompatible",
            "globwarden.llm.registry has no get_provider() function.",
        )
    kwargs: dict = {}
    try:
        params = inspect.signature(get_provider).parameters
    except (TypeError, ValueError):
        params = {}
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
    for key, value in (("model", model), ("api_key", api_key), ("base_url", base_url)):
        if value is not None and (key in params or has_var_kw):
            kwargs[key] = value
    return get_provider(name, **kwargs)


def _resolve_provider(
    provider_choice: ProviderChoice | None,
    *,
    model: str | None,
    api_key: str | None,
    base_url: str | None,
) -> tuple[str, LLMProvider]:
    if provider_choice is not None:
        name = provider_choice.value
        if name == "fake":
            return "fake", FakeProvider(model=model)

        registry_mod = _try_import_registry()
        if registry_mod is None:
            raise CLIError(
                "provider backend not available",
                f"'{name}' can't be used yet -- globwarden.llm.registry hasn't landed in this build.",
                hint="Pass --provider fake for a network-free demo run.",
            )
        provider_inst = _build_provider(registry_mod, name, model=model, api_key=api_key, base_url=base_url)
        try:
            available = provider_inst.is_available()
        except Exception:
            available = False
        if not available:
            raise CLIError(
                f"provider '{name}' not available",
                f"'{name}' failed its availability check (missing API key, unreachable local server, etc.).",
                hint="Run `globwarden providers` to see status, or pass --api-key/--base-url.",
            )
        return name, provider_inst

    # --provider not given: auto-detect the first available real provider.
    registry_mod = _try_import_registry()
    if registry_mod is None:
        raise CLIError(
            "no provider backend available",
            "globwarden.llm.registry could not be imported, so no real provider "
            "can be auto-detected. This usually means the installed globwarden "
            "package is incomplete or corrupted.",
            hint="Try reinstalling globwarden, or pass --provider fake for a network-free demo run in the meantime.",
        )
    for name in _real_provider_names(registry_mod):
        try:
            provider_inst = _build_provider(registry_mod, name, model=model, api_key=api_key, base_url=base_url)
            if provider_inst.is_available():
                return name, provider_inst
        except Exception:
            continue
    raise CLIError(
        "no LLM provider available",
        "None of openai/anthropic/gemini/ollama/lmstudio are currently configured or reachable.",
        hint=(
            "Run `globwarden providers` to see status for each, set an API key, start a "
            "local Ollama/LM Studio server, or pass --provider fake to demo without one."
        ),
    )


def _provider_statuses() -> dict[str, bool | None]:
    statuses: dict[str, bool | None] = {}
    registry_mod = _try_import_registry()
    for name in _real_provider_names(registry_mod):
        if registry_mod is None:
            statuses[name] = None
            continue
        try:
            inst = _build_provider(registry_mod, name, model=None, api_key=None, base_url=None)
            statuses[name] = bool(inst.is_available())
        except Exception:
            statuses[name] = None
    statuses["fake"] = True
    return statuses


def _parse_rule_types(raw: str) -> list[RuleType]:
    tokens = [t.strip().lower() for t in raw.split(",") if t.strip()]
    if not tokens:
        raise CLIError(
            "invalid --rules value",
            "No rule types given.",
            hint="Use e.g. --rules regex,sigma, or omit --rules to generate all five.",
        )
    result: list[RuleType] = []
    for token in tokens:
        rule_type = _RULE_TYPE_ALIASES.get(token)
        if rule_type is None:
            raise CLIError(
                "invalid --rules value",
                f"Unknown rule type '{token}'.",
                hint="Valid values: regex, kql, spl, yara-l, sigma (comma-separated).",
            )
        if rule_type not in result:
            result.append(rule_type)
    return result


# ===========================================================================
# Commands
# ===========================================================================


@app.command(
    epilog=(
        "Examples:\n\n"
        "  globwarden scan demo --provider fake\n\n"
        "  globwarden scan https://example.com/report --provider openai\n\n"
        "  globwarden scan ./report.pdf --rules regex,sigma --output json > findings.json\n\n"
        "  globwarden scan ./report.pdf --output-file report.txt\n\n"
        "  globwarden scan ./report.pdf --output markdown --output-file report.md"
    )
)
def scan(
    source: str = typer.Argument(
        ...,
        help="URL, local PDF/text/code/image path, or the literal 'demo' for a built-in, network-free demo source.",
    ),
    provider: ProviderChoice | None = typer.Option(  # noqa: B008 - standard typer pattern
        None,
        "--provider",
        help="LLM provider to use. Omit to auto-detect the first available real "
        "provider. 'fake' is a built-in, network-free stub for demos/testing.",
    ),
    model: str | None = typer.Option(None, "--model", help="Model name/tag to use with the chosen provider."),
    rules: str = typer.Option(
        DEFAULT_RULES,
        "--rules",
        help="Comma-separated rule types to generate.",
    ),
    output: OutputFormat = typer.Option(  # noqa: B008 - standard typer pattern
        OutputFormat.terminal,
        "--output",
        case_sensitive=False,
        help="How to render results. 'json'/'markdown' print clean, scriptable output to stdout with no rich styling.",
    ),
    output_file: Path | None = typer.Option(  # noqa: B008 - standard typer pattern
        None,
        "--output-file",
        help="Write results to this file instead of stdout, in whichever --output "
        "format was chosen. 'terminal' (the default) writes the same colorized "
        "panel layout shown on screen, as plain text (box-drawing preserved, no "
        "ANSI codes) at a fixed, portable width -- suitable for sharing or "
        "archiving a scan that's too long for a terminal to scroll back through.",
    ),
    api_key: str | None = typer.Option(None, "--api-key", help="Override the provider's default API key env var."),
    base_url: str | None = typer.Option(
        None,
        "--base-url",
        help="Override the provider's base URL (mainly for Ollama/LM Studio or a self-hosted OpenAI-compatible endpoint).",
    ),
    user_agent: str | None = typer.Option(
        None,
        "--user-agent",
        envvar="GLOBWARDEN_USER_AGENT",
        help="Override the User-Agent sent for URL fetches (default: a standard browser "
        "string, since some sites -- security/threat-intel blogs especially -- block "
        "requests that self-identify as a bot).",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Ingest + detect only; skip rule generation."),
    verbose: bool = typer.Option(
        False,
        "-v",
        "--verbose",
        "--debug",
        help="Show full tracebacks and extra pipeline detail on failure.",
    ),
) -> None:
    """Scan a threat-intel report and generate detection content for the
    command obfuscation techniques (T1027.010) it describes."""
    out_console = Console()
    err_console = Console(stderr=True)

    if output == OutputFormat.terminal:
        render.banner(out_console, version=__version__)

    try:
        rule_types = _parse_rule_types(rules)
    except CLIError as exc:
        render.render_error(err_console, title=exc.title, message=exc.message, hint=exc.hint, verbose=verbose)
        raise typer.Exit(code=2) from None

    try:
        provider_name, provider_inst = _resolve_provider(provider, model=model, api_key=api_key, base_url=base_url)
    except CLIError as exc:
        render.render_error(err_console, title=exc.title, message=exc.message, hint=exc.hint, verbose=verbose)
        raise typer.Exit(code=1) from None

    resolved_model = model or getattr(provider_inst, "model", None)

    if output == OutputFormat.terminal:
        render.scan_header(
            out_console,
            source=source,
            provider=provider_name,
            model=resolved_model,
            rule_types=rule_types,
            dry_run=dry_run,
        )
        if dry_run:
            render.render_dry_run_notice(out_console)

    findings: list[ObfuscationFinding] = []
    generated_rules: list[GeneratedRule] = []

    try:
        with render.pipeline_progress(err_console) as stage:
            stage.stage("[1/3] ingesting source…")
            content = _load_source(source, verbose=verbose, console=err_console, user_agent=user_agent)

            stage.stage("[2/3] detecting obfuscation techniques…")
            findings = _find_obfuscation(content, provider_inst)

            if not dry_run:
                # engine.generate calls the provider once per finding (covering
                # every requested rule type in that one combined call), running
                # independent findings' calls concurrently -- against a real
                # cloud LLM this can still take a while, with the spinner's
                # text otherwise static the whole time. Surfacing the expected
                # call count at least sets an honest expectation instead of a
                # silent "[3/3] generating detection rules…" that looks
                # stalled on stage. "at least" because a format that fails
                # validation gets retried (capped, per format) -- the true
                # count can run higher than this floor.
                call_estimate = len(findings)
                calls_note = f" (~{call_estimate}+ LLM call{'s' if call_estimate != 1 else ''})" if call_estimate else ""
                stage.stage(f"[3/3] generating detection rules{calls_note}…")
                generated_rules = _generate_rules(findings, rule_types, provider_inst)

            stage.finish("pipeline complete.")
    except CLIError as exc:
        render.render_error(err_console, title=exc.title, message=exc.message, hint=exc.hint, verbose=verbose)
        raise typer.Exit(code=1) from None
    except _LLMError as exc:
        render.render_error(
            err_console,
            title="LLM request failed",
            message=str(exc) or exc.__class__.__name__,
            hint="Check your API key / --base-url / --model, or run `globwarden providers`.",
            verbose=verbose,
        )
        raise typer.Exit(code=1) from None
    except _DetectionError as exc:
        render.render_error(
            err_console,
            title="detection pass failed",
            message=str(exc) or exc.__class__.__name__,
            hint="The model's response couldn't be parsed as JSON — try a different model.",
            verbose=verbose,
        )
        raise typer.Exit(code=1) from None
    except _GenerationError as exc:
        render.render_error(
            err_console,
            title="rule generation failed",
            message=str(exc) or exc.__class__.__name__,
            hint="The model's response couldn't be parsed as JSON — try a different model.",
            verbose=verbose,
        )
        raise typer.Exit(code=1) from None
    except Exception as exc:  # last-resort net: never dump a raw traceback unasked
        render.render_error(
            err_console,
            title="unexpected error",
            message=str(exc) or exc.__class__.__name__,
            hint=None if verbose else "re-run with --verbose for the full traceback.",
            verbose=verbose,
        )
        raise typer.Exit(code=1) from None

    if output == OutputFormat.terminal and output_file is None:
        out_console.print()
        render.render_results(out_console, findings, generated_rules, dry_run=dry_run)
        if not findings and verbose:
            # Makes good on the no-findings panel's own "try --verbose to see
            # what was ingested" hint -- previously that hint did nothing.
            out_console.print()
            render.render_ingested_preview(out_console, content)
        if not dry_run:
            out_console.print()
            render.render_summary(out_console, findings, generated_rules)
    elif output_file is None:
        content_str = (
            render.to_json(findings, generated_rules, source=source, provider=provider_name, model=resolved_model)
            if output == OutputFormat.json
            else render.to_markdown(findings, generated_rules, source=source, provider=provider_name, model=resolved_model)
        )
        typer.echo(content_str)
    else:
        # Written atomically (a temp file, renamed into place only once
        # everything succeeded) and with a catch-all exception handler --
        # not just OSError. A render-time bug or any other mid-write failure
        # must never leave a truncated, misleadingly-plausible-looking file
        # sitting at the real destination path for someone to open later
        # unattended (the whole reason this feature exists is to be read
        # later by someone who didn't watch the console), and must never dump
        # a raw traceback either, matching this command's own "last resort"
        # handling for every other failure mode.
        tmp_path = output_file.with_name(output_file.name + ".tmp")
        try:
            if output == OutputFormat.terminal:
                with open(tmp_path, "w", encoding="utf-8") as file_handle:
                    # Rich auto-detects a real file isn't a live terminal and
                    # renders plain text (box-drawing characters, layout, no
                    # ANSI escape codes) accordingly -- no special flag
                    # needed, same render.* calls as the live path, just a
                    # different Console/width.
                    target_console = Console(file=file_handle, width=FILE_OUTPUT_WIDTH)
                    target_console.print()
                    render.render_results(target_console, findings, generated_rules, dry_run=dry_run)
                    if not findings and verbose:
                        target_console.print()
                        render.render_ingested_preview(target_console, content)
                    if not dry_run:
                        target_console.print()
                        render.render_summary(target_console, findings, generated_rules)
            else:
                content_str = (
                    render.to_json(findings, generated_rules, source=source, provider=provider_name, model=resolved_model)
                    if output == OutputFormat.json
                    else render.to_markdown(
                        findings, generated_rules, source=source, provider=provider_name, model=resolved_model
                    )
                )
                tmp_path.write_text(content_str, encoding="utf-8")
            tmp_path.replace(output_file)
        except Exception as exc:
            tmp_path.unlink(missing_ok=True)
            render.render_error(
                err_console,
                title="could not write --output-file",
                message=f"Failed to write to {str(output_file)!r}: {exc}",
                hint="Check the path is writable and its parent directory exists."
                if isinstance(exc, OSError)
                else "re-run with --verbose for the full traceback.",
                verbose=verbose,
            )
            raise typer.Exit(code=1) from None
        # soft_wrap=True: a filesystem path must never be broken across a
        # line by width-based wrapping (unlike prose, a wrapped path can't be
        # copy-pasted back out usably).
        err_console.print(f"[dim]✓ written to {escape(str(output_file))}[/dim]", soft_wrap=True)


@app.command()
def providers() -> None:
    """List known LLM providers and whether each is currently available."""
    console = Console()
    statuses = _provider_statuses()
    render.render_providers_table(console, statuses)


if __name__ == "__main__":
    app()
