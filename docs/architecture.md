# Architecture

This is the developer-facing tour of how GlobWarden is put together. It's derived
from the project's internal architecture contract and kept in sync with it; if
you're planning a non-trivial change, this doc plus a skim of the relevant module's
docstrings should be enough to orient you.

## The pipeline

`globwarden scan <source>` runs a straight-line pipeline. Each stage's output is a
plain `dataclass` from `globwarden/models.py`, so every stage is independently
testable with stub inputs — you don't need the LLM, a real PDF, or another
contributor's module finished to test the piece you're working on.

```
                 ┌──────────────────────────────────────────────────────────┐
                 │                        globwarden scan                    │
                 └──────────────────────────────────────────────────────────┘

  source (URL / PDF / text / code file / image)
         │
         ▼
  ┌────────────────────┐   IngestedContent(source, source_type, text, images, ...)
  │ ingest.detect_source│──────────────────────────────────────────────────────┐
  │      .load()        │                                                       │
  └────────────────────┘                                                       │
         │ dispatches to one of:                                               │
         │  ingest.url.from_url        (http(s):// sources)                   │
         │  ingest.pdf.from_pdf        (.pdf files)                           │
         │  ingest.image.from_image    (.png/.jpg/.gif/... screenshots)       │
         │  ingest.text.from_text      (.txt/.md/.ps1/.sh/... raw text/code)  │
         ▼                                                                     │
                                                                                 ▼
  ┌────────────────────┐   list[ObfuscationFinding]
  │  engine.detect      │───────────────────────────────────────────┐
  │  .find_obfuscation()│  (LLM call: system + user prompt from       │
  │  (content, provider)│   engine.prompts, json_mode=True, parsed    │
  └────────────────────┘   defensively regardless of json_mode)      │
         │                                                            │
         ▼                                                            ▼
  ┌────────────────────┐   list[GeneratedRule]  (one combined LLM call per finding,
  │  engine.generate    │────────────────────────────────────────────┐  covering every requested rule_type at once)
  │  .generate_rules()  │  regex · KQL · SPL · YARA-L · Sigma          │
  │  (findings, types,  │  each syntactically validated before return; │
  │   provider)         │  invalid=False + validation_note, never      │
  └────────────────────┘  silently dropped                            │
         │                                                            ▼
         ▼
  ┌────────────────────┐
  │     render.show()    │  rich terminal output: findings table,
  │                       │  per-finding rule panels, confidence/
  │                       │  ATT&CK mapping, summary footer
  └────────────────────┘
```

## Module map

```
globwarden/
  models.py     Shared dataclasses/enums every module codes against.
                 SourceType, IngestedContent, ObfuscationCategory,
                 ObfuscationFinding, RuleType, GeneratedRule.
                 Single source of truth for cross-module shapes — nothing
                 else redefines these.

  cli.py         Entry point (Typer app, `app = typer.Typer()`). Wires
                 ingest → engine → render together via the `scan` command
                 (--provider, --model, --rules, --output, --api-key,
                 --base-url, --dry-run, --verbose) and a `providers`
                 command that lists availability. Is the only module that
                 imports from all three of ingest/, engine/, and llm/.
                 Also ships a built-in `fake` provider and a literal
                 `demo` source for a network-free smoke test / live demo
                 that needs no API keys or local server.

  render.py      All `rich` terminal presentation. Nothing upstream of
                 this module prints directly — findings/rules are handed
                 to render.show() as plain dataclasses.

  llm/
    base.py               LLMProvider ABC + LLMResponse. The contract
                           every provider below implements.
    openai_provider.py     Cloud, official OpenAI chat-completions API.
    anthropic_provider.py  Cloud, Anthropic Messages API.
    gemini_provider.py     Cloud, Google Gemini generateContent API.
    openai_compatible.py   Shared base for local, OpenAI-wire-format
                           servers — request building, json_mode
                           handling, and response parsing live here once.
    ollama_provider.py     Local, subclasses OpenAICompatibleProvider,
                           default base_url http://localhost:11434/v1.
    lmstudio_provider.py   Local, subclasses OpenAICompatibleProvider,
                           default base_url http://localhost:1234/v1.
    registry.py            Name -> provider factory, backs --provider
                           and the `globwarden providers` command.

  ingest/
    detect_source.py  Single entry point (`load(source)`); sniffs
                       whether `source` is a URL, PDF path, image path,
                       or raw text/code, and dispatches accordingly.
    url.py             Fetches + extracts readable text from a web page,
                       plus a bounded number of embedded content-sized
                       <img> screenshots from the article body for vision
                       analysis (filtered before download; icons/logos/
                       tracking pixels/etc. never fetched).
    pdf.py             Extracts text (and, where present, embedded
                       images) from a local PDF.
    text.py            Raw text/code file loader — the fallback for
                       anything not URL/PDF/image.
    image.py           Loads a screenshot/image for vision-capable
                       providers; text stays empty, images is populated.
    errors.py          IngestError and subclasses (FetchError,
                       SizeLimitExceeded, UnsupportedSourceError,
                       ParseError) — callers catch this family, not raw
                       requests/IO exceptions.

  engine/
    detect.py    find_obfuscation(content, provider) -> list[ObfuscationFinding].
                 Builds the detection prompt from prompts.py, calls the
                 provider, parses/validates the LLM's JSON defensively
                 (never trusts json_mode alone). Long content is chunked;
                 independent chunks' calls run concurrently.
    generate.py   generate_rules(findings, rule_types, provider) ->
                 list[GeneratedRule]. One combined call per finding --
                 covering every requested rule_type in a single response,
                 asking for the minimal matching expression per format
                 (not a complete standalone rule) -- plus per-format
                 syntactic validation (regex compiles, YAML parses for
                 Sigma, etc.). A format that fails validation is retried
                 (failure reason fed back, narrow single-format prompt)
                 up to DEFAULT_MAX_VALIDATION_RETRIES times before being
                 returned as invalid. Independent findings' calls run
                 concurrently, bounded by DEFAULT_MAX_CONCURRENCY.
    prompts.py    Shared prompt templates for both detect.py and
                 generate.py — the wording that encodes "narrow input,
                 broad output, analyst-review-required" into the model's
                 actual instructions, not just the marketing copy.
```

## Design decisions worth knowing

- **Everything upstream of `render.py` is provider-and-presentation agnostic.**
  `engine/` and `ingest/` never import `rich` or touch the terminal; they take and
  return plain dataclasses. This is what makes the pipeline testable stage-by-stage
  and would make a future non-CLI frontend (a library import, a web UI) additive
  rather than a rewrite.
- **The LLM boundary is narrow on purpose.** Every provider reduces to one method,
  `complete()`, that takes a system prompt, a user prompt, optional images, and a
  `json_mode` hint, and returns `LLMResponse`. Nothing in `engine/` knows or cares
  which of the five providers it's talking to.
- **`json_mode=True` is a hint, not a guarantee.** Not every provider/model
  combination honors structured output reliably (this is especially true of small
  local models). `engine/detect.py` and `engine/generate.py` parse the response
  defensively either way — expect to find `json.loads` wrapped in fences-stripping
  and error handling, not a bare parse.
- **Validation never silently drops output.** A `GeneratedRule` that fails
  syntactic validation still comes back, with `valid=False` and a
  `validation_note` explaining why — surfaced in the terminal rather than hidden,
  because a detection engineer deciding whether to trust a rule needs to see the
  near-misses too.
- **Local providers share one HTTP implementation.** Ollama and LM Studio are both
  OpenAI-wire-format servers with different default ports; duplicating
  request-building logic for them would be pure risk with no benefit, hence
  `OpenAICompatibleProvider`. See `CONTRIBUTING.md` for how this makes adding a
  sixth (or seventh) local backend a ~5-line change.
- **Nothing in this codebase executes or evaluates ingested content.** GlobWarden
  reads and describes obfuscation; it never runs it, even inside a sandbox. If
  you're adding an ingestion path, this constraint is non-negotiable.

## Where to look next

- [`docs/providers.md`](providers.md) — setup details for each of the five LLM
  providers, including local server installation.
- [`globwarden/models.py`](../globwarden/models.py) — the authoritative dataclass
  definitions this document describes.
- `CONTRIBUTING.md` — the process for adding a provider or rule language.
