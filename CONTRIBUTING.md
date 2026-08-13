# Contributing to GlobWarden

Thanks for considering a contribution. GlobWarden is young and the shape of the
codebase is deliberately simple — a small, well-defined pipeline (`ingest → engine →
render`, wired together by `cli.py`) built around the shared data models in
`globwarden/models.py`. Most contributions fall into one of three buckets: a new LLM
provider, a new rule language, or a bug/quality fix. All three are covered below.

If you're looking for how the pieces fit together first, read
[`docs/architecture.md`](docs/architecture.md).

## Development setup

GlobWarden targets Python 3.10+.

```bash
git clone https://github.com/bobby-tablez/GlobWarden.git
cd globwarden

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
```

`.[dev]` pulls in the full ingestion stack (PDF/web/image extras), plus `pytest`,
`pytest-cov`, `responses` (for mocked-HTTP provider tests), and `ruff`.

Verify the setup:

```bash
pytest
ruff check .
```

## Running the tool locally during development

```bash
python -m globwarden.cli providers
python -m globwarden.cli scan ./some-report.pdf --provider ollama
python -m globwarden.cli scan demo --provider fake   # network-free smoke test
```

(or `globwarden ...` directly once you've done an editable install — see above).

## Running tests

```bash
pytest                                   # full suite
pytest tests/llm/                        # just the provider layer
pytest -k "openai"                       # anything matching "openai"
pytest --cov=globwarden --cov-report=term-missing   # with coverage
```

Guidelines for tests:

- **Never make live calls to paid cloud APIs.** Cloud provider tests
  (`tests/llm/test_openai_provider.py` and friends) must mock HTTP with
  `unittest.mock` or the `responses` library, and assert both request construction
  (headers, payload shape, endpoint) and response parsing.
- Local providers (Ollama, LM Studio) may be tested against a real local install if
  you have one running — that's encouraged for stronger integration coverage — but
  the suite must still pass with mocked responses when no local server is present, so
  CI doesn't depend on a live Ollama instance.
- Ingestion tests may hit real, public, free URLs (e.g. a stable blog post) for
  realistic coverage — never anything requiring auth or a paid tier.
- Never `eval` or execute content pulled from a fixture or a real source. GlobWarden
  reads and describes obfuscation; it never runs it. This applies to test code too.
- All example/test fixtures (sample reports, obfuscated snippets) must be synthetic
  or clearly drawn from public reporting, and defanged per convention (`hxxp`, `[.]`,
  placeholder domains).

## Adding a new LLM provider

This is the contribution GlobWarden is built to make easy. Every provider implements
the small `LLMProvider` ABC in `globwarden/llm/base.py`:

```python
class LLMProvider(ABC):
    name: str

    @abstractmethod
    def complete(self, system_prompt, user_prompt, images=None, json_mode=False) -> LLMResponse: ...

    @abstractmethod
    def is_available(self) -> bool: ...
```

**If the provider speaks the OpenAI chat-completions wire format** (most local
inference servers do — LM Studio, Ollama, vLLM's OpenAI-compatible mode, llama.cpp's
server, etc.), you don't write a new HTTP client at all. Subclass
`OpenAICompatibleProvider` in `globwarden/llm/openai_compatible.py` and set the two
things that differ:

```python
# globwarden/llm/my_new_provider.py
from globwarden.llm.openai_compatible import OpenAICompatibleProvider


class MyNewProvider(OpenAICompatibleProvider):
    name = "my_new_provider"
    default_base_url = "http://localhost:8000/v1"
    default_model = "my-default-model"
```

That's the whole implementation — five lines, as promised. `is_available()`,
request construction, `json_mode` handling, and response parsing are all inherited.

**If the provider has its own wire format** (a new cloud vendor with a bespoke REST
API, for example), implement `complete()` and `is_available()` directly against
`requests`, following `openai_provider.py` or `anthropic_provider.py` as a template.
Keep the same discipline those files use: raise `globwarden.llm.errors.LLMError`
subclasses (`AuthenticationError`, `RateLimitError`, `ProviderAPIError`,
`ProviderConnectionError`) rather than leaking raw `requests` exceptions, so the CLI
can print a clean, consistent error instead of a traceback.

Then:

1. Register the provider in `globwarden/llm/registry.py` so it resolves by name
   from the registry.
2. **Add the provider's name to the `ProviderChoice` enum in `globwarden/cli.py`.**
   This step is easy to miss and the CLI will not tell you clearly that you
   missed it: `--provider` is validated by Typer against `ProviderChoice`
   *before* the registry is ever consulted, so a provider that's registered but
   not added here is unreachable — `globwarden scan demo --provider
   my_new_provider` fails with a generic "not one of ..." error, and
   `globwarden providers` will list it as if it works, which is actively
   misleading until this step is done. Do this before you consider the
   provider finished.
3. Add a test file under `tests/llm/` mirroring an existing provider's tests —
   mocked HTTP, asserting request shape and response parsing.
4. Add a short section to [`docs/providers.md`](docs/providers.md) (env vars / local
   setup, whether it supports vision).

## Adding a new rule language

Rule generation lives in `globwarden/engine/generate.py`, driven by templates in
`globwarden/engine/prompts.py` and the `RuleType` enum in `globwarden/models.py`.

1. Add the new format to the `RuleType` enum in `globwarden/models.py`.
2. Add a generation prompt/template for it in `globwarden/engine/prompts.py` —
   follow the existing rule-type prompts for tone and structure (ask for the rule
   plus a short plain-language explanation of what it catches).
3. Add a syntactic validator for the new format in `generate.py` (e.g. "does this
   compile as regex," "does this parse as YAML," "does this look like well-formed
   KQL"). Every `GeneratedRule` must come back with `valid` set honestly — never
   silently drop a rule that failed validation; set `valid=False` and fill in
   `validation_note` instead so the user can see and fix it.
4. Wire the new type into `render.py` so it gets its own labeled panel in the
   terminal output.
5. Add tests under `tests/engine/` with a handful of representative findings and
   assert the generated rule is well-formed.
6. Document the new language's target SIEM/platform in the README's "Supported Rule
   Languages" section and in this file's own docs if there's provider-specific
   nuance worth calling out.

## Code style

- Formatted and linted with [ruff](https://docs.astral.sh/ruff/) (`ruff check .` /
  `ruff format .`). CI runs both; please run them locally before opening a PR.
- Type hints throughout — the codebase targets Python 3.10+ and uses modern syntax
  (`list[bytes]`, `X | None`) rather than `typing.List`/`typing.Optional`.
- Dataclasses for shared shapes, not ad-hoc dicts — see `globwarden/models.py` and
  don't redefine those shapes elsewhere.
- Prefer small, focused modules over one large file; this is already the pattern
  across `llm/`, `ingest/`, and `engine/` — follow it for new code.
- Docstrings on public functions/classes, especially anything another builder's code
  will call across a module boundary.
- No bare `except Exception` swallowing errors silently — catch specific exceptions
  and either handle them meaningfully or wrap them in one of this project's own
  exception types.

## Pull request process

1. Fork the repo and create a feature branch off `main`.
2. Keep PRs scoped to one thing (one provider, one rule language, one fix) — easier
   to review, easier to revert if something's wrong.
3. Make sure `pytest` and `ruff check .` pass locally; CI will run both plus a
   package build on every PR.
4. Include or update tests for any behavior change. A PR that adds a provider or
   rule language without tests will be asked for them before merge.
5. Update relevant docs (`README.md`, `docs/providers.md`, `docs/architecture.md`) in
   the same PR if your change affects what's documented there.
6. Describe *why* in the PR description, not just what — especially for anything
   touching prompt templates or validation logic, where the reasoning matters more
   than the diff.
7. One maintainer approval is required before merge. Be patient; this is a
   part-time-maintained project.

## Reporting issues

Bug reports and feature requests are welcome via GitHub Issues. For bug reports,
please include: the command you ran, the provider/model, and (with any API keys or
sensitive report content redacted) enough of the input/output to reproduce. Do not
paste real, non-defanged malicious content into a public issue.

## A note on scope

GlobWarden is a detection-engineering *assistant*, not a certified rule-translation
engine — see the README's "how it's different" section. PRs that push the tool
toward "silently trust the LLM's output" (e.g. removing validation, auto-suppressing
low-confidence findings without surfacing them) are likely to be declined; PRs that
make the human-review step easier, faster, or clearer are very welcome.
