# CLI reference

GlobWarden has two commands: `scan` (the main pipeline) and `providers` (a status
check). Both also inherit `--version`/`--help` from the root `globwarden` command.

```bash
globwarden --version          # show the installed version and exit
globwarden providers          # list every known provider and whether it's available
globwarden scan <source>      # run the pipeline
```

## `globwarden scan <source>`

`source` is a URL, a local PDF/text/code/image path, or the literal `demo` for a
built-in, network-free demo source.

| Flag | Default | What it does |
|---|---|---|
| `--provider` | auto-detect | LLM provider: `openai`, `anthropic`, `gemini`, `ollama`, `lmstudio`, or `fake` (built-in, network-free stub for demos/testing). Omit to auto-detect the first available real provider. |
| `--model` | provider default | Model name/tag to use with the chosen provider. |
| `--rules` | `regex,kql,spl,yara-l,sigma` | Comma-separated rule types to generate. |
| `--output` | `terminal` | How to render results: `terminal` (colorized panels), `json`, or `markdown` (both print clean, scriptable output with no rich styling). |
| `--output-file <path>` | stdout | Write results to this file instead of stdout, in whichever `--output` format was chosen. `terminal` writes the same colorized panel layout shown on screen as plain text (box-drawing preserved, no ANSI codes) at a fixed, portable width — for a scan too long for terminal scrollback. |
| `--api-key` | provider's env var | Override the provider's default API key env var (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc. — see [`providers.md`](providers.md)). |
| `--base-url` | provider default | Override the provider's base URL — mainly for Ollama/LM Studio or a self-hosted OpenAI-compatible endpoint. |
| `--user-agent` | a standard browser UA | Override the User-Agent sent for URL fetches. Some sites — security/threat-intel blogs especially — block requests that self-identify as a bot. Env var: `GLOBWARDEN_USER_AGENT`. |
| `--dry-run` | off | Ingest + detect only; skip rule generation. |
| `-v`, `--verbose`, `--debug` | off | Show full tracebacks and extra pipeline detail on failure. |
| `--help` | — | Show this message and exit. |

### Examples

```bash
# network-free demo, no API key needed
globwarden scan demo --provider fake

# a real report against a real provider
globwarden scan https://example.com/report --provider openai

# narrow the rule types, pipe clean JSON to a file via shell redirection
globwarden scan ./report.pdf --rules regex,sigma --output json > findings.json

# same terminal-style layout as the live view, saved directly to a file
globwarden scan ./report.pdf --output-file report.txt

# markdown saved directly to a file
globwarden scan ./report.pdf --output markdown --output-file report.md
```

## `globwarden providers`

No options beyond `--help`. Prints every registered provider, whether it's a
cloud or local backend, and whether it's currently available (API key present /
local server reachable) — without spending an actual request.

---

This reference is checked against the CLI's real `--help` output and against
[`../README.md`](../README.md)'s own copy of this table by the test suite (see
`tests/test_cli.py`), so all three — `--help`, this file, and the README — stay
in sync automatically as flags are added.
