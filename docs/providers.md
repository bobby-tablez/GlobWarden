# Provider setup

GlobWarden supports five LLM backends behind one interface (`globwarden.llm.base.LLMProvider`):
three cloud APIs and two local inference servers. Pick whichever fits your
constraints — nothing else in the tool changes based on which one you use, aside from
vision support (see the table at the end).

Select a provider per run with `--provider`:

```bash
globwarden scan report.pdf --provider anthropic
```

If you omit `--provider`, GlobWarden auto-detects the first available real
provider (checked in registry order — see `globwarden providers` below) rather
than reading any environment variable, so the reliable way to pin a specific
provider for every run is the `--provider` flag itself (alias it in your shell
if you want a shorthand).

Check what's available (keys present / local servers reachable) without spending a
request:

```bash
globwarden providers
```

---

## OpenAI (cloud)

1. Create an API key at <https://platform.openai.com/api-keys>.
2. Export it:

   ```bash
   export OPENAI_API_KEY="sk-..."
   ```

3. Run:

   ```bash
   globwarden scan report.pdf --provider openai
   ```

`--model` is optional; it defaults to `gpt-4o-mini`. Any current OpenAI
chat-completions-compatible model works — use a vision-capable model (the `gpt-4o`
family) if you're scanning a screenshot or image-only source.

**Env vars:** `OPENAI_API_KEY` (required).

---

## Anthropic (cloud)

1. Create an API key at <https://console.anthropic.com/settings/keys>.
2. Export it:

   ```bash
   export ANTHROPIC_API_KEY="sk-ant-..."
   ```

3. Run:

   ```bash
   globwarden scan report.pdf --provider anthropic
   ```

`--model` defaults to `claude-opus-5` — deliberately the top-tier model, since
cost/quality tradeoffs are the operator's call rather than the tool's. Use a cheaper
model with `--model claude-haiku-4-5` or by setting `ANTHROPIC_MODEL`.

**Env vars:** `ANTHROPIC_API_KEY` (required). `ANTHROPIC_MODEL` (optional, sets the
default model without a `--model` flag on every run).

Vision-capable Claude models can take a PDF or screenshot directly; GlobWarden will
pass extracted images through when the source is an image or an image-heavy PDF.

---

## Google Gemini (cloud)

1. Create an API key at <https://aistudio.google.com/app/apikey>.
2. Export it:

   ```bash
   export GOOGLE_API_KEY="..."
   ```

3. Run:

   ```bash
   globwarden scan report.pdf --provider gemini
   ```

`--model` defaults to `gemini-2.0-flash`; override with `--model` or `GEMINI_MODEL`
for a different Gemini model.

**Env vars:** `GOOGLE_API_KEY` (primary — the convention most Google AI tooling
uses). `GEMINI_API_KEY` is accepted as a fallback if that's what's already set in
your environment. `GEMINI_MODEL` (optional, default model override).

---

## Ollama (local)

Fully offline once the model is pulled — nothing leaves your machine. This is the
path for orgs that can't send threat-intel content to a cloud API.

1. Install Ollama:

   ```bash
   # macOS
   brew install ollama

   # Linux
   curl -fsSL https://ollama.com/install.sh | sh

   # Windows: download the installer from https://ollama.com/download
   ```

2. Start the server (if it isn't already running as a service):

   ```bash
   ollama serve
   ```

3. Pull a model. GlobWarden's default is `llama3.2`, which Ollama serves out of the
   box for text; for vision input (image/screenshot sources) pull a vision-tagged
   model instead:

   ```bash
   ollama pull llama3.2          # default, text-only
   ollama pull llama3.2-vision   # if you need vision support
   ```

4. Run GlobWarden against it:

   ```bash
   globwarden scan report.pdf --provider ollama
   # or, to use a different pulled model:
   globwarden scan report.pdf --provider ollama --model llama3.2-vision
   ```

**Env vars:** none required — `llama3.2` is used by default. `OLLAMA_BASE_URL`
optional if your server isn't on the default `http://localhost:11434/v1` (e.g. it's
running on another machine on your network). `OLLAMA_MODEL` optional default-model
override. `OLLAMA_API_KEY` optional — Ollama doesn't require one, but it's honored
if you've put an auth proxy in front of your server.

Local models are generally weaker than frontier cloud models at this task — expect
lower-confidence findings and treat analyst review as even more load-bearing than
usual. That tradeoff is the point: fully offline beats no coverage at all for a
report that can't leave your network.

---

## LM Studio (local)

Same idea as Ollama, with a GUI-first workflow if you'd rather manage models that way.

1. Download and install LM Studio from <https://lmstudio.ai>.
2. In the app, use the search tab to download a model (any GGUF-format chat model;
   pick a vision-tagged model if you need image support).
3. Start the local server: **Developer tab → Start Server** (defaults to port
   `1234`), or from the command line if you have the `lms` CLI installed:

   ```bash
   lms server start
   ```

4. Run GlobWarden against it:

   ```bash
   globwarden scan report.pdf --provider lmstudio
   ```

   LM Studio serves whichever model is currently loaded, and GlobWarden
   auto-detects it via the server's `/v1/models` endpoint — no `--model` flag
   needed unless you want to target a specific one explicitly:

   ```bash
   globwarden scan report.pdf --provider lmstudio --model <model-name-shown-in-lm-studio>
   ```

**Env vars:** none required. `LMSTUDIO_BASE_URL` optional if your server isn't on the
default `http://localhost:1234/v1`. `LMSTUDIO_MODEL` optional default-model
override. `LMSTUDIO_API_KEY` optional — LM Studio doesn't require one by default.

---

## Adding another OpenAI-compatible provider

Ollama and LM Studio both work by subclassing a shared
`OpenAICompatibleProvider` base — any other local (or cloud) server that speaks the
OpenAI chat-completions wire format can be added the same way, in about five lines.
See the "Adding a new LLM provider" section of
[`CONTRIBUTING.md`](../CONTRIBUTING.md).

---

## At a glance

| Provider       | Type  | Vision support               | Requires                              |
|-----------------|-------|-------------------------------|----------------------------------------|
| OpenAI          | Cloud | Yes (`gpt-4o` family)         | `OPENAI_API_KEY`                       |
| Anthropic       | Cloud | Yes (Claude 3+ / Sonnet 4 family) | `ANTHROPIC_API_KEY`                |
| Google Gemini   | Cloud | Yes (Gemini 2.0+)             | `GOOGLE_API_KEY` (or `GEMINI_API_KEY`) |
| Ollama          | Local | Model-dependent (e.g. `llama3.2-vision`) | Local server (`ollama serve`) |
| LM Studio       | Local | Model-dependent               | Local server (Developer tab / `lms`)   |
