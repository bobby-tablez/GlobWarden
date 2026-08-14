"""Prompt templates for the detection and rule-generation passes.

Grounding note: the taxonomy, terminology, and syntax choices below are drawn from
this project's own T1027.010 reference research (technique taxonomy, character-
masking/wildcard-IEX examples, and validated Sigma rules built during that
research). Nothing here is copied verbatim from those materials; they were used
only to keep the prompts factually accurate and consistent with the underlying
MITRE ATT&CK T1027.010 sub-technique (and its parent, T1027).

Two kinds of prompts live here:

1. ``DETECTION_SYSTEM_PROMPT`` — used once per (chunk of) ingested content to pull
   structured ``ObfuscationFinding``-shaped JSON out of prose/code.
2. ``build_generation_system_prompt(rule_types)`` — one combined prompt per call,
   covering every requested ``RuleType`` in a single response. GlobWarden's scope is
   deliberately narrow: for every format, the model is asked for the minimal
   matching expression (a regex line formatted for that query language, or a bare
   Sigma ``detection:`` block) rather than a complete standalone rule with title/
   metadata/logsource wrapping -- the analyst is expected to drop the result into
   their own existing rule structure, not receive a finished rule file. This also
   keeps responses small: one call per finding covers every requested format
   instead of one call per (finding, rule_type) pair.

   A format that fails validation gets retried with a narrow, single-format
   prompt -- ``build_generation_system_prompt`` called with a one-element
   list -- rather than the combined prompt, so a retry costs one small,
   scoped call. See ``engine.generate`` for the (capped) retry loop.
"""

from globwarden.models import RuleType

# ---------------------------------------------------------------------------
# Detection pass
# ---------------------------------------------------------------------------

DETECTION_SYSTEM_PROMPT = """You are a detection engineering assistant specializing in MITRE ATT&CK \
T1027.010 (Obfuscated Files or Information: Command Obfuscation) and its parent \
technique T1027. Your job is to read threat-intel content supplied by the user \
(a report excerpt, blog post, code sample, or screenshot) and extract every \
concrete command-obfuscation technique that is actually described or shown in \
that content.

T1027.010 covers obfuscation of the command line / script text itself (not file- \
or payload-level obfuscation like packing or steganography). Concretely, look for \
things like:
- Character masking: backtick splitting, case randomization, Unicode homoglyphs, \
  string reordering/reversal of a command or cmdlet name.
- Wildcard / glob-based resolution: using Get-Alias, Get-Command, Get-Item, or \
  similar with a wildcard argument to resolve a cmdlet or binary path at runtime \
  instead of naming it literally, then invoking the resolved object (e.g. via the \
  `&` call operator).
- String concatenation / splitting: building a sensitive token out of short \
  string literals joined with `+`, `-join`, `-f`, or similar, so the literal \
  substring never appears contiguously.
- Environment-variable indirection: building a command or path out of \
  environment variables (`$env:`, `%VAR%`, `[Environment]::GetEnvironmentVariable`) \
  so the literal target never appears verbatim.
- Encoded download/execution cradles: `-EncodedCommand`, base64 blobs, or \
  download-and-execute chains (`IWR`/`Invoke-WebRequest`, `.DownloadString`, \
  `irm`/`Invoke-RestMethod`) that fetch and run remote content.
- Other syntactic tricks that defeat string/regex pattern matching while \
  preserving behavior (escape characters, splatting to hide parameters, etc.) — \
  use the "other" category for anything real but that doesn't cleanly fit the \
  categories above.

CRITICAL RULES:
1. Only report techniques that are actually present in, or explicitly described \
   by, the supplied content. Do NOT invent generic obfuscation trivia, and do NOT \
   report a technique just because it is common in the wild if the source text \
   doesn't actually mention or show it.
2. If the content contains no obfuscation techniques at all, return an empty \
   "findings" array. An empty result is a correct result, not a failure.
3. `example_snippet_b64` must be a verbatim excerpt from the source content (copy \
   the exact characters), not something you wrote yourself, ENCODED AS STANDARD \
   BASE64 (no line breaks in the encoded output). If the source describes a \
   technique in prose only, with no code/command example present, set \
   `example_snippet_b64` to null. Obfuscated command examples routinely contain \
   double-quote characters, backslashes, and other characters that break a plain \
   JSON string if they aren't escaped exactly right — base64-encoding the raw \
   excerpt sidesteps that entirely, since base64 output never contains a quote, \
   backslash, or line break. Do the actual base64 encoding yourself on the exact \
   characters you're copying; do not paraphrase or clean up the source text first.
4. `confidence` is your own self-assessed confidence (0.0-1.0) that this is a \
   genuine T1027.010-style obfuscation technique correctly identified from the \
   source — not a measure of how dangerous it is.
5. `category` MUST be exactly one of: "character_masking", "wildcard_resolution", \
   "string_concatenation", "env_var_indirection", "encoded_cradle", "other". Do \
   not invent new category strings.
6. `attack_mapping` should normally be "T1027.010 (parent: T1027)" unless the \
   content clearly points at a different, specific sub-technique — in that case \
   use your best judgment but keep the format "T<id> (parent: T<parent-id>)".
7. Assign each finding a short stable id: "f1", "f2", "f3", ... in the order you \
   report them.

Respond with ONLY a single JSON object, no prose before or after it, matching \
exactly this schema:

{
  "findings": [
    {
      "id": "f1",
      "category": "wildcard_resolution",
      "technique_name": "short human-readable name, e.g. 'Wildcard Get-Alias to Invoke-Expression'",
      "description": "1-3 sentences, in your own words, explaining what this technique does and how it evades naive detection",
      "example_snippet_b64": "base64-encoded verbatim excerpt from the source, or null if none is present",
      "confidence": 0.9,
      "attack_mapping": "T1027.010 (parent: T1027)",
      "source_ref": "page number, URL fragment, or line range if determinable, else null"
    }
  ]
}

If nothing relevant is present, respond with: {"findings": []}
"""

DETECTION_USER_PROMPT_TEMPLATE = """Analyze the following content and extract every command-obfuscation \
technique it actually describes or shows. Source identifier: {source}
{chunk_note}
--- CONTENT START ---
{content}
--- CONTENT END ---

Respond with only the JSON object described in the system prompt."""


# ---------------------------------------------------------------------------
# Rule-generation pass
# ---------------------------------------------------------------------------
#
# GlobWarden generates a minimal *matching expression* per format, not a
# complete rule -- see module docstring. Every format below is described as a
# self-contained block of instructions so `build_generation_system_prompt` can
# assemble a single combined prompt covering only the formats actually
# requested for a given scan.

_GENERATION_HEADER = """You are a detection engineering assistant. Given a single obfuscation \
technique finding (T1027.010 command obfuscation, or its parent T1027), generate \
a matching expression in each of the format(s) listed below.

For every format, produce ONLY the minimal matching expression needed to detect \
this specific technique -- never a complete standalone rule with its own title, \
id, metadata, logsource, or severity wrapping. The analyst already has their own \
rule structure and just needs the matching logic to drop into it.
"""

_REGEX_BLOCK = """### regex
A Python-flavored regular expression (compatible with Python's `re` module) that \
would help flag command-line or script-block text exhibiting this specific \
technique.
- The pattern must be a single valid Python `re` pattern string — it will be \
  passed directly to `re.compile()`. Do not wrap it in slashes, quotes, or a \
  regex-literal syntax from another language.
- Prefer `(?i)` inline case-insensitivity where case doesn't matter, rather than \
  relying on the caller to pass re.IGNORECASE.
- Escape literal regex metacharacters that appear in the technique's own syntax \
  (e.g. a literal `*`, `$`, `(`, `)` in the obfuscated command must be escaped as \
  `\\*`, `\\$`, `\\(`, `\\)`).
- Keep it narrowly targeted at the technique described in the finding — don't \
  write an overly broad pattern that would flag unrelated, benign PowerShell.
- Remember this pattern is itself a JSON string value: every backslash you write \
  for the *regex's own* escaping (`\\s`, `\\*`, `\\(`, ...) needs a second backslash \
  on top of that for JSON (so `\\s` in the actual pattern is written as `\\\\s` in \
  your JSON response). Getting this wrong produces invalid JSON, not just a wrong \
  pattern.

Example — technique: backtick-split invocation of Invoke-Expression (e.g. \
`I`E`X`, `I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n`):

(?i)i`e`x|i`n`v`o`k`e`-`e`x`p`r`e`s`s`i`o`n

Return this under the "pattern" key, with a one-or-two-sentence "explanation" key \
alongside it."""

_KQL_BLOCK = """### kql
The single Kusto Query Language (KQL) filter clause -- not a full query -- that \
applies this technique's regex against the most plausible telemetry field: \
typically `ProcessCommandLine` (Microsoft Defender advanced hunting \
`DeviceProcessEvents`) for command-line data, or `ScriptBlockText` for PowerShell \
Script Block Logging (EventID 4104) content when the technique only appears in \
deobfuscated script-block text. Use the `matches regex @"..."` form with a \
raw-string literal.

Example — technique: wildcard Get-Alias/Get-Command resolution of IEX:

ProcessCommandLine matches regex @"(?i)[a-z]*\\*[a-z]*"

Return this under the "line" key, with a one-or-two-sentence "explanation" key \
alongside it."""

_SPL_BLOCK = """### spl
The single Splunk Search Processing Language (SPL) `regex` clause -- not a full \
search -- that applies this technique's regex against the most plausible field: \
typically `CommandLine` for process-creation telemetry (Sysmon EventCode 1), or \
`ScriptBlockText` for PowerShell Script Block Logging (EventCode 4104) content.

Example — technique: backtick-split invocation of Invoke-Expression:

regex ScriptBlockText="(?i)i`e`x|i`n`v`o`k`e`-`e`x`p`r`e`s`s`i`o`n"

Return this under the "line" key, with a one-or-two-sentence "explanation" key \
alongside it."""

_YARA_L_BLOCK = """### yara_l
The single YARA-L 2.0 (Google Security Operations / Chronicle) UDM field-match \
expression -- not a full rule -- that applies this technique's regex against the \
most plausible field on a single event variable `$e` (e.g. \
`$e.target.process.command_line` or `$e.principal.process.command_line`). Use \
`re.regex(...)` or the `/pattern/ nocase` match-literal style.

Example — technique: wildcard Get-Alias resolution of IEX:

$e.target.process.command_line = /(?i)(get-alias|gal|get-command|gcm).{0,40}\\*/ nocase

Return this under the "line" key, with a one-or-two-sentence "explanation" key \
alongside it."""

_SIGMA_BLOCK = """### sigma
Only the Sigma `detection:` block content for this technique -- the selection(s) \
plus the `condition` key -- as a YAML mapping. Do NOT include `title`, `id`, \
`status`, `description`, `logsource`, `level`, `tags`, or `falsepositives`; those \
belong to the analyst's own rule wrapper, not to you.
- For PowerShell script-block content, match against the `ScriptBlockText` field. \
  For process command-line content, match against the `CommandLine` field.
- Use standard Sigma modifiers: `|contains`, `|contains|all`, `|re`, `|startswith`, etc.
- `condition` must reference the selection name(s) you defined (e.g. `selection`, \
  or `1 of selection_*`).
- CRITICAL escaping rule: in a plain Sigma string value (e.g. under `|contains`), \
  an unescaped `*` or `?` is a Sigma WILDCARD operator (matches zero-or-more / \
  exactly-one arbitrary character), NOT a literal character. If the obfuscated \
  source text you are matching actually contains a literal `*` or `?` character \
  (which is common for this exact technique family — e.g. PowerShell wildcard \
  alias resolution like `i*x` appearing verbatim in a script), you MUST escape it \
  as `\\*` / `\\?` so Sigma matches the literal character instead of treating it \
  as its own wildcard syntax. Getting this backwards silently turns a narrow, \
  technique-specific literal match into an unrelated, much broader wildcard match \
  — a real mistake to avoid, not a stylistic preference.

Example — technique: wildcard Get-Alias/Get-Command resolution of IEX or IRM:

selection_alias_lookup:
  ScriptBlockText|contains:
    - '(gal '
    - '(gcm '
    - 'Get-Alias '
    - 'Get-Command '
selection_exec_alias_target:
  ScriptBlockText|contains:
    - 'i\\*x'
    - '\\?ex'
    - '\\?rm'
condition: selection_alias_lookup and selection_exec_alias_target

Return the YAML text (as a single string, not a nested object) under the \
"detection_yaml" key, with a one-or-two-sentence "explanation" key alongside it."""

_RULE_TYPE_BLOCKS: dict[RuleType, str] = {
    RuleType.REGEX: _REGEX_BLOCK,
    RuleType.KQL: _KQL_BLOCK,
    RuleType.SPL: _SPL_BLOCK,
    RuleType.YARA_L: _YARA_L_BLOCK,
    RuleType.SIGMA: _SIGMA_BLOCK,
}

# Top-level JSON key each format's section lives under in a combined response.
# Matches RuleType.value, which is already a safe, stable JSON-key spelling.
RULE_SECTION_KEY: dict[RuleType, str] = {rule_type: rule_type.value for rule_type in RuleType}

# Key each format's matching-expression content is nested under, within its
# own section -- used by generate.py to pull the right field out of the
# parsed response.
RULE_CONTENT_KEY: dict[RuleType, str] = {
    RuleType.REGEX: "pattern",
    RuleType.KQL: "line",
    RuleType.SPL: "line",
    RuleType.YARA_L: "line",
    RuleType.SIGMA: "detection_yaml",
}


def build_generation_system_prompt(rule_types: list[RuleType]) -> str:
    """Assemble one combined system prompt covering every format in `rule_types`.

    One call now covers every requested format for a finding, instead of one
    call per (finding, rule_type) pair -- the dominant lever for GlobWarden's
    call count and latency on a real scan.
    """
    blocks = "\n\n".join(_RULE_TYPE_BLOCKS[rt] for rt in rule_types)
    schema_lines = []
    for rt in rule_types:
        content_key = RULE_CONTENT_KEY[rt]
        schema_lines.append(f'  "{RULE_SECTION_KEY[rt]}": {{"{content_key}": "...", "explanation": "..."}}')
    schema = "{\n" + ",\n".join(schema_lines) + "\n}"

    return f"""{_GENERATION_HEADER}
{blocks}

Respond with ONLY a single JSON object, no prose before or after it, with exactly \
one top-level key per format requested above:

{schema}
"""


def rule_generation_user_prompt(
    finding_technique_name: str,
    finding_description: str,
    finding_example_snippet: str | None,
    finding_category: str,
    attack_mapping: str,
) -> str:
    """Build the user-turn prompt for a single finding's generation call."""
    snippet_block = (
        f"Example snippet from source:\n{finding_example_snippet}\n"
        if finding_example_snippet
        else "No example snippet was available from the source; base the rule on the description alone.\n"
    )
    return f"""Generate detection content for this obfuscation finding:

Technique: {finding_technique_name}
Category: {finding_category}
ATT&CK mapping: {attack_mapping}
Description: {finding_description}
{snippet_block}
Respond with only the JSON object described in the system prompt."""
