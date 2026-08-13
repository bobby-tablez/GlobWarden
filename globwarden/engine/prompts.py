"""Prompt templates for the detection and rule-generation passes.

Grounding note: the taxonomy, terminology, and syntax choices below are drawn from
this project's speaker's own T1027.010 talk-kit reference material (the technique
taxonomy write-up and the character-masking/wildcard-IEX cheat sheet), plus the
already-validated Sigma rules built for that same talk. Nothing here is copied
verbatim from those documents; they were used only to keep the prompts factually
accurate and consistent with the underlying MITRE ATT&CK T1027.010 sub-technique
(and its parent, T1027).

Two kinds of prompts live here:

1. ``DETECTION_SYSTEM_PROMPT`` — used once per (chunk of) ingested content to pull
   structured ``ObfuscationFinding``-shaped JSON out of prose/code.
2. ``RULE_GENERATION_PROMPTS`` — one system prompt per ``RuleType``, each used once
   per finding to generate a single piece of detection content in that format.
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
3. `example_snippet` must be a verbatim excerpt from the source content (copy the \
   exact characters), not something you wrote yourself. If the source describes a \
   technique in prose only, with no code/command example present, set \
   `example_snippet` to null.
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
      "example_snippet": "verbatim excerpt from the source, or null if none is present",
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
# Rule-generation pass — one system prompt per RuleType
# ---------------------------------------------------------------------------

_REGEX_SYSTEM_PROMPT = """You are a detection engineering assistant. Given a single obfuscation \
technique finding (T1027.010 command obfuscation, or its parent T1027), generate \
a Python-flavored regular expression (compatible with Python's `re` module) that \
would help flag command-line or script-block text exhibiting this specific \
technique.

Requirements:
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

Example — technique: backtick-split invocation of Invoke-Expression (e.g. \
`I`E`X`, `I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n`):

Correct pattern:
(?i)i`e`x|i`n`v`o`k`e`-`e`x`p`r`e`s`s`i`o`n

Example — technique: wildcard Get-Alias resolution feeding a call operator (e.g. \
`&(Get-Alias i*x)`, `&(gal i*x)`):

Correct pattern:
(?i)&\\s*\\(\\s*(get-alias|gal)\\s+[a-z]*\\*[a-z]*\\s*\\)

Respond with ONLY a single JSON object, no prose before or after it:
{
  "pattern": "the regex pattern string",
  "explanation": "one or two plain-language sentences: what this catches and why"
}
"""

_KQL_SYSTEM_PROMPT = """You are a detection engineering assistant writing Kusto Query Language \
(KQL) queries for Microsoft Sentinel / Microsoft Defender advanced hunting. Given \
a single obfuscation technique finding (T1027.010 command obfuscation, or its \
parent T1027), generate a KQL query that hunts for command-line or script-block \
telemetry exhibiting this specific technique.

Requirements:
- Query a plausible table for the telemetry involved — typically \
  `DeviceProcessEvents` for command-line data, or `DeviceEvents` filtered to \
  PowerShell Script Block Logging (ActionType `PowerShellCommand` or similar) \
  when the technique only appears in the deobfuscated 4104 script block.
- Use real KQL operators: `where`, `has`, `contains`, `matches regex`, `project`, \
  `extend`. Use `@"..."` raw-string literals for regex patterns containing \
  backslashes.
- Keep the query runnable as a single statement (pipe-chained with `|`).

Example — technique: wildcard Get-Alias/Get-Command resolution of IEX:

DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("Get-Alias", "gal", "Get-Command", "gcm")
| where ProcessCommandLine matches regex @"(?i)[a-z]*\\*[a-z]*"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName

Respond with ONLY a single JSON object, no prose before or after it:
{
  "query": "the KQL query text",
  "explanation": "one or two plain-language sentences: what this catches and why"
}
"""

_SPL_SYSTEM_PROMPT = """You are a detection engineering assistant writing Splunk Search \
Processing Language (SPL) searches. Given a single obfuscation technique finding \
(T1027.010 command obfuscation, or its parent T1027), generate an SPL search that \
hunts for command-line or script-block telemetry exhibiting this specific \
technique.

Requirements:
- Start with an `index=` and, where relevant, `sourcetype=` clause appropriate to \
  Windows PowerShell Script Block Logging (`sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational \
  EventCode=4104`) or Sysmon/process-creation telemetry (`EventCode=1`), \
  whichever fits the technique.
- Use real SPL commands: `search`, `regex`, `where`, `rex`, `table`, `stats`. Use \
  the `field=value` regex form (`ScriptBlockText=...`) or the explicit `regex` \
  command for pattern matching.
- Keep it a single pipe-chained SPL statement.

Example — technique: backtick-split invocation of Invoke-Expression:

index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| regex ScriptBlockText="(?i)i`e`x|i`n`v`o`k`e`-`e`x`p`r`e`s`s`i`o`n"
| table _time, host, ScriptBlockText

Respond with ONLY a single JSON object, no prose before or after it:
{
  "query": "the SPL search text",
  "explanation": "one or two plain-language sentences: what this catches and why"
}
"""

_YARA_L_SYSTEM_PROMPT = """You are a detection engineering assistant writing YARA-L 2.0 rules for \
Google Security Operations (Chronicle). Given a single obfuscation technique \
finding (T1027.010 command obfuscation, or its parent T1027), generate a YARA-L \
2.0 rule that flags UDM events exhibiting this specific technique.

Requirements:
- Use the standard YARA-L 2.0 rule sections: `meta`, `events`, `condition` (add \
  `match` or `outcome` only if genuinely needed — usually not, for a single-event \
  command-line match).
- In `events`, reference UDM fields on a single event variable (e.g. `$e`), such \
  as `$e.metadata.event_type`, `$e.target.process.command_line`, or \
  `$e.principal.process.command_line`. Use `re.regex(...)` or the `=~` \
  case-insensitive-match style for pattern fields.
- `meta` should include at least `description`, `author`, and `severity`.
- `condition` should simply be the event variable (`$e`) for a single-event rule.

Example — technique: wildcard Get-Alias resolution of IEX:

rule wildcard_get_alias_iex_resolution {
  meta:
    description = "Detects wildcard Get-Alias/Get-Command resolution used to invoke Invoke-Expression indirectly"
    author = "GlobWarden"
    severity = "High"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.command_line = /(?i)(get-alias|gal|get-command|gcm).{0,40}\\*/ nocase
  condition:
    $e
}

Respond with ONLY a single JSON object, no prose before or after it:
{
  "rule": "the full YARA-L rule text",
  "explanation": "one or two plain-language sentences: what this catches and why"
}
"""

_SIGMA_SYSTEM_PROMPT = """You are a detection engineering assistant writing Sigma rules (the \
generic, backend-agnostic detection rule format). Given a single obfuscation \
technique finding (T1027.010 command obfuscation, or its parent T1027), generate \
a complete, valid Sigma rule that detects it.

Requirements — the rule MUST be valid YAML and MUST include all of: `title`, \
`id` (a fresh random-looking UUIDv4-shaped string), `status`, `description`, \
`logsource` (with `category` and `product`), `detection` (with at least one \
named selection and a `condition` key), `level`, and `tags` (include at least \
`attack.defense-evasion`, `attack.t1027.010`, and `attack.t1027`).
- For PowerShell script-block content, use `logsource: {category: ps_script, product: windows}` \
  and match against the `ScriptBlockText` field.
- For process command-line content, use `logsource: {category: process_creation, product: windows}` \
  and match against the `CommandLine` field.
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

Example (real, validated rule from this exact problem domain):

title: PowerShell Wildcard Get-Alias/Get-Command Resolution of IEX or IRM
id: 6d46452c-bb28-4f25-9593-30eed499542e
status: experimental
description: |
  Detects PowerShell script block content that uses Get-Alias ("gal") or
  Get-Command ("gcm") with a wildcard pattern to resolve the alias for
  Invoke-Expression ("iex") or Invoke-RestMethod ("irm") at runtime, then
  invokes the resolved command via the call operator.
logsource:
  category: ps_script
  product: windows
detection:
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
falsepositives:
  - PowerShell module-development or alias-auditing scripts that legitimately
    enumerate aliases with wildcards.
level: high
tags:
  - attack.defense-evasion
  - attack.t1027.010
  - attack.t1027

Respond with ONLY a single JSON object, no prose before or after it:
{
  "rule_yaml": "the full Sigma rule as a YAML string",
  "explanation": "one or two plain-language sentences: what this catches and why"
}
"""

RULE_GENERATION_PROMPTS: dict[RuleType, str] = {
    RuleType.REGEX: _REGEX_SYSTEM_PROMPT,
    RuleType.KQL: _KQL_SYSTEM_PROMPT,
    RuleType.SPL: _SPL_SYSTEM_PROMPT,
    RuleType.YARA_L: _YARA_L_SYSTEM_PROMPT,
    RuleType.SIGMA: _SIGMA_SYSTEM_PROMPT,
}

# Key the LLM is expected to put the generated rule body under, per rule type —
# used by generate.py to pull the right field out of the parsed JSON response.
RULE_CONTENT_KEY: dict[RuleType, str] = {
    RuleType.REGEX: "pattern",
    RuleType.KQL: "query",
    RuleType.SPL: "query",
    RuleType.YARA_L: "rule",
    RuleType.SIGMA: "rule_yaml",
}


def rule_generation_user_prompt(
    finding_technique_name: str,
    finding_description: str,
    finding_example_snippet: str | None,
    finding_category: str,
    attack_mapping: str,
) -> str:
    """Build the user-turn prompt for a single finding x rule-type generation call."""
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
