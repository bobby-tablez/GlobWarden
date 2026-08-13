"""Detection and rule-generation engine: the heart of GlobWarden.

`detect.py` turns ingested content into structured `ObfuscationFinding`s via an
LLM; `generate.py` turns those findings into validated `GeneratedRule`s in five
formats (regex, KQL, SPL, YARA-L, Sigma); `prompts.py` holds the system prompts
both of those modules send to the provider.
"""
