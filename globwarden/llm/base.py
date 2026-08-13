"""The LLM provider interface all backends implement.

See `_briefs/00-ARCHITECTURE.md` for the authoritative contract this file
implements. Concrete providers (openai, anthropic, gemini, ollama, lmstudio)
live alongside this module but are owned by a different builder.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMResponse:
    text: str
    model: str
    provider: str
    raw: dict | None = None  # original provider response, for debugging


class LLMProvider(ABC):
    name: str  # e.g. "openai", "anthropic", "gemini", "ollama", "lmstudio"

    @abstractmethod
    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        images: list[bytes] | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Single-turn completion. json_mode hints the provider to return valid JSON
        where the provider supports it natively; callers must still validate/parse
        defensively either way, since not all providers/models honor this reliably."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Cheap check (e.g. local server reachable, API key present) — used by the
        CLI's --list-providers / preflight check. Must not raise; return False on
        any failure."""
        ...
