"""
providers/base.py — Abstract base class for all LLM providers
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMResponse:
    content: str
    model: str
    provider: str
    input_tokens: int = 0
    output_tokens: int = 0


class BaseLLMProvider(ABC):
    """Abstract interface every LLM provider must implement."""

    name: str = "base"

    @abstractmethod
    def chat(
        self,
        messages: list[dict],
        *,
        json_mode: bool = False,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> LLMResponse:
        """Send a chat completion request and return a structured response."""
        ...

    def chat_json(self, messages: list[dict], **kwargs) -> LLMResponse:
        """Convenience wrapper that enforces JSON output mode."""
        return self.chat(messages, json_mode=True, **kwargs)
