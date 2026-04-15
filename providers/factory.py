"""
providers/factory.py — Resolves the configured LLM provider at runtime
"""
from __future__ import annotations
import os
from providers.base import BaseLLMProvider


def get_provider(name: str | None = None) -> BaseLLMProvider:
    """
    Return an LLM provider instance.

    Resolution order:
      1. Explicit `name` argument
      2. LLM_PROVIDER env var  (openai | anthropic)
      3. Infer from which API key is set
      4. Default → OpenAI
    """
    provider_name = (name or os.getenv("LLM_PROVIDER", "")).lower().strip()

    if not provider_name:
        if os.getenv("ANTHROPIC_API_KEY"):
            provider_name = "anthropic"
        else:
            provider_name = "openai"

    if provider_name == "anthropic":
        from providers.anthropic_provider import AnthropicProvider
        return AnthropicProvider()

    if provider_name == "openai":
        from providers.openai_provider import OpenAIProvider
        return OpenAIProvider()

    raise ValueError(
        f"Unknown LLM provider '{provider_name}'. "
        "Valid options: openai, anthropic"
    )


__all__ = ["get_provider", "BaseLLMProvider"]
