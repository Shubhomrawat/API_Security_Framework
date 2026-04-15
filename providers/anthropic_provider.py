"""
providers/anthropic_provider.py — Anthropic Claude provider implementation
"""
from __future__ import annotations
import os
import anthropic
from providers.base import BaseLLMProvider, LLMResponse


class AnthropicProvider(BaseLLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.client = anthropic.Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
        self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-opus-4-5")

    def chat(
        self,
        messages: list[dict],
        *,
        json_mode: bool = False,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> LLMResponse:
        # Anthropic uses system messages separately
        system = ""
        filtered = []
        for m in messages:
            if m["role"] == "system":
                system = m["content"]
            else:
                filtered.append(m)

        if json_mode and system:
            system += "\n\nReturn ONLY valid JSON. No markdown, no explanation."
        elif json_mode:
            system = "Return ONLY valid JSON. No markdown, no explanation."

        kwargs: dict = dict(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=filtered,
        )
        if system:
            kwargs["system"] = system

        resp = self.client.messages.create(**kwargs)
        content = ""
        for block in resp.content:
            if hasattr(block, "text"):
                content = block.text
                break

        return LLMResponse(
            content=content,
            model=self.model,
            provider=self.name,
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
        )
