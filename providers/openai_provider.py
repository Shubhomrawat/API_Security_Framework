"""
providers/openai_provider.py — OpenAI GPT provider implementation
"""
from __future__ import annotations
import os
from openai import OpenAI
from providers.base import BaseLLMProvider, LLMResponse


class OpenAIProvider(BaseLLMProvider):
    name = "openai"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.client = OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o")

    def chat(
        self,
        messages: list[dict],
        *,
        json_mode: bool = False,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> LLMResponse:
        kwargs: dict = dict(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        resp = self.client.chat.completions.create(**kwargs)
        usage = resp.usage
        return LLMResponse(
            content=resp.choices[0].message.content or "",
            model=self.model,
            provider=self.name,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
        )
