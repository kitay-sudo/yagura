"""Build the right AIClient subclass from config."""

from __future__ import annotations

from yagura.ai.anthropic_client import AnthropicClient
from yagura.ai.base import AIClient
from yagura.ai.gemini_client import GeminiClient
from yagura.ai.openai_client import OpenAIClient


def build_client(provider: str, api_key: str, model: str = "") -> AIClient | None:
    if not provider or provider == "none" or not api_key:
        return None
    provider = provider.lower()
    if provider in ("claude", "anthropic"):
        return AnthropicClient(api_key=api_key, model=model)
    if provider in ("openai", "chatgpt", "gpt"):
        return OpenAIClient(api_key=api_key, model=model)
    if provider in ("gemini", "google"):
        return GeminiClient(api_key=api_key, model=model)
    return None
