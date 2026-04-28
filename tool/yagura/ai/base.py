"""Abstract AI provider interface."""

from __future__ import annotations

from abc import ABC, abstractmethod


class AIClient(ABC):
    name: str = "base"
    default_model: str = ""

    def __init__(self, api_key: str, model: str = ""):
        self.api_key = api_key
        self.model = model or self.default_model

    @abstractmethod
    def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        """Send prompt, return text. Raise on transport/auth errors."""

    def validate(self) -> bool:
        """Quick smoke-test the API key with a tiny request."""
        try:
            text = self.complete("ok?", max_tokens=8)
            return bool(text)
        except Exception:
            return False
