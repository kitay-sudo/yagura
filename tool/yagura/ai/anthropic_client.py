"""Anthropic Claude provider."""

from __future__ import annotations

import json

import requests

from yagura.ai.base import AIClient

API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class AnthropicClient(AIClient):
    name = "claude"
    default_model = "claude-sonnet-4-6"

    def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = requests.post(API_URL, headers=headers, data=json.dumps(body), timeout=60)
        resp.raise_for_status()
        data = resp.json()
        parts = data.get("content", [])
        text_parts = [p.get("text", "") for p in parts if p.get("type") == "text"]
        return "".join(text_parts).strip()
