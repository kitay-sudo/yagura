"""OpenAI Chat Completions provider."""

from __future__ import annotations

import json

import requests

from yagura.ai.base import AIClient

API_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIClient(AIClient):
    name = "openai"
    default_model = "gpt-4o-mini"

    def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
        }
        resp = requests.post(API_URL, headers=headers, data=json.dumps(body), timeout=60)
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            return ""
        return (choices[0].get("message", {}).get("content") or "").strip()
