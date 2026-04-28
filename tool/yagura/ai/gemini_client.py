"""Google Gemini provider (REST, no SDK dependency)."""

from __future__ import annotations

import json

import requests

from yagura.ai.base import AIClient


class GeminiClient(AIClient):
    name = "gemini"
    default_model = "gemini-1.5-flash"

    def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max_tokens},
        }
        resp = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(body),
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        candidates = data.get("candidates") or []
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts).strip()
