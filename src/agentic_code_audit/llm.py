from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from .config import Settings


@dataclass
class LLMResponse:
    ok: bool
    content: str
    error: str = ""


class DeepSeekClient:
    """Minimal DeepSeek OpenAI-compatible chat client using stdlib only."""

    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def enabled(self) -> bool:
        return bool(self.settings.deepseek_api_key)

    def chat(self, system_prompt: str, user_prompt: str, timeout: int = 60) -> LLMResponse:
        if not self.enabled:
            return LLMResponse(ok=False, content="", error="DEEPSEEK_API_KEY is not configured")

        url = self.settings.deepseek_base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.settings.deepseek_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
        }
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.settings.deepseek_api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
            content = body["choices"][0]["message"]["content"]
            return LLMResponse(ok=True, content=content)
        except (urllib.error.URLError, KeyError, json.JSONDecodeError, TimeoutError) as exc:
            return LLMResponse(ok=False, content="", error=str(exc))
