"""Minimal client for a *local* Ollama server."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from .config import assert_local_model_name, assert_local_url


class LlmError(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout: float = 600.0):
        assert_local_url(base_url)
        assert_local_model_name(model)
        self.model = model
        # trust_env=False: ignore HTTP(S)_PROXY so requests can't be routed off-box
        self._http = httpx.Client(
            base_url=base_url,
            trust_env=False,
            timeout=httpx.Timeout(timeout, connect=5.0),
        )

    def close(self) -> None:
        self._http.close()

    def version(self) -> str:
        r = self._http.get("/api/version")
        r.raise_for_status()
        return r.json().get("version", "?")

    def local_models(self) -> list[dict[str, Any]]:
        r = self._http.get("/api/tags")
        r.raise_for_status()
        return r.json().get("models", [])

    def ensure_model_is_local(self) -> dict[str, Any]:
        for m in self.local_models():
            if m.get("name") == self.model or m.get("model") == self.model:
                if m.get("remote_host") or m.get("remote_model"):
                    raise LlmError(f"Model {self.model!r} is a remote (cloud) model; refusing to use it.")
                return m
        raise LlmError(f"Model {self.model!r} is not pulled. Run: ollama pull {self.model}")

    def chat_json(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        *,
        num_ctx: int | None = None,
        think: bool = False,
        temperature: float = 0.0,
    ) -> tuple[dict[str, Any], float]:
        """Chat with structured output. Returns (parsed_json, seconds)."""
        options: dict[str, Any] = {"temperature": temperature}
        if num_ctx:
            options["num_ctx"] = num_ctx  # Ollama's default context is small; raise it for big prompts
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "format": schema,
            "stream": False,
            "think": think,  # Qwen3-family: off by default, we only want the JSON
            "keep_alive": "15m",
            "options": options,
        }
        t0 = time.perf_counter()
        try:
            r = self._http.post("/api/chat", json=payload)
            if r.status_code == 400 and "think" in r.text.lower():
                payload.pop("think")  # model without thinking support
                r = self._http.post("/api/chat", json=payload)
        except httpx.HTTPError as exc:
            raise LlmError(f"Ollama request failed: {type(exc).__name__}: {exc}") from exc
        if r.status_code != 200:
            raise LlmError(f"Ollama /api/chat returned {r.status_code}: {r.text[:300]}")
        content = r.json().get("message", {}).get("content", "")
        try:
            return json.loads(content), time.perf_counter() - t0
        except json.JSONDecodeError as exc:
            raise LlmError(f"Model returned non-JSON content: {content[:200]!r}") from exc
