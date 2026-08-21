"""
Multi-provider adapter for the CLI copilot.

The interactive chat (`InteractiveChat`) and the `report` command were written
against the Anthropic-only `CopilotClient`. This adapter exposes the same tiny
interface (`load_context` / `stream_message` / `single_message`) but routes
through the web app's tested provider layer — Gemini → Groq → Anthropic → local
Ollama, with the same sticky auto-switch and offline fallback. So `packetiq
chat` / `packetiq report` now work with whatever provider is available (a free
cloud key or a fully-offline local model), not just an Anthropic key.
"""

from __future__ import annotations

import asyncio
from typing import Callable


class MultiProviderClient:
    """Drop-in replacement for CopilotClient that speaks to all providers."""

    def __init__(self, provider: str = "auto", model: str = ""):
        # Imported lazily so importing the copilot package stays light.
        import os

        from packetiq.webapp import app as webapp
        self._w = webapp
        if provider and provider not in ("auto", ""):
            webapp._AI_FORCED["provider"] = provider
        if model:
            # Same pin the web UI's model picker writes, so `--model` and the GUI
            # selector are one mechanism: without it the local runtime is free to
            # answer with whichever model it picked, which on a small machine may
            # be one far too large to run at a usable speed. With no `--provider`
            # the pin lands on whichever provider is about to be used, so the flag
            # never silently configures one the run won't touch.
            target = (provider if provider and provider not in ("auto", "")
                      else webapp._detect_provider()["provider"])
            if target:
                os.environ[webapp._model_env_name(target)] = model
        self._context: str = ""
        self._system: str | None = None

    # ── interface expected by InteractiveChat / report ──────────────────────
    def load_context(self, context: str) -> None:
        self._context = context
        self._system = self._w._CHAT_SYSTEM

    def available(self) -> bool:
        return self._w._detect_provider()["provider"] is not None

    @property
    def model_label(self) -> str:
        d = self._w._detect_provider()
        if not d["provider"]:
            return "no provider"
        label = self._w._AI_LABEL.get(d["provider"], d["provider"])
        return f"{label} · {d['model']}"

    def single_message(self, prompt: str) -> str:
        """Non-streaming completion with cross-provider fallback (used by /report)."""
        if self._system is None:
            raise RuntimeError("Call load_context() first.")
        return asyncio.run(self._w._collect_ai_with_fallback(
            self._system, self._context, [{"role": "user", "content": prompt}]))

    def stream_message(self, messages: list, on_chunk: Callable[[str], None]) -> str:
        """Streaming turn with sticky auto-switch across providers. Never raises for
        provider errors — emits a friendly message through on_chunk instead, so the
        interactive REPL can't be killed by a transient API failure."""
        if self._system is None:
            raise RuntimeError("Call load_context() first.")
        w = self._w

        async def _run() -> str:
            skipped: set = set()
            current = w._detect_provider()
            if not current["provider"]:
                msg = w._NO_PROVIDER_HINT
                on_chunk(msg)
                return msg
            last_err = ""
            while current["provider"]:
                full = ""
                label = w._AI_LABEL.get(current["provider"], current["provider"])
                try:
                    async for chunk in w._stream_ai(
                        current["provider"], current["key"], current["model"],
                        self._system, self._context, messages,
                    ):
                        on_chunk(chunk)
                        full += chunk
                    if full.strip():
                        return full
                    last_err = f"{label} returned an empty response."
                except Exception as exc:  # noqa: BLE001
                    last_err = str(exc)
                    if w._is_rate_limit(last_err):
                        w._mark_cooldown(current["provider"], w._retry_after_seconds(last_err))
                skipped.add(current["provider"])
                nxt = w._detect_provider(skip=skipped)
                if nxt["provider"]:
                    notice = f"\n*({label} unavailable — switching to " \
                             f"{w._AI_LABEL.get(nxt['provider'], nxt['provider'])}…)*\n"
                    on_chunk(notice)
                current = nxt
            fail = f"\n[AI request failed: {last_err[:200]}]"
            on_chunk(fail)
            return fail

        return asyncio.run(_run())
