"""
Claude API client for PacketIQ Copilot.

Features:
  - Prompt caching on the PCAP analysis context (saves ~70% tokens per message)
  - Streaming responses with per-chunk callback
  - Conversation history management
  - Graceful error handling with informative messages
"""

import os
from typing import Any, Callable, Optional, cast

import anthropic

from packetiq.copilot.prompts import CONTEXT_WRAPPER, ROLE_PROMPT

MODEL      = "claude-sonnet-4-6"
MAX_TOKENS = 4096
# Grounding: low temperature keeps explanations tied to the evidence, not creative.
TEMPERATURE = float(os.environ.get("PACKETIQ_AI_TEMPERATURE", "0.15"))


class CopilotClient:
    """
    Wrapper around the Anthropic Messages API.
    Maintains the system prompt with prompt caching across the entire session.
    """

    def __init__(self, api_key: Optional[str] = None):
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ValueError(
                "ANTHROPIC_API_KEY not set. "
                "Add it to your .env file or export it in your shell."
            )
        self._client = anthropic.Anthropic(api_key=key)
        self._pcap_context: Optional[str] = None
        # Anthropic system blocks: plain dicts at runtime, TypedDicts to the SDK.
        self._system: Optional[list[Any]] = None

    def load_context(self, pcap_context: str):
        """
        Pre-load the PCAP analysis context.
        The context block is marked for prompt caching so Claude doesn't
        re-process it on every message in the session.
        """
        self._pcap_context = pcap_context
        context_block = CONTEXT_WRAPPER.format(context=pcap_context)

        # Two-block system: role prompt (not cached) + PCAP context (cached)
        self._system = [
            {
                "type": "text",
                "text": ROLE_PROMPT,
            },
            {
                "type": "text",
                "text": context_block,
                # Prompt caching: this large block is cached server-side.
                # Saves ~70% of tokens for every subsequent message.
                "cache_control": {"type": "ephemeral"},
            },
        ]

    def stream_message(
        self,
        messages: list[dict],
        on_chunk: Callable[[str], None],
    ) -> str:
        """
        Send a conversation turn and stream the response.

        Args:
            messages: Full conversation history in Anthropic format.
            on_chunk: Called with each streamed text chunk.

        Returns:
            Complete response text.
        """
        if not self._system:
            raise RuntimeError("Call load_context() before stream_message().")

        full_text = ""
        with self._client.messages.stream(
            model       = MODEL,
            max_tokens  = MAX_TOKENS,
            temperature = TEMPERATURE,
            system      = self._system,
            messages    = cast(Any, messages),
        ) as stream:
            for chunk in stream.text_stream:
                on_chunk(chunk)
                full_text += chunk

        return full_text

    def single_message(self, prompt: str) -> str:
        """
        Non-streaming single-shot message. Used for report generation.
        Returns the full response text.
        """
        if not self._system:
            raise RuntimeError("Call load_context() before single_message().")

        response = self._client.messages.create(
            model       = MODEL,
            max_tokens  = MAX_TOKENS,
            temperature = TEMPERATURE,
            system      = self._system,
            messages    = [{"role": "user", "content": prompt}],
        )
        # Our prompts always lead with a text block, but the content union also
        # covers thinking/tool-use blocks — don't assume, and don't index empty.
        block = response.content[0] if response.content else None
        return str(getattr(block, "text", "") or "")


def load_api_key() -> Optional[str]:
    """Load API key from environment or .env file."""
    # Try environment first
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key

    # Try .env file in current directory or parent
    for path in (".", ".."):
        env_file = os.path.join(path, ".env")
        if os.path.isfile(env_file):
            with open(env_file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("ANTHROPIC_API_KEY"):
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            return parts[1].strip().strip('"').strip("'")
    return None
