"""
Telegram sender — thin wrapper around the Telegram Bot API.

Uses requests (already a dependency) to POST messages.
Supports HTML parse mode, file documents, and connection testing.

Telegram Bot API limits:
  - 30 messages/second per bot (global)
  - 20 messages/minute per chat (group chats)
  - Max message length: 4096 characters
  - We enforce a 1.1s inter-message delay to stay well within limits.
"""

import html
import time
from typing import Optional

import requests

BASE_URL   = "https://api.telegram.org/bot{token}/{method}"
MAX_LENGTH = 4096       # Telegram hard limit per message
MIN_DELAY  = 1.1        # seconds between successive sends (rate safety)


class TelegramSender:
    """
    Sends HTML-formatted messages to a Telegram chat.
    Thread-unsafe — create one instance per analysis run.
    """

    def __init__(self, token: str, chat_id: str, timeout: int = 15):
        self.token   = token.strip()
        self.chat_id = str(chat_id).strip()
        self.timeout = timeout
        self._last_sent: float = 0.0

    # ── Public API ────────────────────────────────────────────────────────────

    def send(self, text: str, disable_preview: bool = True) -> tuple[bool, str]:
        """
        Send a message. If longer than MAX_LENGTH, splits at paragraph boundaries.
        Returns (success, error_message_or_empty).
        """
        chunks = _split_message(text, MAX_LENGTH)
        for chunk in chunks:
            ok, err = self._post("sendMessage", {
                "chat_id":                  self.chat_id,
                "text":                     chunk,
                "parse_mode":               "HTML",
                "disable_web_page_preview": disable_preview,
            })
            if not ok:
                return False, err
            self._rate_limit()
        return True, ""

    def send_document(self, filepath: str, caption: str = "") -> tuple[bool, str]:
        """Send a file as a document attachment."""
        self._rate_limit()
        url = BASE_URL.format(token=self.token, method="sendDocument")
        try:
            with open(filepath, "rb") as f:
                resp = requests.post(
                    url,
                    data={
                        "chat_id":    self.chat_id,
                        "caption":    caption[:1024],
                        "parse_mode": "HTML",
                    },
                    files={"document": f},
                    timeout=self.timeout,
                )
            data = resp.json()
            if data.get("ok"):
                return True, ""
            return False, data.get("description", "Unknown error")
        except Exception as e:
            return False, str(e)

    def test_connection(self) -> tuple[bool, str]:
        """
        Verify token and chat_id by calling getMe and sending a test message.
        Returns (ok, description).
        """
        # 1. Check token is valid
        url = BASE_URL.format(token=self.token, method="getMe")
        try:
            resp = requests.get(url, timeout=self.timeout)
            data = resp.json()
        except Exception as e:
            return False, f"Network error: {e}"

        if not data.get("ok"):
            return False, f"Invalid bot token: {data.get('description', 'unknown')}"

        bot_name = data["result"].get("username", "unknown")

        # 2. Send a test message
        test_msg = (
            "🟢 <b>PacketIQ — Connection Test</b>\n\n"
            "✅ Telegram alerting is configured correctly.\n"
            f"🤖 Bot: @{bot_name}\n"
            "📡 Alerts will be sent here for HIGH and CRITICAL findings."
        )
        ok, err = self.send(test_msg)
        if not ok:
            return False, f"Token valid but message failed: {err}"

        return True, f"Connected as @{bot_name}"

    # ── Internal ──────────────────────────────────────────────────────────────

    def _post(self, method: str, payload: dict) -> tuple[bool, str]:
        url = BASE_URL.format(token=self.token, method=method)
        try:
            resp = requests.post(url, json=payload, timeout=self.timeout)
            data = resp.json()
            if data.get("ok"):
                return True, ""
            return False, data.get("description", "Unknown Telegram API error")
        except requests.Timeout:
            return False, "Request timed out"
        except requests.ConnectionError:
            return False, "Network unreachable"
        except Exception as e:
            return False, str(e)

    def _rate_limit(self):
        """Enforce minimum delay between sends."""
        elapsed = time.time() - self._last_sent
        if elapsed < MIN_DELAY:
            time.sleep(MIN_DELAY - elapsed)
        self._last_sent = time.time()


# ── Credential loading ────────────────────────────────────────────────────────

def load_credentials() -> tuple[Optional[str], Optional[str]]:
    """
    Load TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from environment or .env file.
    Returns (token, chat_id) — either may be None if not found.
    """
    import os

    token   = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if token and chat_id:
        return token, chat_id

    # Fall back to .env file scan
    for path in (".", ".."):
        import os.path
        env_file = os.path.join(path, ".env")
        if not os.path.isfile(env_file):
            continue
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if "=" not in line or line.startswith("#"):
                    continue
                key, _, val = line.partition("=")
                val = val.strip().strip('"').strip("'")
                if key.strip() == "TELEGRAM_BOT_TOKEN" and not token:
                    token = val
                if key.strip() == "TELEGRAM_CHAT_ID" and not chat_id:
                    chat_id = val

    return token or None, chat_id or None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _split_message(text: str, limit: int) -> list[str]:
    """
    Split text into chunks ≤ limit characters, breaking at double-newlines
    (paragraph boundaries) to preserve formatting.
    """
    if len(text) <= limit:
        return [text]

    chunks: list[str] = []
    remaining = text
    while len(remaining) > limit:
        # Try to break at the last double-newline before limit
        cut = remaining.rfind("\n\n", 0, limit)
        if cut == -1:
            cut = remaining.rfind("\n", 0, limit)
        if cut == -1:
            cut = limit
        chunks.append(remaining[:cut].rstrip())
        remaining = remaining[cut:].lstrip()

    if remaining:
        chunks.append(remaining)

    return chunks


def esc(text: str) -> str:
    """Escape a string for safe inclusion in HTML Telegram messages."""
    return html.escape(str(text), quote=False)
