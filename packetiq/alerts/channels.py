"""
Additional alert channels beyond Telegram: Slack (incoming webhook), generic
webhook (JSON POST), and email (SMTP).

Each channel is configured purely via environment / .env variables and is a
no-op if its config is absent, so enabling a channel never breaks a run.

Env vars:
  SLACK_WEBHOOK_URL          — Slack incoming webhook URL
  ALERT_WEBHOOK_URL          — generic JSON webhook (POSTs the full payload)
  SMTP_HOST, SMTP_PORT       — mail server (port defaults to 587)
  SMTP_USER, SMTP_PASSWORD   — SMTP auth
  ALERT_EMAIL_FROM, ALERT_EMAIL_TO  — sender / recipient
"""

import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Optional

import requests

_TIMEOUT = 15


def _env(name: str) -> Optional[str]:
    val = os.environ.get(name)
    if val:
        return val
    # fall back to .env (reuse the alerts loader's scan)
    for path in (".", ".."):
        p = os.path.join(path, ".env")
        if os.path.isfile(p):
            with open(p, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    if k.strip() == name:
                        return v.strip().strip('"').strip("'")
    return None


class SlackWebhook:
    def __init__(self, url: str):
        self.url = url

    def send(self, text: str) -> tuple[bool, str]:
        try:
            r = requests.post(self.url, json={"text": text}, timeout=_TIMEOUT)
            return (r.status_code == 200, "" if r.status_code == 200 else f"HTTP {r.status_code}")
        except Exception as e:  # noqa: BLE001
            return False, str(e)


class GenericWebhook:
    def __init__(self, url: str):
        self.url = url

    def send(self, payload: dict) -> tuple[bool, str]:
        try:
            r = requests.post(self.url, json=payload, timeout=_TIMEOUT)
            return (200 <= r.status_code < 300, "" if r.ok else f"HTTP {r.status_code}")
        except Exception as e:  # noqa: BLE001
            return False, str(e)


class EmailSender:
    def __init__(self, host, port, user, password, sender, recipient):
        self.host = host
        self.port = int(port or 587)
        self.user = user
        self.password = password
        self.sender = sender
        self.recipient = recipient

    def send(self, subject: str, body: str) -> tuple[bool, str]:
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = self.sender
            msg["To"] = self.recipient
            msg.set_content(body)
            ctx = ssl.create_default_context()
            with smtplib.SMTP(self.host, self.port, timeout=_TIMEOUT) as s:
                s.starttls(context=ctx)
                if self.user and self.password:
                    s.login(self.user, self.password)
                s.send_message(msg)
            return True, ""
        except Exception as e:  # noqa: BLE001
            return False, str(e)


def configured_channels() -> list[str]:
    """Return the names of channels that have the env config to operate."""
    chans = []
    if _env("SLACK_WEBHOOK_URL"):
        chans.append("slack")
    if _env("ALERT_WEBHOOK_URL"):
        chans.append("webhook")
    if _env("SMTP_HOST") and _env("ALERT_EMAIL_TO"):
        chans.append("email")
    return chans


def broadcast(subject: str, text: str, payload: Optional[dict] = None) -> dict:
    """Send to every configured channel. Returns {channel: (ok, err)}."""
    results: dict = {}

    slack = _env("SLACK_WEBHOOK_URL")
    if slack:
        results["slack"] = SlackWebhook(slack).send(f"*{subject}*\n{text}")

    hook = _env("ALERT_WEBHOOK_URL")
    if hook:
        results["webhook"] = GenericWebhook(hook).send(payload or {"subject": subject, "text": text})

    if _env("SMTP_HOST") and _env("ALERT_EMAIL_TO"):
        sender = EmailSender(
            _env("SMTP_HOST"), _env("SMTP_PORT"),
            _env("SMTP_USER"), _env("SMTP_PASSWORD"),
            _env("ALERT_EMAIL_FROM") or _env("SMTP_USER") or "packetiq@localhost",
            _env("ALERT_EMAIL_TO"),
        )
        results["email"] = sender.send(subject, text)

    return results
