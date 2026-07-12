"""
PacketIQ - AI PCAP Forensics & SOC Copilot
Version: 1.0.0
"""
import logging as _logging
import warnings as _warnings

__version__ = "1.0.0"
__author__ = "PacketIQ"


def _quiet_third_party_noise() -> None:
    """Silence two cosmetic third-party notices so the CLI / web app output stays
    clean. Neither is a PacketIQ warning and neither affects analysis correctness:

    * urllib3 prints a ``NotOpenSSLWarning`` on macOS system Python because that
      interpreter is linked against LibreSSL instead of OpenSSL — purely
      informational. Matched by message (not category) so we don't have to import
      urllib3 first, which is what emits the warning.
    * The ``google-genai`` SDK logs "there are non-text parts in the response:
      ['thought_signature'] …" whenever a Gemini *thinking* model returns its
      internal reasoning parts alongside the answer. The answer text is still
      returned correctly (the SDK just concatenates the text parts), so the notice
      is pure noise for our use — we only ever want the text.
    """
    _warnings.filterwarnings(
        "ignore", message=r"urllib3 v2 only supports OpenSSL", module="urllib3"
    )
    # Belt-and-braces: also match if urllib3 was already imported under a different
    # module path before this ran.
    _warnings.filterwarnings("ignore", message=r"urllib3 v2 only supports OpenSSL")
    _logging.getLogger("google_genai.types").setLevel(_logging.ERROR)


_quiet_third_party_noise()
