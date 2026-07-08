"""
Threat-intel enrichment — cross-references observed network indicators
(IPs, domains, file hashes) against REAL OSINT feeds (abuse.ch Feodo /
ThreatFox / MalwareBazaar, the Tor exit list, and Spamhaus DROP).

No indicator is invented: matches come only from feeds that ship with the
package or that the user refreshes via `packetiq feeds update`.
"""

from packetiq.enrichment.engine import enrich
from packetiq.enrichment.feeds import IOCStore, feed_details, feed_summary, load_store

__all__ = ["IOCStore", "load_store", "feed_summary", "feed_details", "enrich"]
