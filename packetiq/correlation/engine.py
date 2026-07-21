"""
Correlation Engine — runs all rules, deduplicates overlapping chains,
and returns a ranked list of AttackChains.

Deduplication strategy:
  Two chains are considered overlapping if they share the same primary
  attacker IP AND >50% of their events (by identity). The smaller chain
  is absorbed into the larger, preserving all MITRE intel and events.

Usage:
    engine = CorrelationEngine()
    chains = engine.correlate(detection_events)
"""


import contextlib

from packetiq.correlation import rules as rule_module
from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent, Severity

# Ordered list of rule functions to apply
_RULES = [
    rule_module.full_kill_chain,          # most specific first → highest confidence
    rule_module.recon_to_initial_access,
    rule_module.reconnaissance_progression,
    rule_module.brute_credential_chain,
    rule_module.lateral_movement_smb,
    rule_module.c2_channel_detection,
    rule_module.covert_exfiltration,
    rule_module.dga_c2_cluster,
    rule_module.credential_spray,
]

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
}


class CorrelationEngine:

    def correlate(self, events: list[DetectionEvent]) -> list[AttackChain]:
        """
        Apply all rules to the event list, merge overlapping chains,
        and return chains sorted by severity → confidence → event count.
        """
        if not events:
            return []

        raw_chains: list[AttackChain] = []
        for rule_fn in _RULES:
            # A broken rule should never crash the whole engine
            with contextlib.suppress(Exception):
                raw_chains.extend(rule_fn(events))

        merged = self._merge(raw_chains)
        return self._rank(merged)

    # ── Deduplication / merging ──────────────────────────────────────────────

    def _merge(self, chains: list[AttackChain]) -> list[AttackChain]:
        """
        Greedily merge chains that:
          - Share at least one common attacker IP, AND
          - Have >50% event overlap (Jaccard index on object identity)
        """
        if len(chains) <= 1:
            return chains

        # Work with indices to allow in-place merging
        merged_flags = [False] * len(chains)
        result: list[AttackChain] = []

        for i, chain_i in enumerate(chains):
            if merged_flags[i]:
                continue

            for j in range(i + 1, len(chains)):
                if merged_flags[j]:
                    continue

                chain_j = chains[j]

                # Must share an attacker IP
                if not (chain_i.attacker_ips & chain_j.attacker_ips):
                    continue

                # Jaccard similarity of event sets
                ids_i = {id(e) for e in chain_i.events}
                ids_j = {id(e) for e in chain_j.events}
                union = ids_i | ids_j
                inter = ids_i & ids_j

                if not union:
                    continue

                jaccard = len(inter) / len(union)
                if jaccard > 0.5:
                    # Absorb smaller into larger
                    if len(chain_j.events) > len(chain_i.events):
                        chain_j.absorb(chain_i)
                        merged_flags[i] = True
                        break
                    else:
                        chain_i.absorb(chain_j)
                        merged_flags[j] = True

            if not merged_flags[i]:
                result.append(chain_i)

        # Collect any chains that were absorbed-into but not yet in result
        for i, chain in enumerate(chains):
            if not merged_flags[i] and chain not in result:
                result.append(chain)

        return result

    def _rank(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Sort by severity → confidence (desc) → event count (desc)."""
        return sorted(
            chains,
            key=lambda c: (
                _SEVERITY_ORDER.get(c.severity, 9),
                -c.confidence,
                -c.event_count,
            ),
        )
