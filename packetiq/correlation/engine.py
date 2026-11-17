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

        Known cost limit. This compares every remaining pair, so it is O(n^2) in
        the number of raw chains, and raw chains scale with distinct attacker
        IPs. Measured end-to-end on synthetic multi-attacker captures: 50
        attackers 0.006s, 400 1.4s, 800 10.5s, 1600 105s. A distributed scan
        with a few thousand sources is ordinary incident material, so this is a
        real ceiling rather than a theoretical one.

        Hoisting the per-pair event-id sets out of the inner loop (below) cut it
        ~3.5x and is output-identical. Going further means indexing chains by
        attacker IP and visiting only the chains that can possibly merge, which
        is the correct fix but not a local one: `absorb` mutates attacker_ips in
        place, so the index has to track ownership as chains grow, and a mistake
        there changes merge results silently. Left deliberately undone rather
        than done unverified.
        """
        if len(chains) <= 1:
            return chains

        # Work with indices to allow in-place merging
        merged_flags = [False] * len(chains)
        result: list[AttackChain] = []

        # Event-identity sets, built once per chain instead of once per pair.
        # Both sets used to be rebuilt inside the inner loop, so the work was
        # O(chains^2 x events) rather than O(chains^2) cheap set operations:
        # 50 distinct attacker IPs correlated in 0.013s but 800 took 37s, and a
        # distributed scan with a few thousand sources — ordinary incident
        # material — ran for hours. `absorb` mutates a chain in place, so the
        # entry for whichever chain grew is refreshed right after each merge;
        # that happens at most once per chain, not once per comparison.
        event_ids = [frozenset(id(e) for e in c.events) for c in chains]

        for i, chain_i in enumerate(chains):
            if merged_flags[i]:
                continue

            for j in range(i + 1, len(chains)):
                if merged_flags[j]:
                    continue

                chain_j = chains[j]

                # Must share an attacker IP. `isdisjoint` short-circuits and
                # allocates nothing where `&` built a throwaway set per pair;
                # profiling showed that was not the bottleneck (0.14s of 3.35s),
                # so this is tidiness, not the fix. The cost that remains is the
                # pair scan itself — see the note above _merge.
                if chain_i.attacker_ips.isdisjoint(chain_j.attacker_ips):
                    continue

                # Jaccard similarity of event sets
                union = event_ids[i] | event_ids[j]
                inter = event_ids[i] & event_ids[j]

                if not union:
                    continue

                jaccard = len(inter) / len(union)
                if jaccard > 0.5:
                    # Absorb smaller into larger
                    if len(chain_j.events) > len(chain_i.events):
                        chain_j.absorb(chain_i)
                        event_ids[j] = frozenset(id(e) for e in chain_j.events)
                        merged_flags[i] = True
                        break
                    else:
                        chain_i.absorb(chain_j)
                        event_ids[i] = frozenset(id(e) for e in chain_i.events)
                        merged_flags[j] = True

            if not merged_flags[i]:
                result.append(chain_i)

        # The loop above already appends exactly the chains that were not merged
        # away, so the sweep that used to follow could never add anything: every
        # chain with `merged_flags[i]` false is in `result`, and every other one
        # was deliberately absorbed.
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
