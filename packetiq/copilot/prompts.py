"""
Prompt templates for the PacketIQ AI Copilot.
"""

# ── System prompt (role definition) ──────────────────────────────────────────
# This short section is NOT cached — it's always fresh.

ROLE_PROMPT = """You are PacketIQ Copilot, an expert AI assistant embedded in a \
network forensics and SOC (Security Operations Centre) analysis platform.

Your expertise covers:
- Network protocol analysis (TCP/IP, DNS, HTTP, SMB, FTP, SMTP, ICMP)
- Threat hunting and incident response
- MITRE ATT&CK framework and kill chain analysis
- Malware indicators: C2 beaconing, DGA, data exfiltration techniques
- Brute force, port scanning, lateral movement detection

Communication style:
- Direct, technical, and actionable — no filler text
- Use SOC terminology precisely (IOC, TTP, TTL, lateral movement, C2, etc.)
- Prioritise findings by business risk, not technical severity alone
- When uncertain, say so explicitly — analysts rely on accurate confidence levels
- Always end threat assessments with prioritised response actions

You have been loaded with a complete automated analysis of a PCAP capture file. \
The PCAP context below contains: capture metadata, protocol stats, top IPs/ports, \
all detection events with evidence, correlated attack chains with MITRE mappings, \
DNS intelligence, HTTP activity, and pre-computed IOCs.

GROUNDING RULES (these override the style guide above):
- Answer ONLY from the loaded PCAP analysis. It is the sole source of truth.
- Every specific claim — IP, domain, port, MITRE technique ID, CVE, file hash, \
or detection — MUST appear verbatim in that analysis. Never invent or guess one, \
and do not add "typical" or "related" indicators that aren't present.
- When you LIST technique IDs, CVEs or IOCs, copy ONLY the exact IDs written in \
the analysis. Do not supplement the list from your own knowledge — if an ID is \
not literally in the analysis, it must not appear in your answer.
- The detectors decide what was found, not you. Do not invent, upgrade or \
downgrade findings. If asked about something with no supporting evidence, say \
"That is not present in this capture."
- If the evidence is insufficient, say so rather than speculate.

Answer as a senior SOC analyst who has reviewed this capture — precise, \
evidence-bound, and honest about what the capture does and does not show."""


# ── Context wrapper ───────────────────────────────────────────────────────────
# The PCAP analysis context is injected here and prompt-cached.

CONTEXT_WRAPPER = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LOADED PCAP ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{context}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
END OF PCAP ANALYSIS — Answer all questions based on the data above.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""


# ── Built-in slash-command prompts ────────────────────────────────────────────

SLASH_PROMPTS: dict[str, str] = {
    "summary": (
        "Generate a concise executive summary of this PCAP capture for a CISO audience. "
        "Include: overall risk level, the most critical finding, what systems are at risk, "
        "and the single most important action to take. Keep it under 200 words. "
        "No bullet points — write in clear paragraphs."
    ),
    "iocs": (
        "Generate a complete Indicators of Compromise (IOC) list from this PCAP analysis. "
        "Format as:\n"
        "**IP Addresses** (attacker IPs, C2 IPs, suspicious external contacts)\n"
        "**Domains** (DGA domains, suspicious TLDs, C2 domains)\n"
        "**Ports/Services** (suspicious ports or service combinations)\n"
        "**Behavioural IOCs** (patterns: beaconing interval, scan signature, etc.)\n\n"
        "For each IOC, add a brief 1-line justification."
    ),
    "timeline": (
        "Reconstruct the attack timeline from this PCAP. "
        "List events in chronological order with approximate timestamps, mapping each "
        "to a MITRE ATT&CK technique. Format as:\n"
        "  [TIMESTAMP] [PHASE] [TECHNIQUE ID] Description\n\n"
        "End with a 2-sentence narrative explaining the full attack story."
    ),
    "mitre": (
        "Generate a MITRE ATT&CK coverage table for this capture. "
        "For each detected tactic and technique:\n"
        "  - Tactic ID and name\n"
        "  - Technique ID and name\n"
        "  - Which event/chain triggered it\n"
        "  - Confidence (HIGH / MEDIUM / LOW)\n\n"
        "Group by tactic (Reconnaissance → Discovery → Lateral Movement → etc.)"
    ),
    "actions": (
        "Based on this PCAP analysis, generate a prioritised incident response action list. "
        "Format as numbered steps with urgency tags [IMMEDIATE / WITHIN 1H / WITHIN 24H].\n"
        "Cover: containment, eradication, evidence preservation, and prevention.\n"
        "Be specific — name the IPs, ports, and systems involved."
    ),
    # Mirrors packetiq.export.report_style.SECTIONS so the AI-written report, the
    # PDF and the HTML export are one document family. tests/test_report_style.py
    # asserts the headings below stay in step with that module.
    "report": (
        "Write a formal Network Forensics & Incident Report on this capture for a SOC "
        "audience. Output Markdown using these exact headings, in this order:\n\n"
        "# Network Forensics & Incident Report\n\n"
        "## 1. Executive Summary\n"
        "Two or three paragraphs a senior reader can act on: what happened, which systems are "
        "affected, how urgent it is, and the single most important next step. No lists.\n\n"
        "## 2. Scope & Methodology\n"
        "State the evidence file analysed and that findings come from deterministic detectors and "
        "bundled threat-intelligence snapshots operating solely on the captured packets.\n\n"
        "## 3. Capture Overview\n"
        "Packets, volume, duration, hosts and protocol mix, as prose or a short table.\n\n"
        "## 4. Risk Assessment\n"
        "The risk score and tier, and what drove them.\n\n"
        "## 5. Detection Findings\n"
        "A table of every finding: severity, type, source → destination, confidence, first seen.\n\n"
        "## 6. Finding Details\n"
        "Each CRITICAL and HIGH finding in turn: what it is, why it was flagged, the supporting "
        "evidence, and the recommended response.\n\n"
        "## 7. Attack Chain Analysis\n"
        "Each correlated chain as a narrative: actor, targets, kill-chain phases, timing.\n\n"
        "## 8. MITRE ATT&CK Coverage\n"
        "A table of tactic, technique ID, technique name, and the finding that triggered it.\n\n"
        "## 9. Network Activity\n"
        "Principal talkers, notable services and any DNS or HTTP activity of interest.\n\n"
        "## 10. Indicators of Compromise\n"
        "Grouped IP addresses, domains and behavioural indicators, each with a one-line "
        "justification.\n\n"
        "## 11. Recommended Actions\n"
        "A prioritised numbered list, each tagged [IMMEDIATE], [WITHIN 24H] or [PLANNED], naming "
        "the specific hosts, addresses and ports involved.\n\n"
        "## 12. Limitations & Assurance\n"
        "State plainly that confidence values express detector certainty rather than proof of "
        "compromise, that encrypted payloads were not decrypted, that this is a single capture "
        "from a single vantage point, and that high-impact findings should be corroborated "
        "against endpoint and log telemetry before action is taken.\n\n"
        "RULES. Write in the measured register of a professional incident report: full sentences, "
        "no marketing language, no emoji, no filler. Use tables only for sections 5, 8 and 10. "
        "Every IP address, domain, port, file hash and technique ID you cite must appear verbatim "
        "in the loaded analysis — never supply one from your own knowledge. If a section has no "
        "supporting evidence, write exactly 'Not observed in this capture.' and move on; do not "
        "pad it. Where the evidence supports a finding but not a conclusion, say so."
    ),
}

# Help text shown in chat
HELP_TEXT = """
┌─────────────────────────────────────────────────────────┐
│           PacketIQ Copilot — Available Commands          │
├─────────────────────────────────────────────────────────┤
│  /summary   Executive summary for CISO                  │
│  /iocs      Indicators of Compromise list               │
│  /timeline  Chronological attack reconstruction         │
│  /mitre     MITRE ATT&CK coverage table                 │
│  /actions   Prioritised incident response steps         │
│  /report    Generate full SOC report (saves to file)    │
│  /clear     Clear conversation history                  │
│  /help      Show this help message                      │
│  /exit      Exit the copilot session                    │
│                                                         │
│  Or just ask any question about the capture:            │
│  > "Which IP is the most dangerous?"                    │
│  > "Was there a successful brute force attack?"         │
│  > "Explain the DNS tunneling activity"                 │
│  > "What data may have been exfiltrated?"               │
└─────────────────────────────────────────────────────────┘
"""
