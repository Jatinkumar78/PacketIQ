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
    "report": (
        "Generate a complete SOC Incident Report for this PCAP capture. "
        "Use this exact structure:\n\n"
        "# SOC Incident Report — PacketIQ Analysis\n\n"
        "## 1. Executive Summary\n"
        "(2-3 paragraphs: what happened, impact, urgency)\n\n"
        "## 2. Risk Assessment\n"
        "(Risk score, tier, classification)\n\n"
        "## 3. Attack Timeline\n"
        "(Chronological events with kill chain phases)\n\n"
        "## 4. Critical Findings\n"
        "(All CRITICAL and HIGH severity events with evidence)\n\n"
        "## 5. Attack Chain Analysis\n"
        "(Each correlated chain with narrative)\n\n"
        "## 6. MITRE ATT&CK Mapping\n"
        "(Tactics and techniques table)\n\n"
        "## 7. Indicators of Compromise\n"
        "(IPs, domains, behavioural IOCs)\n\n"
        "## 8. Affected Systems\n"
        "(Internal IPs that appear compromised or targeted)\n\n"
        "## 9. Immediate Response Actions\n"
        "(Prioritised numbered list)\n\n"
        "## 10. Recommendations\n"
        "(Longer-term security improvements)\n\n"
        "Be thorough, technical, and specific. Use actual IPs, ports, and domain names "
        "from the analysis. This report will be used by incident responders."
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
