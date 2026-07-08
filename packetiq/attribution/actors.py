"""
Threat Actor Database.

Curated list of known threat groups with their characteristic TTPs.
Used by the attribution engine to score detected patterns against known actors.

Sources: MITRE ATT&CK Groups, CISA advisories, CrowdStrike Adversary Intelligence.
"""

from packetiq.detection.models import EventType

THREAT_ACTORS: list[dict] = [
    {
        "name":        "APT28",
        "aliases":     ["Fancy Bear", "Sofacy", "STRONTIUM", "Sednit"],
        "origin":      "Russia (GRU / Unit 26165)",
        "mitre_group": "G0007",
        "motivation":  "Espionage",
        "target_sectors": ["Government", "Defense", "Media", "NATO"],
        "description": (
            "Russian military intelligence unit conducting cyber espionage "
            "against NATO governments and political organizations."
        ),
        "ttp_weights": {
            EventType.PORT_SCAN:           0.8,
            EventType.BRUTE_FORCE:         0.9,
            EventType.CREDENTIAL_EXPOSURE: 0.7,
            EventType.C2_BEACON:           0.6,
            EventType.SUSPICIOUS_FLAGS:    0.5,
        },
        "phases": {"Reconnaissance", "Exploitation", "Command & Control"},
        "icon": "🐻",
        "color": "#cc2200",
    },
    {
        "name":        "APT29",
        "aliases":     ["Cozy Bear", "NOBELIUM", "The Dukes", "Midnight Blizzard"],
        "origin":      "Russia (SVR / Foreign Intelligence Service)",
        "mitre_group": "G0016",
        "motivation":  "Espionage",
        "target_sectors": ["Government", "Healthcare", "Think Tanks", "Tech"],
        "description": (
            "Russian foreign intelligence service unit specializing in "
            "stealthy, long-duration intrusions with minimal footprint."
        ),
        "ttp_weights": {
            EventType.C2_BEACON:           0.95,
            EventType.JA3_ANOMALY:         0.85,
            EventType.DNS_TUNNELING:       0.8,
            EventType.PROTOCOL_MISUSE:     0.6,
            EventType.CREDENTIAL_EXPOSURE: 0.5,
        },
        "phases": {"Command & Control", "Actions on Objectives"},
        "icon": "🐻‍❄️",
        "color": "#0055cc",
    },
    {
        "name":        "Lazarus Group",
        "aliases":     ["HIDDEN COBRA", "Guardians of Peace", "APT38", "BlueNoroff"],
        "origin":      "North Korea (RGB / Reconnaissance General Bureau)",
        "mitre_group": "G0032",
        "motivation":  "Financial + Espionage",
        "target_sectors": ["Finance", "Crypto", "Defense", "Media"],
        "description": (
            "North Korean state-sponsored group conducting financially "
            "motivated attacks and destructive operations."
        ),
        "ttp_weights": {
            EventType.PORT_SCAN:           0.85,
            EventType.BRUTE_FORCE:         0.75,
            EventType.DNS_ANOMALY:         0.7,
            EventType.PROTOCOL_MISUSE:     0.8,
            EventType.C2_BEACON:           0.65,
            EventType.JA3_ANOMALY:         0.6,
        },
        "phases": {"Reconnaissance", "Exploitation", "Delivery"},
        "icon": "🚀",
        "color": "#cc4400",
    },
    {
        "name":        "APT41",
        "aliases":     ["Double Dragon", "Winnti Group", "Barium", "Wicked Panda"],
        "origin":      "China (MSS / Ministry of State Security)",
        "mitre_group": "G0096",
        "motivation":  "Espionage + Financial",
        "target_sectors": ["Healthcare", "Telecom", "Video Games", "Finance"],
        "description": (
            "Unique dual-mission group conducting espionage for Chinese "
            "government and financially motivated cybercrime."
        ),
        "ttp_weights": {
            EventType.PORT_SCAN:           0.9,
            EventType.CREDENTIAL_EXPOSURE: 0.85,
            EventType.PROTOCOL_MISUSE:     0.75,
            EventType.BRUTE_FORCE:         0.7,
            EventType.DNS_ANOMALY:         0.6,
            EventType.C2_BEACON:           0.65,
        },
        "phases": {"Reconnaissance", "Exploitation", "Installation"},
        "icon": "🐉",
        "color": "#aa0000",
    },
    {
        "name":        "Sandworm",
        "aliases":     ["Voodoo Bear", "ELECTRUM", "TeleBots", "Seashell Blizzard"],
        "origin":      "Russia (GRU / Unit 74455)",
        "mitre_group": "G0034",
        "motivation":  "Sabotage + Disruption",
        "target_sectors": ["Energy", "Government", "Industrial Control Systems"],
        "description": (
            "Russian GRU unit responsible for NotPetya, BlackEnergy, "
            "and attacks on Ukrainian infrastructure."
        ),
        "ttp_weights": {
            EventType.PROTOCOL_MISUSE:     0.95,
            EventType.ICMP_TUNNELING:      0.85,
            EventType.SUSPICIOUS_FLAGS:    0.8,
            EventType.DNS_TUNNELING:       0.7,
            EventType.C2_BEACON:           0.6,
        },
        "phases": {"Delivery", "Exploitation", "Actions on Objectives"},
        "icon": "🐛",
        "color": "#884400",
    },
    {
        "name":        "FIN7",
        "aliases":     ["Carbanak", "Navigator Group", "Sangria Tempest"],
        "origin":      "Russia / Ukraine (Criminal)",
        "mitre_group": "G0046",
        "motivation":  "Financial",
        "target_sectors": ["Hospitality", "Retail", "Finance", "Restaurant"],
        "description": (
            "Financially motivated criminal group known for targeting "
            "POS systems and conducting large-scale payment card theft."
        ),
        "ttp_weights": {
            EventType.CREDENTIAL_EXPOSURE: 0.95,
            EventType.BRUTE_FORCE:         0.85,
            EventType.C2_BEACON:           0.75,
            EventType.JA3_ANOMALY:         0.65,
            EventType.DNS_ANOMALY:         0.5,
        },
        "phases": {"Exploitation", "Command & Control", "Actions on Objectives"},
        "icon": "💰",
        "color": "#006600",
    },
    {
        "name":        "APT10",
        "aliases":     ["Stone Panda", "MenuPass", "Cloud Hopper", "Bronze Riverside"],
        "origin":      "China (MSS / Tianjin Bureau)",
        "mitre_group": "G0045",
        "motivation":  "Espionage",
        "target_sectors": ["MSP", "Healthcare", "Manufacturing", "Government"],
        "description": (
            "Chinese espionage group known for targeting managed service "
            "providers to gain access to downstream clients."
        ),
        "ttp_weights": {
            EventType.PORT_SCAN:           0.85,
            EventType.CREDENTIAL_EXPOSURE: 0.9,
            EventType.PROTOCOL_MISUSE:     0.8,
            EventType.DNS_ANOMALY:         0.65,
            EventType.C2_BEACON:           0.7,
        },
        "phases": {"Reconnaissance", "Exploitation"},
        "icon": "🐼",
        "color": "#cc6600",
    },
    {
        "name":        "Scattered Spider",
        "aliases":     ["UNC3944", "Muddled Libra", "Star Fraud", "Oktapus"],
        "origin":      "Western (Criminal / English-speaking)",
        "mitre_group": "G1015",
        "motivation":  "Financial + Data Extortion",
        "target_sectors": ["Telecom", "BPO", "Hospitality", "Tech"],
        "description": (
            "Sophisticated English-speaking criminal group specializing in "
            "social engineering, SIM swapping, and MFA bypass."
        ),
        "ttp_weights": {
            EventType.BRUTE_FORCE:         0.9,
            EventType.CREDENTIAL_EXPOSURE: 0.85,
            EventType.C2_BEACON:           0.8,
            EventType.JA3_ANOMALY:         0.6,
            EventType.DNS_ANOMALY:         0.55,
        },
        "phases": {"Exploitation", "Command & Control"},
        "icon": "🕷️",
        "color": "#440088",
    },
]
