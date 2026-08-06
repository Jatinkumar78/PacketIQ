"""
MITRE ATT&CK Navigator layer export.

Produces a real ATT&CK Navigator (v4.5 / layer format 4.5) JSON layer from the
techniques PacketIQ actually detected, so analysts can open the coverage in the
official Navigator (https://mitre-attack.github.io/attack-navigator/). Techniques
are scored by how many findings mapped to them and coloured by peak severity.
Nothing is invented — only techniques tied to real detections are emitted.
"""

from __future__ import annotations

from packetiq.correlation.mitre import techniques_for_event

# tactic display name -> ATT&CK Navigator tactic shortname
_TACTIC_SHORTNAME = {
    "Reconnaissance": "reconnaissance",
    "Resource Development": "resource-development",
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command & Control": "command-and-control",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
}

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_SEV_COLOR = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6"}


def _sev_value(ev) -> str:
    if isinstance(ev, dict):
        return str(ev.get("severity", "LOW"))
    s = getattr(ev, "severity", None)
    value = getattr(s, "value", None)
    return str(value) if value is not None else str(s or "LOW")


def _techs(ev):
    """Yield (technique_id, technique_name, tactic_name) for an event object OR
    a serialized event dict (which already carries its mitre mapping)."""
    if isinstance(ev, dict):
        for t in ev.get("mitre", []) or []:
            yield t.get("id", ""), t.get("name", ""), t.get("tactic", "")
    else:
        for t in techniques_for_event(ev.event_type):
            yield t.technique_id, t.technique_name, t.tactic_name


def coverage(events: list) -> list:
    """
    Aggregate detected techniques for the in-GUI matrix.
    Accepts DetectionEvent objects or serialized event dicts.
    Returns a list of dicts: {id, name, tactic, count, severity}.
    """
    agg: dict = {}
    for ev in events or []:
        sev = _sev_value(ev)
        for tid, tname, tactic in _techs(ev):
            if not tid:
                continue
            key = (tid, tactic)
            cur = agg.get(key)
            if cur is None:
                agg[key] = {"id": tid, "name": tname, "tactic": tactic,
                            "count": 1, "severity": sev}
            else:
                cur["count"] += 1
                if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(cur["severity"], 0):
                    cur["severity"] = sev
    out = list(agg.values())
    out.sort(key=lambda x: (-_SEV_RANK.get(x["severity"], 0), -x["count"], x["id"]))
    return out


def build_layer(events: list, name: str = "PacketIQ Coverage",
                description: str = "") -> dict:
    """Build a MITRE ATT&CK Navigator layer (format 4.5) from real detections."""
    techniques = []
    for c in coverage(events):
        short = _TACTIC_SHORTNAME.get(c["tactic"])
        entry = {
            "techniqueID": c["id"],
            "score": c["count"],
            "color": _SEV_COLOR.get(c["severity"], "#3b82f6"),
            "comment": f"{c['count']} PacketIQ finding(s) · peak severity {c['severity']}",
            "enabled": True,
            "metadata": [{"name": "peak_severity", "value": c["severity"]}],
        }
        if short:
            entry["tactic"] = short
        techniques.append(entry)

    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description or "Techniques observed by PacketIQ in this capture (real detections only).",
        "techniques": techniques,
        "gradient": {
            "colors": ["#3b82f6", "#eab308", "#ef4444"],
            "minValue": 0,
            "maxValue": max((t["score"] for t in techniques), default=1),
        },
        "legendItems": [
            {"label": "Critical", "color": _SEV_COLOR["CRITICAL"]},
            {"label": "High", "color": _SEV_COLOR["HIGH"]},
            {"label": "Medium", "color": _SEV_COLOR["MEDIUM"]},
            {"label": "Low", "color": _SEV_COLOR["LOW"]},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#0b0e14",
        "selectTechniquesAcrossTactics": True,
    }
