"""MITRE ATT&CK mappings and helper functions for BantayNet detection rules.

Maps each rule to its corresponding ATT&CK technique ID, name, tactic, and official reference URL.
Detect-and-alert only, per project security policy.
"""

from __future__ import annotations

from typing import Any

MITRE_MAPPINGS: dict[str, dict[str, str]] = {
    "port_scan": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "slow_scan": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "suspicious_flags": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "host_sweep": {
        "id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1018/",
    },
    "syn_burst": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "icmp_flood": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "cleartext": {
        "id": "POLICY",
        "name": "Insecure Protocol (Cleartext)",
        "tactic": "Policy Violation",
        "url": "",
    },
}

DEFAULT_MITRE: dict[str, str] = {
    "id": "N/A",
    "name": "Unclassified",
    "tactic": "General",
    "url": "",
}


def get_mitre_info(rule: str | None) -> dict[str, str]:
    """Return a dictionary of MITRE ATT&CK details for a given rule key."""
    if not rule:
        return dict(DEFAULT_MITRE)
    return dict(MITRE_MAPPINGS.get(rule.lower().strip(), DEFAULT_MITRE))


def attach_mitre_info(alert: dict[str, Any]) -> dict[str, Any]:
    """Enrich an alert dictionary with MITRE fields in-place and return it."""
    info = get_mitre_info(alert.get("rule"))
    alert["mitre_id"] = info["id"]
    alert["mitre_name"] = info["name"]
    alert["mitre_tactic"] = info["tactic"]
    alert["mitre_url"] = info["url"]
    if info["id"] not in ("N/A", "POLICY"):
        alert["mitre_tag"] = f"{info['id']}: {info['name']}"
    elif info["id"] == "POLICY":
        alert["mitre_tag"] = "Policy: Cleartext"
    else:
        alert["mitre_tag"] = "Unmapped"
    return alert
