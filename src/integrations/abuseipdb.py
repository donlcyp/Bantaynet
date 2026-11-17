"""AbuseIPDB IP reputation integration for BantayNet.

Checks public source IP addresses against the AbuseIPDB v2 API:
- Outbound only (HTTPS GET).
- Off by default (enabled via rules.yaml: integrations.abuseipdb.enabled).
- Secret API key read from ABUSEIPDB_API_KEY environment variable.
- Private, loopback, and reserved addresses are skipped and labeled 'Internal address'.
- Lookups are cached per IP for cache_hours to protect the daily quota.
- Failures (quota exceeded, network timeout, bad key) log a warning and leave fields empty.
- Detect-and-alert only: never blocks or scans.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import src.config
from src.config import Config
from src.db import update_alert_reputation

logger = logging.getLogger("bantaynet.integrations.abuseipdb")

_CACHE_LOCK = threading.Lock()
# Mapping: ip_str -> (timestamp, score, note)
_REPUTATION_CACHE: dict[str, tuple[float, int | None, str | None]] = {}


def clear_cache() -> None:
    """Clear the in-memory IP reputation cache (useful for testing)."""
    with _CACHE_LOCK:
        _REPUTATION_CACHE.clear()


def is_public_ip(ip_str: str | None) -> tuple[bool, str]:
    """Check if an IP is a valid public/global IPv4 or IPv6 address.

    Returns:
        (is_public, label): (True, 'Public address') or (False, 'Internal address')
    """
    clean = (ip_str or "").strip()
    if not clean or clean.lower() in ("unknown", "-", "n/a", "none"):
        return False, "Internal address"
    try:
        obj = ipaddress.ip_address(clean)
    except ValueError:
        return False, "Internal address"

    if not obj.is_global:
        return False, "Internal address"
    return True, "Public address"


def check_ip_reputation(
    ip: str,
    api_key: str | None = None,
    max_age_days: int = 90,
    cache_hours: int = 24,
    timeout: float = 5.0,
) -> tuple[int | None, str | None]:
    """Look up IP reputation in cache or via AbuseIPDB API.

    Returns:
        (score, note): score is integer 0-100 (or None if unrated/internal),
                       note is a descriptive summary string.
    """
    is_pub, label = is_public_ip(ip)
    if not is_pub:
        return None, label

    if not api_key:
        api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()

    if not api_key:
        # Per spec: No key means silent skip
        return None, None

    now = time.time()
    ttl_seconds = max(1, int(cache_hours)) * 3600
    with _CACHE_LOCK:
        if ip in _REPUTATION_CACHE:
            cached_time, cached_score, cached_note = _REPUTATION_CACHE[ip]
            if now - cached_time < ttl_seconds:
                return cached_score, cached_note

    clean_ip = ip.strip()
    url = (
        f"https://api.abuseipdb.com/api/v2/check?"
        f"ipAddress={urllib.parse.quote(clean_ip)}&maxAgeInDays={int(max_age_days)}"
    )

    req = urllib.request.Request(
        url,
        headers={
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": "BantayNet-SOC/1.0",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            data = json.loads(body).get("data", {})
            score = data.get("abuseConfidenceScore")
            total_reports = data.get("totalReports", 0)
            country = data.get("countryCode") or "Unknown"

            note = f"Score: {score}% | {total_reports} reports | {country}"
            with _CACHE_LOCK:
                _REPUTATION_CACHE[clean_ip] = (now, score, note)
            return score, note
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            logger.warning("AbuseIPDB quota exceeded (HTTP 429) checking %s", clean_ip)
        elif exc.code in (401, 403):
            logger.warning("AbuseIPDB authentication failed (HTTP %d) checking %s", exc.code, clean_ip)
        else:
            logger.warning("AbuseIPDB HTTP %d error checking %s: %s", exc.code, clean_ip, exc)
        return None, None
    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", clean_ip, exc)
        return None, None


def check_abuseipdb_alerts(
    normalized_alerts: list[dict[str, Any]],
    cfg: Config | None = None,
) -> int:
    """Process alert source IPs and persist reputation scores and notes to the database.

    Skips if integration is disabled. Internal/private IPs are labeled 'Internal address'.
    Public IPs are queried with rate-limit and quota caching.
    """
    if not normalized_alerts:
        return 0

    if cfg is None:
        try:
            cfg = src.config.load_config()
        except Exception as exc:
            logger.warning("AbuseIPDB skipped: could not load config: %s", exc)
            return 0

    abuse_cfg = getattr(getattr(cfg, "integrations", None), "abuseipdb", None)
    if not abuse_cfg or not getattr(abuse_cfg, "enabled", False):
        return 0

    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    max_age_days = int(getattr(abuse_cfg, "max_age_days", 90))
    cache_hours = int(getattr(abuse_cfg, "cache_hours", 24))

    processed_count = 0
    for a in normalized_alerts:
        src = a.get("src_ip") or a.get("src", "")
        alert_id = a.get("id") or a.get("alert_id")

        is_pub, label = is_public_ip(src)
        if not is_pub:
            score = None
            note = label
            a["reputation_score"] = score
            a["reputation_note"] = note
            if alert_id:
                try:
                    update_alert_reputation(int(alert_id), score, note)
                except Exception as exc:
                    logger.warning("Failed updating reputation for alert #%s: %s", alert_id, exc)
            processed_count += 1
            continue

        # For public IP:
        if not api_key:
            # Silent skip when no key
            continue

        score, note = check_ip_reputation(
            ip=src,
            api_key=api_key,
            max_age_days=max_age_days,
            cache_hours=cache_hours,
        )

        a["reputation_score"] = score
        a["reputation_note"] = note
        if alert_id and (score is not None or note is not None):
            try:
                update_alert_reputation(int(alert_id), score, note)
            except Exception as exc:
                logger.warning("Failed updating reputation for alert #%s: %s", alert_id, exc)
        processed_count += 1

    return processed_count

