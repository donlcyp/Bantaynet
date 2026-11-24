"""Central dispatch mechanism for BantayNet alert integrations.

Integrations are outbound only, off by default, and isolated so that a failure
in one integration never stops or prevents execution of the others.
"""

from __future__ import annotations

import logging
from typing import Any

import src.config
from src.config import Config
from src.notifier import send_alert_email

logger = logging.getLogger("bantaynet.integrations")


def _normalize_alert(alert: Any, client_name: str = "Default") -> dict[str, Any]:
    """Convert an Alert object or dict into a standard dictionary format."""
    if hasattr(alert, "to_dict"):
        d = alert.to_dict()
        d["src_ip"] = getattr(alert, "src", d.get("src", "Unknown"))
        d["dst_ip"] = getattr(alert, "dst", d.get("dst", "-"))
        d["description"] = getattr(alert, "summary", d.get("summary", ""))
        d["packet_count"] = getattr(alert, "packet_count", 1)
        d["dst_port"] = getattr(alert, "dst_port", None)
        if hasattr(alert, "first_ts"):
            d["detected_at"] = alert.fmt_ts(alert.first_ts)
    elif isinstance(alert, dict):
        d = dict(alert)
        if "src_ip" not in d and "src" in d:
            d["src_ip"] = d["src"]
        if "dst_ip" not in d and "dst" in d:
            d["dst_ip"] = d["dst"]
        if "description" not in d and "summary" in d:
            d["description"] = d["summary"]
    else:
        d = {"rule": str(alert), "severity": "low", "src_ip": "Unknown"}

    if hasattr(alert, "id"):
        d["id"] = getattr(alert, "id")
        d["alert_id"] = getattr(alert, "id")
    elif isinstance(alert, dict) and "id" in alert:
        d["id"] = alert["id"]
        d["alert_id"] = alert["id"]

    d.setdefault("client_name", client_name)
    return d


def dispatch_email(normalized_alerts: list[dict[str, Any]], cfg: Config) -> int:
    """Dispatch alert emails for alerts meeting configured minimum severity."""
    settings = cfg.notifications
    if not getattr(settings, "enabled", False):
        return 0

    sent_count = 0
    for a in normalized_alerts:
        try:
            if send_alert_email(a, settings=settings):
                sent_count += 1
        except Exception as exc:
            logger.warning("Email notification error for alert %s: %s", a.get("rule"), exc)
    return sent_count


def dispatch_telegram(normalized_alerts: list[dict[str, Any]], cfg: Config) -> int:
    """Dispatch alerts to Telegram if enabled (T3)."""
    try:
        from src.integrations.telegram import send_telegram_alert
        return send_telegram_alert(normalized_alerts, cfg)
    except ImportError:
        return 0
    except Exception as exc:
        logger.warning("Telegram dispatch error: %s", exc)
        return 0


def dispatch_abuseipdb(normalized_alerts: list[dict[str, Any]], cfg: Config) -> int:
    """Check and update IP reputation via AbuseIPDB if enabled (T4)."""
    try:
        from src.integrations.abuseipdb import check_abuseipdb_alerts
        return check_abuseipdb_alerts(normalized_alerts, cfg)
    except ImportError:
        return 0
    except Exception as exc:
        logger.warning("AbuseIPDB dispatch error: %s", exc)
        return 0


def dispatch(
    alerts: list[Any],
    client_name: str = "Default",
    cfg: Config | None = None,
) -> dict[str, Any]:
    """Execute all configured notification and threat intelligence integrations independently.

    Guarantees that a failure in one integration never stops or affects the others.
    """
    if not alerts:
        return {"email": 0, "telegram": 0, "abuseipdb": 0}

    if cfg is None:
        try:
            cfg = src.config.load_config()
        except Exception as exc:
            logger.warning("Failed to load config for integrations dispatch: %s", exc)
            return {"email": 0, "telegram": 0, "abuseipdb": 0}

    normalized = [_normalize_alert(a, client_name) for a in alerts]
    results: dict[str, int] = {}

    # 1. Email notifications
    try:
        results["email"] = dispatch_email(normalized, cfg)
    except Exception as exc:
        logger.warning("Email integration failed: %s", exc)
        results["email"] = 0

    # 2. Telegram notifications
    try:
        results["telegram"] = dispatch_telegram(normalized, cfg)
    except Exception as exc:
        logger.warning("Telegram integration failed: %s", exc)
        results["telegram"] = 0

    # 3. AbuseIPDB reputation check
    try:
        results["abuseipdb"] = dispatch_abuseipdb(normalized, cfg)
    except Exception as exc:
        logger.warning("AbuseIPDB integration failed: %s", exc)
        results["abuseipdb"] = 0

    return results

