"""Optional email notification handler for high-severity alerts.

Detect-and-alert only, per project security policy.
Off by default in rules.yaml. Failures in sending notifications are logged
and will never interrupt packet analysis or core alert pipelines.
"""

from __future__ import annotations

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from src.config import NotificationSettings

logger = logging.getLogger("bantaynet.notifier")

SEVERITY_RANKS = {"low": 1, "medium": 2, "high": 3}


def send_alert_email(
    alert: dict[str, Any],
    settings: NotificationSettings | Any | None = None,
) -> bool:
    """Send an email notification for a detected alert if enabled and severity meets threshold."""
    if settings is None:
        from src.config import load_config
        settings = load_config().notifications
    elif hasattr(settings, "notifications"):
        settings = settings.notifications

    if not getattr(settings, "enabled", False):
        return False


    min_rank = SEVERITY_RANKS.get(settings.min_severity.lower(), 3)
    alert_rank = SEVERITY_RANKS.get(str(alert.get("severity", "")).lower(), 1)
    if alert_rank < min_rank:
        return False

    try:
        rule = alert.get("rule", "Unknown Rule")
        severity = str(alert.get("severity", "high")).upper()
        src_ip = alert.get("src_ip", "Unknown")
        dst_ip = alert.get("dst_ip", "-")
        client = alert.get("client_name", "Default")

        msg = MIMEMultipart()
        msg["Subject"] = f"[BantayNet {severity}] {rule} detected from {src_ip} ({client})"
        msg["From"] = settings.sender
        msg["To"] = settings.recipient

        body = (
            f"BantayNet Security Alert Notification\n"
            f"----------------------------------------\n"
            f"Severity:       {severity}\n"
            f"Rule:           {rule}\n"
            f"Client / Site:  {client}\n"
            f"Attacker Host:  {src_ip}\n"
            f"Target Host:    {dst_ip}\n"
            f"Target Port:    {alert.get('dst_port', '-')}\n"
            f"Description:    {alert.get('description', '')}\n"
            f"Timestamp:      {alert.get('detected_at', '')}\n"
            f"Packet Count:   {alert.get('packet_count', 1)}\n\n"
            f"Review this alert immediately in the BantayNet SOC Dashboard.\n"
        )
        msg.attach(MIMEText(body, "plain"))

        password = os.environ.get("BANTAYNET_SMTP_PASSWORD", "")

        server = smtplib.SMTP(settings.smtp_server, settings.smtp_port, timeout=10)
        if settings.use_tls:
            server.starttls()
        if password:
            server.login(settings.sender, password)

        server.send_message(msg)
        server.quit()
        logger.info("Sent alert notification email to %s for %s", settings.recipient, rule)
        return True
    except Exception as exc:
        logger.warning("Could not dispatch alert notification email: %s", exc)
        return False
