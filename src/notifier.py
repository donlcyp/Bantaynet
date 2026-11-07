"""Optional email notification handler for high-severity alerts and 2FA authentication.

Detect-and-alert only, per project security policy.
Supports Gmail SMTP (smtp.gmail.com:587) and standard TLS mail servers.
Failures in sending notifications are logged and handled gracefully with user feedback.
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


def _get_smtp_credentials() -> dict[str, Any]:
    """Retrieve SMTP configuration favoring Gmail settings if configured."""
    gmail_user = (os.environ.get("GMAIL_USER") or os.environ.get("BANTAYNET_SMTP_USER") or "").strip()
    gmail_pass = (os.environ.get("GMAIL_APP_PASSWORD") or os.environ.get("BANTAYNET_SMTP_PASSWORD") or "").strip()
    smtp_server = (os.environ.get("BANTAYNET_SMTP_SERVER") or ("smtp.gmail.com" if gmail_user else "localhost")).strip()
    smtp_port = int(os.environ.get("BANTAYNET_SMTP_PORT") or "587")
    sender = gmail_user or os.environ.get("BANTAYNET_SMTP_SENDER") or "alerts@bantaynet.local"

    return {
        "user": gmail_user,
        "password": gmail_pass,
        "server": smtp_server,
        "port": smtp_port,
        "sender": sender,
        "use_tls": True,
    }


def send_2fa_otp_email(to_email: str, otp_code: str, username: str = "") -> tuple[bool, str]:
    """Dispatch a 6-digit 2FA verification code to the operator's email address via Gmail/SMTP.

    Returns (success: bool, message: str).
    """
    to_email = (to_email or "").strip()
    if not to_email:
        return False, "Recipient email address is missing."

    conf = _get_smtp_credentials()
    if not conf["password"]:
        logger.warning(
            "SMTP credentials not fully configured (GMAIL_APP_PASSWORD/BANTAYNET_SMTP_PASSWORD missing). [Dev/Lab OTP for %s: %s]",
            to_email,
            otp_code,
        )
        return False, "SMTP email service is not configured (GMAIL_APP_PASSWORD missing in environment)."

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[BantayNet SOC] Your Verification Code: {otp_code}"
        msg["From"] = conf["sender"]
        msg["To"] = to_email

        display_user = username or "Security Operator"
        text_content = (
            f"Hello {display_user},\n\n"
            f"Your BantayNet two-factor authentication verification code is:\n\n"
            f"    {otp_code}\n\n"
            f"This code will expire in 10 minutes.\n"
            f"If you did not initiate this sign-in attempt, please notify your SOC Administrator immediately.\n\n"
            f"-- BantayNet Intrusion Alert System\n"
        )

        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; background: #0b1528; border: 1px solid #1e3a5f; border-radius: 8px; color: #f1f5f9;">
          <div style="border-bottom: 1px solid #1e3a5f; padding-bottom: 12px; margin-bottom: 20px;">
            <h2 style="color: #38bdf8; margin: 0; font-size: 1.3rem;">Bantay<span style="color: #ffffff;">Net</span> Authentication</h2>
            <div style="color: #94a3b8; font-size: 0.8rem; margin-top: 4px;">Authorized SOC Operator Verification</div>
          </div>
          <p style="font-size: 0.95rem; color: #cbd5e1;">Hello <strong>{display_user}</strong>,</p>
          <p style="font-size: 0.9rem; color: #94a3b8;">Use the one-time 6-digit security code below to complete your sign-in to the BantayNet SOC Portal:</p>
          <div style="text-align: center; margin: 25px 0;">
            <div style="display: inline-block; letter-spacing: 8px; font-size: 2rem; font-weight: 700; color: #38bdf8; background: #070e1c; padding: 12px 28px; border-radius: 6px; border: 1px solid #0284c7; font-family: monospace;">
              {otp_code}
            </div>
          </div>
          <p style="font-size: 0.8rem; color: #64748b; margin-top: 20px;">
            This security code expires in <strong>10 minutes</strong>. Never share this code with anyone.
          </p>
          <div style="border-top: 1px solid #1e3a5f; padding-top: 14px; margin-top: 25px; font-size: 0.75rem; color: #475569;">
            If you did not attempt to sign in to BantayNet, please contact your SOC Administrator immediately.
          </div>
        </div>
        """

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        server = smtplib.SMTP(conf["server"], conf["port"], timeout=10)
        if conf["use_tls"]:
            server.starttls()
        if conf["user"] and conf["password"]:
            server.login(conf["user"], conf["password"])

        server.send_message(msg)
        server.quit()
        logger.info("Successfully dispatched 2FA OTP email to %s", to_email)
        return True, "Authentication code sent to your email."

    except smtplib.SMTPAuthenticationError as exc:
        err = f"Gmail SMTP authentication failed. Please verify GMAIL_USER and GMAIL_APP_PASSWORD: {exc}"
        logger.error(err)
        return False, "SMTP authentication failed. Please verify Gmail credentials."
    except Exception as exc:
        err = f"Could not send 2FA email: {exc}"
        logger.error(err)
        return False, f"Could not deliver 2FA email: {exc}"


def send_account_created_email(
    to_email: str,
    username: str,
    temp_password: str,
    login_url: str = "",
) -> tuple[bool, str]:
    """Notify a newly created operator account with their initial temporary credentials.

    Returns (success: bool, message: str).
    """
    to_email = (to_email or "").strip()
    if not to_email:
        return False, "Recipient email address is missing."

    conf = _get_smtp_credentials()
    if not conf["password"]:
        logger.warning(
            "SMTP not configured; cannot email credentials for '%s' to %s (temp password: %s)",
            username,
            to_email,
            temp_password,
        )
        return False, "SMTP email service is not configured (GMAIL_APP_PASSWORD missing)."

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[BantayNet SOC] Welcome - Your Operator Account Details"
        msg["From"] = conf["sender"]
        msg["To"] = to_email

        portal_link = login_url or "http://localhost:5000/login"
        text_content = (
            f"Hello {username},\n\n"
            f"Your BantayNet SOC operator account has been created.\n\n"
            f"Account Details:\n"
            f"----------------------------------------\n"
            f"Username:           {username}\n"
            f"Temporary Password: {temp_password}\n"
            f"Portal URL:         {portal_link}\n\n"
            f"IMPORTANT SECURITY NOTICE:\n"
            f"As a first-time operator, the system requires that you change this temporary password\n"
            f"immediately upon your first login.\n\n"
            f"-- BantayNet Security Operations Team\n"
        )

        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 540px; margin: 0 auto; padding: 24px; background: #0b1528; border: 1px solid #1e3a5f; border-radius: 8px; color: #f1f5f9;">
          <div style="border-bottom: 1px solid #1e3a5f; padding-bottom: 12px; margin-bottom: 20px;">
            <h2 style="color: #38bdf8; margin: 0; font-size: 1.3rem;">Bantay<span style="color: #ffffff;">Net</span> Operator Welcome</h2>
            <div style="color: #94a3b8; font-size: 0.8rem; margin-top: 4px;">Security Operations Center Access</div>
          </div>
          <p style="font-size: 0.95rem; color: #cbd5e1;">Welcome to the SOC team, <strong>{username}</strong>!</p>
          <p style="font-size: 0.9rem; color: #94a3b8;">Your account has been provisioned. Use the temporary credentials below to sign in:</p>
          <div style="background: #070e1c; border: 1px solid #1e3a5f; border-radius: 6px; padding: 16px; margin: 20px 0; font-family: monospace; font-size: 0.9rem;">
            <div style="margin-bottom: 8px;"><span style="color: #94a3b8;">Username:</span> <strong style="color: #38bdf8;">{username}</strong></div>
            <div><span style="color: #94a3b8;">Temporary Password:</span> <strong style="color: #f59e0b;">{temp_password}</strong></div>
          </div>
          <div style="background: rgba(245, 158, 11, 0.1); border-left: 3px solid #f59e0b; padding: 12px; margin-bottom: 20px; font-size: 0.82rem; color: #fde68a;">
            <strong>Mandatory First-Time Password Setup:</strong><br>
            Per cybersecurity policy, you will be prompted to replace this temporary password with a secure permanent passphrase immediately after signing in.
          </div>
          <div style="text-align: center; margin: 25px 0;">
            <a href="{portal_link}" style="display: inline-block; background: #0284c7; color: #ffffff; text-decoration: none; padding: 10px 24px; border-radius: 6px; font-weight: 600; font-size: 0.9rem;">
              Sign In to BantayNet Portal &rarr;
            </a>
          </div>
          <div style="border-top: 1px solid #1e3a5f; padding-top: 14px; margin-top: 25px; font-size: 0.75rem; color: #475569;">
            This email was sent automatically by the BantayNet Security Operations Platform.
          </div>
        </div>
        """

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        server = smtplib.SMTP(conf["server"], conf["port"], timeout=10)
        if conf["use_tls"]:
            server.starttls()
        if conf["user"] and conf["password"]:
            server.login(conf["user"], conf["password"])

        server.send_message(msg)
        server.quit()
        logger.info("Successfully sent welcome email to %s for user '%s'", to_email, username)
        return True, "Welcome email with temporary credentials delivered successfully."

    except Exception as exc:
        err = f"Could not send account creation email: {exc}"
        logger.error(err)
        return False, err


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

