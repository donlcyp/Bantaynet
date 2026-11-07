"""Optional email notification handler for high-severity alerts and 2FA authentication.

Detect-and-alert only, per project security policy.
Supports Gmail SMTP (smtp.gmail.com:587) and standard TLS mail servers.
Failures in sending notifications are logged and handled gracefully with user feedback.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from src.config import NotificationSettings

# Automatically load environment variables from .env if present
try:
    from dotenv import load_dotenv

    _env_path = Path(__file__).resolve().parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
except ImportError:
    pass

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

        conf = _get_smtp_credentials()
        smtp_server = settings.smtp_server if settings.smtp_server != "localhost" else (conf["server"] or "localhost")
        smtp_port = settings.smtp_port if settings.smtp_port != 587 else (conf["port"] or 587)
        sender = settings.sender if settings.sender != "alerts@bantaynet.local" else conf["sender"]
        password = conf["password"] or os.environ.get("BANTAYNET_SMTP_PASSWORD", "")

        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        if settings.use_tls:
            server.starttls()
        if password and conf["user"]:
            server.login(conf["user"], password)
        elif password:
            server.login(sender, password)

        server.send_message(msg)
        server.quit()
        logger.info("Sent alert notification email to %s for %s", settings.recipient, rule)
        return True
    except Exception as exc:
        logger.warning("Could not dispatch alert notification email: %s", exc)
        return False


def test_smtp_connection(recipient_email: str) -> tuple[bool, str]:
    """Test the SMTP / Gmail configuration and dispatch a test message to recipient_email.

    Returns (success: bool, status_message: str).
    """
    to_email = (recipient_email or "").strip()
    if not to_email:
        return False, "Recipient email address is required."

    conf = _get_smtp_credentials()
    if not conf["password"]:
        return (
            False,
            "SMTP password not found. Please set GMAIL_APP_PASSWORD (for Gmail) or BANTAYNET_SMTP_PASSWORD in your .env file.",
        )
    if not conf["user"]:
        return (
            False,
            "SMTP user not found. Please set GMAIL_USER (for Gmail) or BANTAYNET_SMTP_USER in your .env file.",
        )

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "[BantayNet SOC] Gmail SMTP Integration Test Successful"
        msg["From"] = conf["sender"]
        msg["To"] = to_email

        body_text = (
            "Congratulations! Your BantayNet Gmail SMTP integration is functioning successfully.\n\n"
            f"SMTP Server:  {conf['server']}:{conf['port']}\n"
            f"Sender Email: {conf['sender']}\n"
            f"Recipient:    {to_email}\n\n"
            "This confirms that 2FA security OTPs, password setup notifications, and high-severity "
            "alerts can be delivered to authorized operators via Gmail SMTP.\n\n"
            "-- BantayNet Intrusion Alert System\n"
        )

        body_html = f"""
        <div style="font-family: Arial, sans-serif; max-width: 540px; margin: 0 auto; padding: 24px; background: #0b1528; border: 1px solid #1e3a5f; border-radius: 8px; color: #f1f5f9;">
          <div style="border-bottom: 1px solid #1e3a5f; padding-bottom: 12px; margin-bottom: 20px;">
            <h2 style="color: #38bdf8; margin: 0; font-size: 1.3rem;">Bantay<span style="color: #ffffff;">Net</span> SMTP Verified</h2>
            <div style="color: #94a3b8; font-size: 0.8rem; margin-top: 4px;">Gmail SMTP Integration Test</div>
          </div>
          <div style="padding: 12px 16px; background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; border-radius: 6px; margin-bottom: 16px; color: #34d399; font-weight: 600;">
            ✓ SMTP Connection &amp; TLS Handshake Successful
          </div>
          <p style="font-size: 0.95rem; color: #cbd5e1;">
            Your BantayNet Gmail SMTP integration is properly configured.
          </p>
          <div style="background: #070e1c; padding: 12px 16px; border-radius: 6px; font-size: 0.85rem; font-family: monospace; color: #94a3b8; line-height: 1.6; margin: 16px 0;">
            <div><strong>Server:</strong> {conf['server']}:{conf['port']}</div>
            <div><strong>Sender:</strong> {conf['sender']}</div>
            <div><strong>Recipient:</strong> {to_email}</div>
          </div>
          <p style="font-size: 0.85rem; color: #94a3b8;">
            2FA authentication codes, new operator temporary passwords, and high-severity security alert notifications will now be delivered via Gmail.
          </p>
        </div>
        """

        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        server = smtplib.SMTP(conf["server"], conf["port"], timeout=15)
        if conf["use_tls"]:
            server.starttls()
        server.login(conf["user"], conf["password"])
        server.send_message(msg)
        server.quit()
        return True, f"Success! Verification email successfully delivered to '{to_email}' via Gmail SMTP."
    except smtplib.SMTPAuthenticationError as exc:
        return (
            False,
            f"Gmail SMTP Authentication Failed ({exc.smtp_code}): Please ensure you are using a 16-character Google App Password (not your standard Google account password). Go to: https://myaccount.google.com/apppasswords",
        )
    except Exception as exc:
        return False, f"SMTP Connection failed: {exc}"


if __name__ == "__main__":
    recipient = sys.argv[1] if len(sys.argv) > 1 else None
    if not recipient:
        print("Usage: python -m src.notifier <test_recipient_email>")
        print("Example: python -m src.notifier operator@example.com")
        sys.exit(1)

    print(f"[*] Testing BantayNet Gmail SMTP connection to {recipient}...")
    success, message = test_smtp_connection(recipient)
    if success:
        print(f"[+] {message}")
        sys.exit(0)
    else:
        print(f"[-] {message}")
        sys.exit(1)

