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
import socket
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
    smtp_server = (
        os.environ.get("BANTAYNET_SMTP_SERVER")
        or ("smtp.gmail.com" if (gmail_user or gmail_pass) else "localhost")
    ).strip()
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


def _connect_smtp(server_host: str, port: int, use_tls: bool = True, timeout: int = 10) -> smtplib.SMTP:
    """Connect to SMTP prioritizing IPv4 addresses to prevent '[Errno 101] Network is unreachable' on Linux/Docker/Render containers."""
    target_host = server_host
    try:
        # Resolve IPv4 specifically to prevent broken IPv6 routing on cloud containers
        addr_info = socket.getaddrinfo(server_host, port, socket.AF_INET, socket.SOCK_STREAM)
        if addr_info:
            target_host = addr_info[0][4][0]
    except Exception:
        target_host = server_host

    if port == 465:
        server = smtplib.SMTP_SSL(target_host, port, timeout=timeout)
        server.ehlo(server_host)
        return server

    try:
        server = smtplib.SMTP(target_host, port, timeout=timeout)
        server.ehlo(server_host)
        if use_tls:
            server.starttls()
            server.ehlo(server_host)
        return server
    except (OSError, socket.error) as exc:
        if ("gmail.com" in server_host.lower()) and port != 465:
            logger.info("SMTP port %s unreachable (%s); attempting Gmail SSL fallback on port 465...", port, exc)
            return _connect_smtp(server_host, 465, use_tls=False, timeout=timeout)
        raise


def _send_via_mailtrap_api(
    to_email: str,
    subject: str,
    html_content: str,
    text_content: str,
    sender: str = "",
) -> tuple[bool, str] | None:
    """Send email via Mailtrap HTTPS REST API (port 443) if MAILTRAP_API_TOKEN is configured.

    Supports both Mailtrap Sending API (for verified/demo domains) and Mailtrap Sandbox API
    (for automated testing, dummy .corp/.local domains, and dev environments).
    Render free tier blocks SMTP ports (25, 465, 587), but port 443 (HTTPS) is never blocked.
    Returns None if MAILTRAP_API_TOKEN is not configured.
    """
    api_token = (
        os.environ.get("MAILTRAP_API_TOKEN")
        or os.environ.get("MAILTRAP_TOKEN")
        or ""
    ).strip()
    if not api_token:
        return None

    import json
    import urllib.error
    import urllib.request
    from email.utils import parseaddr

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
        "User-Agent": "BantayNet-SOC/1.0 (Windows NT 10.0; Win64; x64)",
    }

    raw_from = (
        os.environ.get("MAILTRAP_FROM_EMAIL")
        or sender
        or "BantayNet SOC <hello@demomailtrap.co>"
    )
    from_name, from_addr = parseaddr(raw_from)
    if not from_addr or "@" not in from_addr:
        from_addr = "hello@demomailtrap.co"
    if not from_name:
        from_name = "BantayNet SOC"

    inbox_id = (os.environ.get("MAILTRAP_INBOX_ID") or "5007832").strip()
    force_sandbox = os.environ.get("MAILTRAP_USE_SANDBOX", "").lower() in ("1", "true", "yes")
    is_fictitious = any(
        to_email.lower().endswith(suffix)
        for suffix in (".corp", ".local", ".test", ".internal", "@example.com")
    )

    # 1. Attempt live sending if not forcing sandbox and not using internal dummy domain
    if not force_sandbox and not is_fictitious:
        payload = {
            "from": {"email": from_addr, "name": from_name},
            "to": [{"email": to_email}],
            "subject": subject,
            "text": text_content,
            "html": html_content,
        }
        req = urllib.request.Request(
            "https://send.api.mailtrap.io/api/send",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                logger.info("Dispatched email to %s via Mailtrap Sending API", to_email)
                return True, "Email dispatched successfully via Mailtrap."
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="ignore")
            logger.warning("Mailtrap Sending API returned HTTP %s: %s; falling back to Sandbox...", exc.code, err_body)
        except Exception as exc:
            logger.warning("Mailtrap Sending API connection failed: %s; falling back to Sandbox...", exc)

    # 2. Sandbox delivery fallback (Email Testing: safe, no bounces, captured in web inbox)
    sandbox_payload = {
        "from": {"email": from_addr, "name": from_name},
        "to": [{"email": to_email}],
        "subject": subject,
        "text": text_content,
        "html": html_content,
    }
    sandbox_req = urllib.request.Request(
        f"https://sandbox.api.mailtrap.io/api/send/{inbox_id}",
        data=json.dumps(sandbox_payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(sandbox_req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            logger.info("Captured email to %s in Mailtrap Sandbox (Inbox %s)", to_email, inbox_id)
            return True, f"Email delivered to Mailtrap Sandbox (Inbox {inbox_id}). Check your Mailtrap dashboard."
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="ignore")
        logger.error("Mailtrap Sandbox HTTP %s: %s", exc.code, err_body)
        return False, f"Mailtrap API error ({exc.code}): {err_body}"
    except Exception as exc:
        logger.error("Mailtrap delivery failed: %s", exc)
        return False, f"Mailtrap delivery failed: {exc}"


def _send_via_https_api(
    to_email: str,
    subject: str,
    html_content: str,
    text_content: str,
    sender: str = "",
) -> tuple[bool, str] | None:
    """Send email via Mailtrap or Resend HTTPS REST API (port 443).

    Render free tier blocks all outbound SMTP ports (25, 465, 587). Port 443 (HTTPS)
    is never blocked. Returns None if neither HTTPS API is configured.
    """
    # Priority 1: Mailtrap HTTPS API
    mailtrap_res = _send_via_mailtrap_api(to_email, subject, html_content, text_content, sender)
    if mailtrap_res is not None:
        return mailtrap_res

    # Priority 2: Resend HTTPS API
    api_key = (os.environ.get("RESEND_API_KEY") or "").strip()
    if not api_key:
        return None

    import json
    import urllib.error
    import urllib.request

    from_email = (
        sender
        or os.environ.get("RESEND_FROM_EMAIL")
        or "BantayNet SOC <onboarding@resend.dev>"
    )

    payload = {
        "from": from_email,
        "to": [to_email],
        "subject": subject,
        "html": html_content,
        "text": text_content,
    }

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "BantayNet-SOC/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            logger.info("Dispatched email to %s via Resend HTTPS API (id: %s)", to_email, data.get("id"))
            return True, "Email dispatched successfully via HTTPS API."
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="ignore")
        logger.error("Resend API HTTP %s: %s", exc.code, err_body)
        return False, f"HTTPS Email API error ({exc.code}): {err_body}"
    except Exception as exc:
        logger.error("Resend API failed: %s", exc)
        return False, f"HTTPS Email API failed: {exc}"


def send_2fa_otp_email(to_email: str, otp_code: str, username: str = "") -> tuple[bool, str]:
    """Dispatch a 6-digit 2FA verification code to the operator's email address via Mailtrap, Resend, or SMTP.

    Returns (success: bool, message: str).
    """
    to_email = (to_email or "").strip()
    if not to_email:
        return False, "Recipient email address is missing."

    conf = _get_smtp_credentials()
    has_https_api = bool(
        (os.environ.get("MAILTRAP_API_TOKEN") or os.environ.get("MAILTRAP_TOKEN") or "").strip()
        or (os.environ.get("RESEND_API_KEY") or "").strip()
    )

    if not conf["password"] and not has_https_api:
        logger.warning(
            "Email credentials not configured (MAILTRAP_API_TOKEN / GMAIL_APP_PASSWORD missing). [Dev/Lab OTP for %s: %s]",
            to_email,
            otp_code,
        )
        return False, "Email service is not configured (set MAILTRAP_API_TOKEN or GMAIL_APP_PASSWORD)."

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

        # Priority 1: Check HTTPS REST API (Port 443 - works on Render free tier)
        api_res = _send_via_https_api(to_email, msg["Subject"], html_content, text_content, conf["sender"])
        if api_res is not None:
            return api_res

        server = _connect_smtp(conf["server"], conf["port"], use_tls=conf["use_tls"], timeout=10)
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
    has_https_api = bool(
        (os.environ.get("MAILTRAP_API_TOKEN") or os.environ.get("MAILTRAP_TOKEN") or "").strip()
        or (os.environ.get("RESEND_API_KEY") or "").strip()
    )

    if not conf["password"] and not has_https_api:
        logger.warning(
            "Email credentials not configured; cannot email credentials for '%s' to %s (temp password: %s)",
            username,
            to_email,
            temp_password,
        )
        return False, "Email service is not configured (set MAILTRAP_API_TOKEN or GMAIL_APP_PASSWORD)."

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

        # Priority 1: Check HTTPS REST API (Port 443 - works on Render free tier)
        api_res = _send_via_https_api(to_email, msg["Subject"], html_content, text_content, conf["sender"])
        if api_res is not None:
            return api_res

        server = _connect_smtp(conf["server"], conf["port"], use_tls=conf["use_tls"], timeout=10)
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

        # Check HTTPS REST API first if configured and no explicit custom SMTP server is defined
        if settings.smtp_server in ("localhost", "smtp.gmail.com") and (
            os.environ.get("MAILTRAP_API_TOKEN") or os.environ.get("MAILTRAP_TOKEN") or os.environ.get("RESEND_API_KEY")
        ):
            api_res = _send_via_https_api(
                settings.recipient,
                msg["Subject"],
                f"<pre style=\"font-family: monospace; background: #070e1c; color: #f1f5f9; padding: 16px; border-radius: 6px;\">{body}</pre>",
                body,
                settings.sender,
            )
            if api_res is not None and api_res[0]:
                logger.info("Sent alert notification email to %s for %s via HTTPS API", settings.recipient, rule)
                return True

        conf = _get_smtp_credentials()
        smtp_server = settings.smtp_server if settings.smtp_server != "localhost" else (conf["server"] or "localhost")
        smtp_port = settings.smtp_port if settings.smtp_port != 587 else (conf["port"] or 587)
        sender = settings.sender if settings.sender != "alerts@bantaynet.local" else conf["sender"]
        password = conf["password"] or os.environ.get("BANTAYNET_SMTP_PASSWORD", "")

        server = _connect_smtp(smtp_server, smtp_port, use_tls=settings.use_tls, timeout=10)
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

    # Priority 1: Check HTTPS REST API if configured (Mailtrap or Resend)
    has_https_api = bool(
        (os.environ.get("MAILTRAP_API_TOKEN") or os.environ.get("MAILTRAP_TOKEN") or "").strip()
        or (os.environ.get("RESEND_API_KEY") or "").strip()
    )
    if has_https_api:
        api_res = _send_via_https_api(
            to_email,
            "[BantayNet SOC] HTTPS Email Delivery Test",
            """<div style="font-family: Arial, sans-serif; max-width: 520px; padding: 20px; background: #0b1528; border: 1px solid #1e3a5f; border-radius: 8px; color: #f1f5f9;">
              <h2 style="color: #38bdf8; margin: 0 0 10px 0;">Bantay<span style="color: #ffffff;">Net</span> &bull; Cloud Email Verified</h2>
              <p style="color: #10b981; font-weight: bold; margin: 0 0 10px 0;">✓ HTTPS Email API Connection Successful</p>
              <p style="color: #94a3b8; font-size: 0.9rem;">Email delivery over HTTPS (Port 443) is fully operational for Render and cloud hosting.</p>
            </div>""",
            "BantayNet HTTPS Email API connection successful. Cloud email delivery is operational.",
        )
        if api_res is not None:
            return api_res

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

        server = _connect_smtp(conf["server"], conf["port"], use_tls=conf["use_tls"], timeout=15)
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

