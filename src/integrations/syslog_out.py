"""Syslog and SIEM forwarder for BantayNet security alerts.

Supports Common Event Format (CEF) and JSON over UDP and TCP.
Standard library only (socket), outbound only, off by default, with a 3-second timeout.
Failures are logged as warnings and never interrupt traffic analysis.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from typing import Any

from src.config import Config, load_config
from src.mitre import get_mitre_info

logger = logging.getLogger("bantaynet.integrations.syslog")

SEVERITY_LEVELS: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


def escape_cef_header(value: Any) -> str:
    """Escape backslashes and pipes in CEF header fields."""
    if value is None:
        return ""
    s = str(value)
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def escape_cef_extension(value: Any) -> str:
    """Escape backslashes and equals signs in CEF extension values."""
    if value is None:
        return ""
    s = str(value)
    return s.replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def format_cef_alert(alert: dict[str, Any]) -> str:
    """Format an alert dictionary into ArcSight Common Event Format (CEF:0).

    Template:
    CEF:0|BantayNet|BantayNet|1.0|RULE|NAME|SEVERITY|src=IP dst=IP proto=TCP cs1=MITRE_ID cs1Label=mitre rt=EPOCH_MS
    """
    rule = alert.get("rule", "unknown")
    mitre = get_mitre_info(rule)
    mitre_id = alert.get("mitre_id") or mitre.get("id", "N/A")
    name = alert.get("name") or mitre.get("name") or rule
    severity = alert.get("severity", "low")

    src = alert.get("src_ip") or alert.get("src", "0.0.0.0")
    dst = alert.get("dst_ip") or alert.get("dst", "0.0.0.0")
    proto = alert.get("protocol") or alert.get("proto", "TCP")

    ts = alert.get("first_ts") or alert.get("timestamp") or alert.get("packet_time")
    if isinstance(ts, (int, float)):
        epoch_ms = int(ts * 1000)
    else:
        epoch_ms = int(time.time() * 1000)

    hdr_rule = escape_cef_header(rule)
    hdr_name = escape_cef_header(name)
    hdr_sev = escape_cef_header(severity)

    ext_src = escape_cef_extension(src)
    ext_dst = escape_cef_extension(dst)
    ext_proto = escape_cef_extension(proto)
    ext_cs1 = escape_cef_extension(mitre_id)
    ext_rt = str(epoch_ms)

    extension = f"src={ext_src} dst={ext_dst} proto={ext_proto} cs1={ext_cs1} cs1Label=mitre rt={ext_rt}"
    return f"CEF:0|BantayNet|BantayNet|1.0|{hdr_rule}|{hdr_name}|{hdr_sev}|{extension}"


def format_json_alert(alert: dict[str, Any]) -> str:
    """Format an alert dictionary into a single-line JSON string."""
    rule = alert.get("rule", "unknown")
    mitre = get_mitre_info(rule)
    mitre_id = alert.get("mitre_id") or mitre.get("id", "N/A")
    name = alert.get("name") or mitre.get("name") or rule
    severity = alert.get("severity", "low")

    src = alert.get("src_ip") or alert.get("src", "0.0.0.0")
    dst = alert.get("dst_ip") or alert.get("dst", "0.0.0.0")
    proto = alert.get("protocol") or alert.get("proto", "TCP")

    ts = alert.get("first_ts") or alert.get("timestamp") or alert.get("packet_time")
    if isinstance(ts, (int, float)):
        epoch_ms = int(ts * 1000)
    else:
        epoch_ms = int(time.time() * 1000)

    obj = {
        "device_vendor": "BantayNet",
        "device_product": "BantayNet",
        "device_version": "1.0",
        "rule": rule,
        "name": name,
        "severity": severity,
        "src": src,
        "src_ip": src,
        "dst": dst,
        "dst_ip": dst,
        "proto": proto,
        "protocol": proto,
        "cs1": mitre_id,
        "mitre_id": mitre_id,
        "rt": epoch_ms,
        "timestamp": epoch_ms,
        "client_name": alert.get("client_name", "Default"),
        "summary": alert.get("summary") or alert.get("description", ""),
    }
    return json.dumps(obj)


def _send_udp_messages(host: str, port: int, messages: list[str], timeout: float = 3.0) -> int:
    """Send formatted alert messages as UDP datagrams."""
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    # Prefer IPv4 in dual-stack / localhost environments
    infos.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)

    sent = 0
    sock = None
    for family, socktype, proto, _, sockaddr in infos:
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            for msg in messages:
                sock.sendto(msg.encode("utf-8"), sockaddr)
                sent += 1
            return sent
        except Exception as exc:
            logger.debug("Failed sending to %s via %s: %s", sockaddr, family, exc)
        finally:
            if sock is not None:
                sock.close()
                sock = None

    raise OSError(f"Could not transmit UDP syslog messages to {host}:{port}")


def _send_tcp_messages(host: str, port: int, messages: list[str], timeout: float = 3.0) -> int:
    """Send formatted alert messages over a TCP stream with newline framing."""
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    infos.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)

    sent = 0
    sock = None
    for family, socktype, proto, _, sockaddr in infos:
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            for msg in messages:
                payload = msg.encode("utf-8")
                if not payload.endswith(b"\n"):
                    payload += b"\n"
                sock.sendall(payload)
                sent += 1
            return sent
        except Exception as exc:
            logger.debug("Failed sending to %s via %s: %s", sockaddr, family, exc)
        finally:
            if sock is not None:
                sock.close()
                sock = None

    raise OSError(f"Could not transmit TCP syslog messages to {host}:{port}")


def send_syslog_alerts(
    normalized_alerts: list[dict[str, Any]],
    cfg: Config | None = None,
) -> int:
    """Forward normalized alerts to an external Syslog / SIEM listener.

    Reads configuration from ``cfg.integrations.syslog``. If disabled or no alerts
    meet ``min_severity``, exits immediately.
    Catches all network and socket errors, logs a warning, and returns 0.
    """
    if not normalized_alerts:
        return 0

    if cfg is None:
        try:
            cfg = load_config()
        except Exception as exc:
            logger.warning("Syslog export skipped: could not load config: %s", exc)
            return 0

    syslog_cfg = getattr(getattr(cfg, "integrations", None), "syslog", None)
    if not syslog_cfg or not getattr(syslog_cfg, "enabled", False):
        return 0

    min_sev_str = str(getattr(syslog_cfg, "min_severity", "low")).lower().strip()
    min_sev_rank = SEVERITY_LEVELS.get(min_sev_str, 1)

    qualifying_alerts: list[dict[str, Any]] = []
    for a in normalized_alerts:
        sev_str = str(a.get("severity", "low")).lower().strip()
        sev_rank = SEVERITY_LEVELS.get(sev_str, 1)
        if sev_rank >= min_sev_rank:
            qualifying_alerts.append(a)

    if not qualifying_alerts:
        return 0

    fmt = str(getattr(syslog_cfg, "format", "cef")).lower().strip()
    protocol = str(getattr(syslog_cfg, "protocol", "udp")).lower().strip()
    host = str(getattr(syslog_cfg, "host", "localhost")).strip()
    port = int(getattr(syslog_cfg, "port", 514))

    messages: list[str] = []
    for a in qualifying_alerts:
        if fmt == "json":
            messages.append(format_json_alert(a))
        else:
            messages.append(format_cef_alert(a))

    try:
        if protocol == "tcp":
            count = _send_tcp_messages(host=host, port=port, messages=messages, timeout=3.0)
        else:
            count = _send_udp_messages(host=host, port=port, messages=messages, timeout=3.0)
        logger.info("Forwarded %d alert(s) to Syslog SIEM (%s:%d/%s)", count, host, port, protocol)
        return count
    except Exception as exc:
        logger.warning("Syslog export to %s:%d/%s failed: %s", host, port, protocol, exc)
        return 0

