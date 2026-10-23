"""Load and validate BantayNet detection rules from YAML.

Every setting has a built-in default, so a rules file only needs to contain the
values you want to change. Unknown keys and invalid values raise ``ConfigError``
with a message naming the offending setting, rather than failing later inside
the detector.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"

SEVERITIES = ("low", "medium", "high")


class ConfigError(ValueError):
    """Raised when the rules file is missing, malformed, or has invalid values."""


@dataclass(frozen=True)
class PortScanRule:
    enabled: bool = True
    severity: str = "high"
    window_seconds: float = 5.0
    distinct_ports: int = 50


@dataclass(frozen=True)
class SlowScanRule:
    enabled: bool = True
    severity: str = "medium"
    window_seconds: float = 300.0
    distinct_ports: int = 20


@dataclass(frozen=True)
class HostSweepRule:
    enabled: bool = True
    severity: str = "medium"
    window_seconds: float = 10.0
    distinct_hosts: int = 50


@dataclass(frozen=True)
class SynBurstRule:
    enabled: bool = True
    severity: str = "high"
    window_seconds: float = 2.0
    syn_count: int = 200


@dataclass(frozen=True)
class SuspiciousFlagsRule:
    enabled: bool = True
    severity: str = "medium"
    null_scan: bool = True
    xmas_scan: bool = True
    fin_only: bool = True


@dataclass(frozen=True)
class CleartextRule:
    enabled: bool = True
    severity: str = "low"
    ports: dict[int, str] = field(
        default_factory=lambda: {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP"}
    )


@dataclass(frozen=True)
class IcmpFloodRule:
    enabled: bool = True
    severity: str = "medium"
    window_seconds: float = 2.0
    echo_requests: int = 100


@dataclass(frozen=True)
class AlertSettings:
    cooldown_seconds: float = 30.0


@dataclass(frozen=True)
class EvidenceSettings:
    enabled: bool = True
    output_dir: str = "evidence"
    max_packets: int = 500


@dataclass(frozen=True)
class DatabaseSettings:
    engine: str = "mysql"
    mysql: dict[str, Any] = field(
        default_factory=lambda: {
            "host": "127.0.0.1",
            "port": 3306,
            "user": "root",
            "password": "",
            "database": "bantaynet_db",
        }
    )
    sqlite: dict[str, Any] = field(default_factory=lambda: {"path": "bantaynet.db"})


@dataclass(frozen=True)
class AllowlistSettings:
    enabled: bool = True
    ips: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Config:
    port_scan: PortScanRule = field(default_factory=PortScanRule)
    slow_scan: SlowScanRule = field(default_factory=SlowScanRule)
    host_sweep: HostSweepRule = field(default_factory=HostSweepRule)
    syn_burst: SynBurstRule = field(default_factory=SynBurstRule)
    suspicious_flags: SuspiciousFlagsRule = field(default_factory=SuspiciousFlagsRule)
    cleartext_protocols: CleartextRule = field(default_factory=CleartextRule)
    icmp_flood: IcmpFloodRule = field(default_factory=IcmpFloodRule)
    allowlist: AllowlistSettings = field(default_factory=AllowlistSettings)
    alerts: AlertSettings = field(default_factory=AlertSettings)
    evidence: EvidenceSettings = field(default_factory=EvidenceSettings)
    database: DatabaseSettings = field(default_factory=DatabaseSettings)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _check_type(section: str, key: str, value: Any, expected: type) -> Any:
    name = f"{section}.{key}"
    if expected is bool:
        if not isinstance(value, bool):
            raise ConfigError(f"{name} must be true or false, got {value!r}")
        return value
    if expected in (int, float):
        # bool is a subclass of int in Python; reject it explicitly.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{name} must be a number, got {value!r}")
        if expected is int and not float(value).is_integer():
            raise ConfigError(f"{name} must be a whole number, got {value!r}")
        if value <= 0:
            raise ConfigError(f"{name} must be greater than 0, got {value!r}")
        return expected(value)
    if expected is str:
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"{name} must be a non-empty string, got {value!r}")
        return value
    if expected is dict:
        if not isinstance(value, dict):
            raise ConfigError(f"{name} must be a mapping, got {value!r}")
        return value
    if expected is list:
        if not isinstance(value, list):
            raise ConfigError(f"{name} must be a list, got {value!r}")
        return [str(v).strip() for v in value if str(v).strip()]
    return value



def _parse_ports(section: str, value: Any) -> dict[int, str]:
    if not isinstance(value, dict) or not value:
        raise ConfigError(f"{section}.ports must be a non-empty mapping of port: name")
    ports: dict[int, str] = {}
    for port, label in value.items():
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ConfigError(f"{section}.ports has invalid port {port!r} (must be 1-65535)")
        ports[port] = str(label)
    return ports


def _build_section(section: str, cls: type, raw: Any) -> Any:
    if raw is None:
        return cls()
    if not isinstance(raw, dict):
        raise ConfigError(f"section '{section}' must be a mapping")

    known = {f.name: f for f in fields(cls)}
    unknown = set(raw) - set(known)
    if unknown:
        raise ConfigError(f"unknown key(s) in '{section}': {', '.join(sorted(map(str, unknown)))}")

    kwargs: dict[str, Any] = {}
    defaults = cls()
    for key, value in raw.items():
        if key == "ports":
            kwargs[key] = _parse_ports(section, value)
        elif key == "severity":
            if value not in SEVERITIES:
                raise ConfigError(f"{section}.severity must be one of {SEVERITIES}, got {value!r}")
            kwargs[key] = value
        else:
            kwargs[key] = _check_type(section, key, value, type(getattr(defaults, key)))
    return cls(**kwargs)


def load_config(path: str | Path | None = None) -> Config:
    """Load rules from ``path`` (default: rules/rules.yaml) merged over defaults."""
    path = Path(path) if path is not None else DEFAULT_RULES_PATH
    if not path.is_file():
        raise ConfigError(f"rules file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"could not parse {path}: {exc}") from exc

    if raw is None:
        return Config()
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a mapping of rule sections at the top level")

    sections = {f.name: f.default_factory for f in fields(Config)}  # type: ignore[misc]
    unknown = set(raw) - set(sections)
    if unknown:
        raise ConfigError(f"unknown section(s) in {path.name}: {', '.join(sorted(map(str, unknown)))}")

    return Config(**{name: _build_section(name, factory, raw.get(name)) for name, factory in sections.items()})
