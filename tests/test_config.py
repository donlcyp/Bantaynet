"""Tests for src.config."""

from __future__ import annotations

import pytest

from src.config import Config, ConfigError, load_config


def write(tmp_path, text: str):
    p = tmp_path / "rules.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_shipped_rules_file_loads():
    cfg = load_config()
    assert cfg.port_scan.distinct_ports == 50
    assert cfg.syn_burst.window_seconds == 2.0
    assert cfg.cleartext_protocols.ports[23] == "Telnet"
    assert 80 not in cfg.cleartext_protocols.ports


def test_empty_file_gives_defaults(tmp_path):
    assert load_config(write(tmp_path, "")) == Config()


def test_partial_override_keeps_other_defaults(tmp_path):
    cfg = load_config(write(tmp_path, "port_scan:\n  distinct_ports: 10\n"))
    assert cfg.port_scan.distinct_ports == 10
    assert cfg.port_scan.window_seconds == 5.0
    assert cfg.icmp_flood == Config().icmp_flood


def test_int_accepted_for_float_setting(tmp_path):
    cfg = load_config(write(tmp_path, "syn_burst:\n  window_seconds: 3\n"))
    assert cfg.syn_burst.window_seconds == 3.0


@pytest.mark.parametrize(
    "yaml_text, message",
    [
        ("port_scn:\n  enabled: true\n", "unknown section"),
        ("port_scan:\n  treshold: 5\n", "unknown key"),
        ("port_scan:\n  distinct_ports: 0\n", "greater than 0"),
        ("port_scan:\n  distinct_ports: 2.5\n", "whole number"),
        ("port_scan:\n  distinct_ports: lots\n", "must be a number"),
        ("port_scan:\n  enabled: yes please\n", "true or false"),
        ("port_scan:\n  severity: critical\n", "severity"),
        ("cleartext_protocols:\n  ports:\n    70000: Bad\n", "invalid port"),
        ("- just\n- a list\n", "mapping"),
        ("port_scan: [1, 2\n", "could not parse"),
    ],
)
def test_invalid_values_rejected(tmp_path, yaml_text, message):
    with pytest.raises(ConfigError, match=message):
        load_config(write(tmp_path, yaml_text))


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.yaml")
