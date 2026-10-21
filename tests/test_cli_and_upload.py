"""CLI and dashboard-upload tests (previously untested paths)."""

from __future__ import annotations

import io

import pytest

from dashboard.app import app
from src import db
from src.main import main
from tests.make_synthetic_pcaps import generate


@pytest.fixture
def sqlite_only(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "ACTIVE_ENGINE", "sqlite")
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(db, "DEFAULT_SQLITE_PATH", tmp_path / "t.db")
    monkeypatch.setattr("dashboard.app.UPLOAD_DIR", tmp_path)
    monkeypatch.setattr("dashboard.app.PROJECT_ROOT", tmp_path)
    return tmp_path


def test_cli_without_arguments_prints_help(monkeypatch, capsys):
    import sys
    monkeypatch.setattr(sys, "argv", ["bantaynet"])
    assert main() == 1
    assert "usage" in capsys.readouterr().out.lower()


def test_cli_analyze_and_export(sqlite_only, monkeypatch, capsys):
    generate(sqlite_only)
    out_csv = sqlite_only / "out.csv"
    import sys
    monkeypatch.setattr(sys, "argv", ["bantaynet", "--pcap", str(sqlite_only / "portscan.pcap"), "--export", str(out_csv)])
    assert main() == 0
    text = out_csv.read_text()
    assert "port_scan" in text and ",TCP," in text
    assert "BANTAYNET ANALYSIS SUMMARY" in capsys.readouterr().out


def test_cli_clear_db(sqlite_only, monkeypatch, capsys):
    import sys
    monkeypatch.setattr(sys, "argv", ["bantaynet", "--clear-db"])
    assert main() == 0
    assert "cleared" in capsys.readouterr().out.lower()


def test_valid_upload_runs_analysis_and_never_overwrites(sqlite_only):
    generate(sqlite_only)
    data = (sqlite_only / "portscan.pcap").read_bytes()
    app.config["TESTING"] = True
    with app.test_client() as c:
        for _ in range(2):
            res = c.post("/upload", data={"pcap_file": (io.BytesIO(data), "scan.pcap")},
                         content_type="multipart/form-data", follow_redirects=True)
            assert b"Successfully analyzed" in res.data
    saved = [p.name for p in sqlite_only.glob("*_scan.pcap")]
    assert len(saved) == 2  # two uploads, two distinct files
