"""Unit tests for the Flask web dashboard."""

from __future__ import annotations

import io
import pytest
from dashboard.app import app
from src.db import init_db, insert_alert


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = tmp_path / "dash_test.db"
    monkeypatch.setattr("src.db.ACTIVE_ENGINE", "sqlite")
    monkeypatch.setattr("src.db.DEFAULT_SQLITE_PATH", test_db)
    monkeypatch.setattr("src.db.DB_PATH", test_db)
    monkeypatch.setattr("dashboard.app.PROJECT_ROOT", tmp_path)
    init_db(test_db)

    insert_alert(
        rule="port_scan",
        severity="high",
        src_ip="10.0.0.66",
        dst_ip="10.0.0.10",
        packet_time=1760000000.0,
        description="Port scan test alert",
        db_path=test_db,
    )

    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def test_index_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"Bantay" in res.data
    assert b"Port scan test alert" in res.data
    assert b"Total Detections" in res.data



def test_alert_detail(client):
    res = client.get("/alert/1")
    assert res.status_code == 200
    assert b"Alert #1" in res.data
    assert b"10.0.0.66" in res.data


def test_alert_not_found(client):
    res = client.get("/alert/999")
    assert res.status_code == 404


def test_export_csv(client):
    res = client.get("/export.csv")
    assert res.status_code == 200
    assert res.content_type.startswith("text/csv")
    assert b"Port scan test alert" in res.data


def test_upload_invalid_extension(client):
    data = {"pcap_file": (io.BytesIO(b"dummy content"), "test.txt")}
    res = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert res.status_code == 200
    assert b"Invalid file type" in res.data
