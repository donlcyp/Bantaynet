"""Pytest configuration and root fixtures for BantayNet test suite."""

import os
import pytest


@pytest.fixture(autouse=True)
def clean_test_environment(monkeypatch):
    """Ensure tests run hermetically regardless of local .env configuration or test order."""
    monkeypatch.setenv("BANTAYNET_ADMIN_PASSWORD", "admin123!")
    monkeypatch.setenv("BANTAYNET_ANALYST_PASSWORD", "analyst123!")
    monkeypatch.setenv("BANTAYNET_VIEWER_PASSWORD", "viewer123!")
    # Disable secure cookies in test runner so session cookies work over plain HTTP test client
    monkeypatch.setenv("BANTAYNET_COOKIE_SECURE", "0")
    from dashboard.app import app
    app.config["FORCE_AUTH_TESTING"] = False
    app.config["FORCE_CSRF_TESTING"] = False
