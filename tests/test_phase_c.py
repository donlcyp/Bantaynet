"""Unit and integration tests for Phase C features:
- User roles (Admin, Analyst, Viewer)
- Password hashing & credentials verification
- Database persistence & default accounts seeding
- Flask authentication, sessions, and role-based access control (RBAC)
"""

from __future__ import annotations

from pathlib import Path
import pytest

from dashboard.app import app
import src.db as db_mod
from src.db import (
    authenticate_user,
    create_user,
    delete_user,
    get_all_users,
    get_user_by_id,
    init_db,
    insert_alert,
    update_user_role,
)


@pytest.fixture
def auth_db(tmp_path: Path, monkeypatch):
    test_db = tmp_path / "test_phase_c.db"
    monkeypatch.setattr(db_mod, "ACTIVE_ENGINE", "sqlite")
    monkeypatch.setattr(db_mod, "DEFAULT_SQLITE_PATH", test_db)
    monkeypatch.setattr(db_mod, "DB_PATH", test_db)
    init_db(test_db)
    yield test_db


def test_default_seeded_users(auth_db: Path):
    """Verify admin, analyst, and viewer default accounts are seeded."""
    users = get_all_users(db_path=auth_db)
    usernames = {u["username"] for u in users}
    assert "admin" in usernames
    assert "analyst" in usernames
    assert "viewer" in usernames

    # Check authentication with default credentials
    admin_user = authenticate_user("admin", "admin123!", db_path=auth_db)
    assert admin_user is not None
    assert admin_user["role"] == "admin"

    analyst_user = authenticate_user("analyst", "analyst123!", db_path=auth_db)
    assert analyst_user is not None
    assert analyst_user["role"] == "analyst"

    viewer_user = authenticate_user("viewer", "viewer123!", db_path=auth_db)
    assert viewer_user is not None
    assert viewer_user["role"] == "viewer"


def test_user_crud_and_validation(auth_db: Path):
    """Test creating, updating, and deleting users with validation."""
    uid = create_user("new_soc_user", "SecurePass999!", "analyst", db_path=auth_db)
    user = get_user_by_id(uid, db_path=auth_db)
    assert user is not None
    assert user["username"] == "new_soc_user"
    assert user["role"] == "analyst"

    # Reject duplicate username
    with pytest.raises(ValueError, match="already exists"):
        create_user("new_soc_user", "AnotherPass!", "viewer", db_path=auth_db)

    # Reject invalid role
    with pytest.raises(ValueError, match="Invalid role"):
        create_user("invalid_role_user", "Pass!", "superhero", db_path=auth_db)

    # Update role
    update_user_role(uid, "admin", db_path=auth_db)
    updated = get_user_by_id(uid, db_path=auth_db)
    assert updated["role"] == "admin"

    # Delete user
    assert delete_user(uid, db_path=auth_db) is True
    assert get_user_by_id(uid, db_path=auth_db) is None


def test_unauthenticated_redirect(auth_db: Path):
    """Unauthenticated users must be redirected to /login."""
    app.config["TESTING"] = True
    app.config["FORCE_AUTH_TESTING"] = True

    with app.test_client() as client:
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


def test_login_flow(auth_db: Path):
    """Test logging in with valid and invalid credentials."""
    app.config["TESTING"] = True
    app.config["FORCE_AUTH_TESTING"] = True

    with app.test_client() as client:
        # Invalid credentials
        res_fail = client.post("/login", data={"username": "admin", "password": "wrongpassword"})
        assert res_fail.status_code == 200
        assert b"Invalid username or password" in res_fail.data

        # Valid credentials
        res_ok = client.post("/login", data={"username": "admin", "password": "admin123!"}, follow_redirects=True)
        assert res_ok.status_code == 200
        assert b"Logged in successfully" in res_ok.data

        # Logout
        res_logout = client.get("/logout", follow_redirects=True)
        assert res_logout.status_code == 200
        assert b"signed out" in res_logout.data


def test_role_based_access_control(auth_db: Path):
    """Test RBAC restrictions across Viewer, Analyst, and Admin."""
    aid = insert_alert(
        rule="port_scan",
        severity="high",
        src_ip="192.168.1.5",
        dst_ip="192.168.1.1",
        packet_time="2026-10-23T12:00:00",
        description="Port scan test alert",
        db_path=auth_db,
    )

    app.config["TESTING"] = True
    app.config["FORCE_AUTH_TESTING"] = True

    # 1. Test as Viewer
    with app.test_client() as viewer_client:
        viewer_client.post("/login", data={"username": "viewer", "password": "viewer123!"})

        # Can view dashboard and alert detail
        res_view = viewer_client.get(f"/alert/{aid}")
        assert res_view.status_code == 200
        assert b"Read-only view" in res_view.data

        # Cannot triage alert
        res_triage = viewer_client.post(
            f"/alert/{aid}/status",
            data={"status": "resolved", "analyst_note": "Triage attempt"},
            follow_redirects=True,
        )
        assert b"Access restricted" in res_triage.data

        # Cannot access user administration
        res_users = viewer_client.get("/users", follow_redirects=True)
        assert b"Access restricted" in res_users.data

    # 2. Test as Analyst
    with app.test_client() as analyst_client:
        analyst_client.post("/login", data={"username": "analyst", "password": "analyst123!"})

        # Can triage alert
        res_triage = analyst_client.post(
            f"/alert/{aid}/status",
            data={"status": "resolved", "analyst_note": "Analyst verified benign"},
            follow_redirects=True,
        )
        assert b"Alert #" in res_triage.data
        assert b"Resolved" in res_triage.data

        # Cannot access user administration
        res_admin = analyst_client.get("/users", follow_redirects=True)
        assert b"Access restricted" in res_admin.data

    # 3. Test as Admin
    with app.test_client() as admin_client:
        admin_client.post("/login", data={"username": "admin", "password": "admin123!"})

        # Can access user administration
        res_admin = admin_client.get("/users")
        assert res_admin.status_code == 200
        assert b"User &amp; Role" in res_admin.data or b"User & Role" in res_admin.data
        assert b"Configured Operators" in res_admin.data

        # Can create user
        res_add = admin_client.post(
            "/users/add",
            data={"username": "operator2", "password": "Password123!", "role": "analyst"},
            follow_redirects=True,
        )
        assert b"created successfully" in res_add.data
