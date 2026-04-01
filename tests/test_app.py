from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app


def build_test_app(tmp_path):
    database_path = tmp_path / "test.db"
    return create_app(
        {
            "TESTING": True,
            "DATABASE": str(database_path),
            "SECRET_KEY": "test-secret",
        }
    )


def login(client, username, password):
    token = fetch_csrf_token(client, "/login")
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=True,
    )


def fetch_csrf_token(client, path):
    response = client.get(path)
    html = response.data.decode("utf-8")
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def test_login_page_loads(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    response = client.get("/login")

    assert response.status_code == 200
    assert b"Staff Portal" in response.data
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_staff_user_can_log_in_and_see_dashboard(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    response = login(client, "staff", "staff123")

    assert response.status_code == 200
    assert b"Signed in as" in response.data
    assert b"staff" in response.data
    assert b"Implemented Controls" not in response.data


def test_admin_user_sees_security_sections_on_dashboard(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    response = login(client, "admin", "admin123")

    assert response.status_code == 200
    assert b"Security Overview" in response.data
    assert b"Implemented Controls" in response.data


def test_admin_page_requires_admin_role(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    login(client, "staff", "staff123")
    response = client.get("/admin", follow_redirects=True)

    assert response.status_code == 200
    assert b"do not have permission" in response.data.lower()


def test_order_can_be_created(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    login(client, "staff", "staff123")
    token = fetch_csrf_token(client, "/orders")
    response = client.post(
        "/orders",
        data={
            "customer_name": "Amina",
            "item_id": "1",
            "quantity": "2",
            "csrf_token": token,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Order created successfully." in response.data
    assert b"Amina" in response.data


def test_order_detail_enforces_ownership(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    login(client, "staff", "staff123")
    token = fetch_csrf_token(client, "/orders")
    client.post(
        "/orders",
        data={
            "customer_name": "Amina",
            "item_id": "1",
            "quantity": "2",
            "csrf_token": token,
        },
        follow_redirects=True,
    )
    client.get("/logout", follow_redirects=True)

    login(client, "admin", "admin123")
    token = fetch_csrf_token(client, "/orders")
    client.post(
        "/orders",
        data={
            "customer_name": "Bilal",
            "item_id": "2",
            "quantity": "1",
            "csrf_token": token,
        },
        follow_redirects=True,
    )
    client.get("/logout", follow_redirects=True)

    login(client, "staff", "staff123")
    response = client.get("/orders/2", follow_redirects=True)

    assert response.status_code == 200
    assert b"not allowed to view that order" in response.data.lower()


def test_admin_page_shows_audit_logs(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    login(client, "admin", "admin123")
    response = client.get("/admin")

    assert response.status_code == 200
    assert b"Recent Audit Logs" in response.data
    assert b"Recent Failed Login Attempts" in response.data


def test_login_rate_limit_blocks_after_repeated_failures(tmp_path):
    app = build_test_app(
        tmp_path,
    )
    client = app.test_client()

    for _ in range(5):
        token = fetch_csrf_token(client, "/login")
        response = client.post(
            "/login",
            data={
                "username": "staff",
                "password": "wrong-password",
                "csrf_token": token,
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

    token = fetch_csrf_token(client, "/login")
    blocked = client.post(
        "/login",
        data={
            "username": "staff",
            "password": "staff123",
            "csrf_token": token,
        },
        follow_redirects=True,
    )

    assert b"Too many failed login attempts" in blocked.data


def test_successful_login_updates_admin_visibility(tmp_path):
    app = build_test_app(tmp_path)
    client = app.test_client()

    login(client, "staff", "staff123")
    client.get("/logout", follow_redirects=True)
    login(client, "admin", "admin123")
    response = client.get("/admin")

    assert response.status_code == 200
    assert b"Last Login" in response.data
