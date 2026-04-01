from functools import wraps
import os
import secrets
from datetime import timedelta

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from db import (
    count_recent_failed_attempts,
    create_order,
    get_all_orders,
    get_db_connection,
    get_menu_items,
    get_order_by_id,
    get_orders_for_user,
    get_recent_audit_logs,
    get_recent_failed_logins,
    get_security_metrics,
    get_user_by_username,
    init_db,
    record_login_attempt,
    update_last_login,
    write_audit_log,
)


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32)),
        DATABASE=os.path.join(app.instance_path, "restaurant.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_SECURE_COOKIE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_FAILED_LOGINS=5,
        LOGIN_WINDOW_MINUTES=15,
        MIN_PASSWORD_LENGTH=8,
    )

    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    with app.app_context():
        init_db(app.config["DATABASE"])

    @app.before_request
    def load_logged_in_user():
        g.user = session.get("user")
        if g.user is not None:
            session.permanent = True

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        return response

    @app.context_processor
    def inject_csrf_token():
        token = session.get("csrf_token")
        if token is None:
            token = secrets.token_hex(16)
            session["csrf_token"] = token
        return {"csrf_token": token}

    def get_client_ip():
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.remote_addr or "unknown"

    def log_event(actor, action, target, result):
        write_audit_log(
            app.config["DATABASE"],
            actor=actor,
            action=action,
            target=target,
            result=result,
            ip_address=get_client_ip(),
        )

    def verify_csrf():
        if request.method == "POST":
            expected = session.get("csrf_token")
            supplied = request.form.get("csrf_token", "")
            if not expected or not secrets.compare_digest(expected, supplied):
                log_event(
                    actor=g.user["username"] if g.user else "anonymous",
                    action="csrf_validation",
                    target=request.path,
                    result="blocked",
                )
                flash("Security check failed. Please try again.", "error")
                return False
        return True

    def login_required(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if g.user is None:
                log_event("anonymous", "auth_required", request.path, "redirected")
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped_view

    def admin_required(view):
        @wraps(view)
        @login_required
        def wrapped_view(*args, **kwargs):
            if g.user["role"] != "admin":
                log_event(g.user["username"], "admin_access", request.path, "denied")
                flash("You do not have permission to view that page.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapped_view

    @app.route("/")
    def index():
        if g.user:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=("GET", "POST"))
    def login():
        if request.method == "POST":
            if not verify_csrf():
                return redirect(url_for("login"))

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            ip_address = get_client_ip()

            if (
                username
                and count_recent_failed_attempts(
                    app.config["DATABASE"],
                    username,
                    ip_address,
                    app.config["LOGIN_WINDOW_MINUTES"],
                )
                >= app.config["MAX_FAILED_LOGINS"]
            ):
                log_event(username, "login", "account", "rate_limited")
                flash(
                    "Too many failed login attempts. Please wait and try again.",
                    "error",
                )
                return render_template("login.html")

            user = get_user_by_username(app.config["DATABASE"], username)

            if user and check_password_hash(user["password"], password):
                session.clear()
                session["csrf_token"] = secrets.token_hex(16)
                session["user"] = {
                    "id": user["id"],
                    "username": user["username"],
                    "role": user["role"],
                }
                record_login_attempt(
                    app.config["DATABASE"], username, ip_address, True
                )
                update_last_login(app.config["DATABASE"], username)
                log_event(username, "login", "account", "success")
                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for("dashboard"))

            record_login_attempt(app.config["DATABASE"], username or "unknown", ip_address, False)
            log_event(username or "unknown", "login", "account", "failed")
            flash("Invalid username or password.", "error")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        if g.user:
            log_event(g.user["username"], "logout", "session", "success")
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        visible_orders = get_orders_for_user(
            app.config["DATABASE"], g.user["username"], g.user["role"]
        )
        stats = {
            "menu_count": len(get_menu_items(app.config["DATABASE"])),
            "order_count": len(visible_orders),
        }
        security_metrics = get_security_metrics(app.config["DATABASE"])
        return render_template(
            "dashboard.html",
            stats=stats,
            security_metrics=security_metrics,
            session_minutes=int(app.permanent_session_lifetime.total_seconds() // 60),
            password_length=app.config["MIN_PASSWORD_LENGTH"],
        )

    @app.route("/menu")
    @login_required
    def menu():
        items = get_menu_items(app.config["DATABASE"])
        return render_template("menu.html", items=items)

    @app.route("/orders", methods=("GET", "POST"))
    @login_required
    def orders():
        items = get_menu_items(app.config["DATABASE"])

        if request.method == "POST":
            if not verify_csrf():
                return redirect(url_for("orders"))

            customer_name = request.form.get("customer_name", "").strip()
            item_id = request.form.get("item_id", "").strip()
            quantity = request.form.get("quantity", "1").strip()

            if not customer_name:
                flash("Customer name is required.", "error")
            elif not item_id.isdigit():
                flash("Please choose a menu item.", "error")
            elif not quantity.isdigit() or int(quantity) < 1:
                flash("Quantity must be a positive number.", "error")
            else:
                create_order(
                    app.config["DATABASE"],
                    customer_name=customer_name,
                    item_id=int(item_id),
                    quantity=int(quantity),
                    created_by=g.user["username"],
                )
                log_event(
                    g.user["username"],
                    "order_create",
                    f"customer:{customer_name}",
                    "success",
                )
                flash("Order created successfully.", "success")
                return redirect(url_for("orders"))

        orders_list = get_orders_for_user(
            app.config["DATABASE"], g.user["username"], g.user["role"]
        )
        return render_template("orders.html", items=items, orders=orders_list)

    @app.route("/orders/<int:order_id>")
    @login_required
    def order_detail(order_id):
        order = get_order_by_id(app.config["DATABASE"], order_id)

        if order is None:
            flash("Order not found.", "error")
            return redirect(url_for("orders"))

        if g.user["role"] != "admin" and order["created_by"] != g.user["username"]:
            log_event(g.user["username"], "order_view", f"order:{order_id}", "denied")
            flash("You are not allowed to view that order.", "error")
            return redirect(url_for("orders"))

        log_event(g.user["username"], "order_view", f"order:{order_id}", "success")
        return render_template("order_detail.html", order=order)

    @app.route("/admin")
    @admin_required
    def admin():
        with get_db_connection(app.config["DATABASE"]) as connection:
            users = connection.execute(
                "SELECT id, username, role, last_login_at FROM users ORDER BY username"
            ).fetchall()
        logs = get_recent_audit_logs(app.config["DATABASE"], limit=12)
        failed_logins = get_recent_failed_logins(app.config["DATABASE"], limit=8)
        security_metrics = get_security_metrics(app.config["DATABASE"])
        log_event(g.user["username"], "admin_view", "dashboard", "success")
        return render_template(
            "admin.html",
            users=users,
            logs=logs,
            failed_logins=failed_logins,
            security_metrics=security_metrics,
        )

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
        port=int(os.environ.get("PORT", "8000")),
    )
