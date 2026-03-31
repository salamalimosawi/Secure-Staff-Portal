import sqlite3

from werkzeug.security import generate_password_hash


def get_db_connection(database_path):
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(database_path):
    with get_db_connection(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                last_login_at TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS menu_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_name TEXT NOT NULL,
                item_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                created_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (item_id) REFERENCES menu_items(id)
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                was_successful INTEGER NOT NULL,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            connection.executemany(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                [
                    ("admin", generate_password_hash("admin123"), "admin"),
                    ("staff", generate_password_hash("staff123"), "staff"),
                ],
            )

        menu_count = connection.execute("SELECT COUNT(*) FROM menu_items").fetchone()[0]
        if menu_count == 0:
            connection.executemany(
                "INSERT INTO menu_items (name, price) VALUES (?, ?)",
                [
                    ("Margherita Pizza", 12.99),
                    ("Pasta Alfredo", 14.50),
                    ("Caesar Salad", 9.75),
                    ("Fresh Lemonade", 4.25),
                ],
            )


def get_user_by_username(database_path, username):
    with get_db_connection(database_path) as connection:
        return connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()


def get_menu_items(database_path):
    with get_db_connection(database_path) as connection:
        return connection.execute(
            "SELECT id, name, price FROM menu_items ORDER BY name"
        ).fetchall()


def create_order(database_path, customer_name, item_id, quantity, created_by):
    with get_db_connection(database_path) as connection:
        connection.execute(
            """
            INSERT INTO orders (customer_name, item_id, quantity, created_by)
            VALUES (?, ?, ?, ?)
            """,
            (customer_name, item_id, quantity, created_by),
        )


def get_all_orders(database_path):
    with get_db_connection(database_path) as connection:
        return connection.execute(
            """
            SELECT
                orders.id,
                orders.customer_name,
                menu_items.name AS item_name,
                menu_items.price,
                orders.quantity,
                orders.created_by,
                orders.created_at
            FROM orders
            JOIN menu_items ON orders.item_id = menu_items.id
            ORDER BY orders.created_at DESC, orders.id DESC
            """
        ).fetchall()


def get_orders_for_user(database_path, username, role):
    with get_db_connection(database_path) as connection:
        if role == "admin":
            return get_all_orders(database_path)

        return connection.execute(
            """
            SELECT
                orders.id,
                orders.customer_name,
                menu_items.name AS item_name,
                menu_items.price,
                orders.quantity,
                orders.created_by,
                orders.created_at
            FROM orders
            JOIN menu_items ON orders.item_id = menu_items.id
            WHERE orders.created_by = ?
            ORDER BY orders.created_at DESC, orders.id DESC
            """,
            (username,),
        ).fetchall()


def get_order_by_id(database_path, order_id):
    with get_db_connection(database_path) as connection:
        return connection.execute(
            """
            SELECT
                orders.id,
                orders.customer_name,
                menu_items.name AS item_name,
                menu_items.price,
                orders.quantity,
                orders.created_by,
                orders.created_at
            FROM orders
            JOIN menu_items ON orders.item_id = menu_items.id
            WHERE orders.id = ?
            """,
            (order_id,),
        ).fetchone()


def record_login_attempt(database_path, username, ip_address, was_successful):
    with get_db_connection(database_path) as connection:
        connection.execute(
            """
            INSERT INTO login_attempts (username, ip_address, was_successful)
            VALUES (?, ?, ?)
            """,
            (username, ip_address, int(was_successful)),
        )


def update_last_login(database_path, username):
    with get_db_connection(database_path) as connection:
        connection.execute(
            """
            UPDATE users
            SET last_login_at = CURRENT_TIMESTAMP
            WHERE username = ?
            """,
            (username,),
        )


def count_recent_failed_attempts(database_path, username, ip_address, minutes=15):
    with get_db_connection(database_path) as connection:
        row = connection.execute(
            """
            SELECT COUNT(*)
            FROM login_attempts
            WHERE username = ?
              AND ip_address = ?
              AND was_successful = 0
              AND attempted_at >= datetime('now', ?)
            """,
            (username, ip_address, f"-{minutes} minutes"),
        ).fetchone()
        return row[0]


def write_audit_log(database_path, actor, action, target, result, ip_address):
    with get_db_connection(database_path) as connection:
        connection.execute(
            """
            INSERT INTO audit_logs (actor, action, target, result, ip_address)
            VALUES (?, ?, ?, ?, ?)
            """,
            (actor, action, target, result, ip_address),
        )


def get_recent_audit_logs(database_path, limit=10):
    with get_db_connection(database_path) as connection:
        return connection.execute(
            """
            SELECT actor, action, target, result, ip_address, created_at
            FROM audit_logs
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def get_security_metrics(database_path):
    with get_db_connection(database_path) as connection:
        failed_logins = connection.execute(
            """
            SELECT COUNT(*)
            FROM login_attempts
            WHERE was_successful = 0
              AND attempted_at >= datetime('now', '-24 hours')
            """
        ).fetchone()[0]

        successful_logins = connection.execute(
            """
            SELECT COUNT(*)
            FROM login_attempts
            WHERE was_successful = 1
              AND attempted_at >= datetime('now', '-24 hours')
            """
        ).fetchone()[0]

        denied_actions = connection.execute(
            """
            SELECT COUNT(*)
            FROM audit_logs
            WHERE result = 'denied'
              AND created_at >= datetime('now', '-24 hours')
            """
        ).fetchone()[0]

        order_count = connection.execute("SELECT COUNT(*) FROM orders").fetchone()[0]

        return {
            "failed_logins_24h": failed_logins,
            "successful_logins_24h": successful_logins,
            "denied_actions_24h": denied_actions,
            "total_orders": order_count,
        }


def get_recent_failed_logins(database_path, limit=10):
    with get_db_connection(database_path) as connection:
        return connection.execute(
            """
            SELECT username, ip_address, attempted_at
            FROM login_attempts
            WHERE was_successful = 0
            ORDER BY attempted_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
