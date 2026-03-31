# Architecture

## Application Flow

```text
Browser -> Flask App -> SQLite Database
```

## Security Pipeline Flow

```text
Developer Push -> GitHub Actions -> Tests + Bandit + Semgrep + pip-audit + Gitleaks
```

## Main Components

- `app.py` handles routes, sessions, and access control.
- `db.py` manages the SQLite schema, seeded data, and query helpers.
- `templates/` renders the user-facing pages.
- `security.yml` runs automated checks on every push and pull request.

## Security Controls Added

- Passwords are stored as hashes rather than plaintext.
- Session cookies are configured with `HttpOnly` and `SameSite=Lax`.
- CSRF tokens are required on login and order creation forms.
- Failed login attempts are tracked to slow brute-force attempts.
- Audit logs capture sensitive actions for accountability.
- Order access uses both role checks and ownership checks to prevent IDOR-style access.
