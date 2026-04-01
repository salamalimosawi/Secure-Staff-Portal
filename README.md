# Restaurant Secure Pipeline Project

This project is a small Flask-based restaurant staff portal used to demonstrate an automated secure development pipeline.

## Project Goal

The goal is to show how a small web application can be improved with security controls from the course and continuously checked in CI before code is merged or deployed.

## Features

- Session-based login with password hashing and CSRF-protected forms
- Menu page backed by SQLite
- Order creation form and order history
- Admin-only page for role-based access control
- Order-detail authorization based on role and ownership
- Login rate limiting and audit logging for accountability
- Secure response headers and session lifetime controls
- GitHub Actions workflow with tests and security scans

## Seeded Accounts

- `admin / admin123`
- `staff / staff123`

## Local Setup

1. Create and activate a virtual environment:
   `python3 -m venv .venv`
   `source .venv/bin/activate`
2. Install dependencies:
   `python3 -m pip install --upgrade pip`
   `python3 -m pip install -r requirements.txt`
3. Start the app:
   `python3 app.py`
4. Open `http://127.0.0.1:8000`

Optional environment variables:

- `FLASK_SECRET_KEY`: set a stable secret for local development
- `FLASK_DEBUG=1`: enable Flask debug mode explicitly
- `FLASK_SECURE_COOKIE=1`: mark session cookies as secure for HTTPS deployments
- `PORT=8000`: override the local port if needed

## Test and Scan Commands

- `pytest`
- `bandit -c bandit.yaml -r .`
- `semgrep scan --config auto .`
- `python3 -m pip_audit -r requirements.txt`
- `gitleaks dir .`

Note: `gitleaks` is installed separately from `pip` on many systems, for example with `brew install gitleaks` on macOS.

## Project Layout

- `app.py`: Flask routes and session logic
- `db.py`: SQLite schema and helper functions
- `templates/`: HTML pages for the staff portal
- `static/`: Basic CSS styling
- `tests/`: Pytest coverage for key flows
- `.github/workflows/security.yml`: CI security pipeline

## Course Concepts Reflected

- Authentication: hashed passwords, login attempt tracking, secure session settings
- Authorization: RBAC plus object-level ownership checks on orders
- Accountability: audit logging for login, admin access, and order actions
- Web security: CSRF protection on state-changing forms and hardened response headers

## Recommended Submission Evidence

- screenshot of a passing local test run
- screenshot of a GitHub Actions run
- one failed security scan example and the later fix
- short discussion of why each tool was included
- the threat model in `docs/threat_model.md`
