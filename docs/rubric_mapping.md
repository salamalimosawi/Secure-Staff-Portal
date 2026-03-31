# Rubric Mapping

## Secure Software Design

- Threat model identifies assets, threats, vulnerabilities, and controls.
- Session security, CSRF protection, and password hashing are implemented.

## Authentication and Authorization

- Session-based login with rate limiting and hashed passwords.
- RBAC for admin routes.
- Object-level authorization for order access.

## Monitoring and Accountability

- Audit logs capture actor, action, target, result, IP, and time.
- Admin panel exposes recent audit activity and failed logins.

## DevSecOps / Secure Pipeline

- `pytest`, Bandit, Semgrep, `pip-audit`, and Gitleaks run in CI.
- Project includes report-ready evidence and a demo script.

## Testing and Validation

- Automated tests cover core behavior and several security expectations.
- Local security scans can be run independently before pushing.
