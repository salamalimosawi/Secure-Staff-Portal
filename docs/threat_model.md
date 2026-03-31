# Threat Model

## Assets

- user accounts and roles
- session cookies
- order records
- application secrets and configuration
- audit logs

## Main Threats

| Threat | Vulnerability | Impact | Control |
| --- | --- | --- | --- |
| Brute-force login | unlimited password guessing | account takeover | login attempt tracking and rate limiting |
| Session theft or misuse | weak cookie/session settings | unauthorized access | `HttpOnly`, `SameSite`, session lifetime, optional secure cookie |
| CSRF | state-changing forms without anti-CSRF tokens | unauthorized order creation or login abuse | per-session CSRF token validation |
| IDOR/BOLA | missing object-level authorization | staff view another user's order | ownership check on `orders/<id>` |
| Over-privileged access | role checks only in UI | unauthorized admin access | server-side admin guard on protected routes |
| Secret leakage | secrets committed to repo | unauthorized app signing/session forgery | environment-based secret configuration plus Gitleaks |
| Vulnerable dependency | outdated package with known CVE | remote compromise or app instability | `pip-audit` in CI |

## Trust Boundaries

- browser to Flask server
- Flask server to SQLite database
- developer workstation to GitHub repository
- GitHub repository to CI security pipeline

## Security Objectives

- authenticate users before protected actions
- authorize each sensitive action server-side
- record enough audit data for accountability
- block unsafe changes before merge through automated scanning
