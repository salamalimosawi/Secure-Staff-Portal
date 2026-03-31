# Demo Script

## 1. Open the application

- Launch the Flask app locally.
- Log in as `staff / staff123`.
- Show the dashboard security overview and implemented controls.

## 2. Show authentication and authorization

- Open the orders page and create an order.
- Explain that staff can only see their own orders.
- Attempt to access another user's order and show the denial message.

## 3. Show admin evidence

- Log in as `admin / admin123`.
- Open the admin page.
- Point out:
  - recent audit logs
  - recent failed login attempts
  - last-login timestamps
  - security metrics cards

## 4. Show the pipeline

- Run `pytest` locally or show the CI output.
- Show Bandit, Semgrep, `pip-audit`, and Gitleaks in the workflow.
- Demonstrate one temporary failing example in a branch, then remove it.

## 5. Close with course mapping

- Authentication: password hashing, session controls, rate limiting
- Authorization: RBAC and object-level checks
- Accountability: audit logs and admin visibility
- Shift-left security: automated scanning on every push and pull request
