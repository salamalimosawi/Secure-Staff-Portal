# Security Pipeline

## Tools and Purpose

| Tool | Purpose | Example Findings |
| --- | --- | --- |
| `pytest` | prevent regressions while security changes are added | broken route, failed login flow |
| `Bandit` | Python-focused static analysis | unsafe debug mode, weak configuration |
| `Semgrep` | broader code-pattern scanning | missing secure coding patterns, risky APIs |
| `pip-audit` | dependency vulnerability scanning | packages with known CVEs |
| `Gitleaks` | secret scanning | API keys, tokens, passwords in repo |

## Pipeline Policy

- every push and pull request runs tests and security scans
- builds should fail on scan findings that indicate exploitable issues
- fixes should be committed with evidence that tests still pass

## Suggested Demo Flow

1. Push the current project and capture a passing test run.
2. Introduce a harmless demo secret in a temporary branch and show `Gitleaks` fail.
3. Add a known vulnerable dependency version in a temporary branch and show `pip-audit` fail.
4. Remove the issues and capture the passing pipeline.
