# Results Notes

Use this file to capture:

- security findings caught by the pipeline
- screenshots of failed and passing runs
- remediation steps taken for each issue
- short discussion of tool strengths and limits

## Evidence Table

| Tool | Finding | Evidence | Fix | Result |
| --- | --- | --- | --- | --- |
| `pytest` | No failing tests in the final version | Local test run and CI test step | N/A | Passed |
| `Bandit` | No issues identified in the final version | Local Bandit run and CI Bandit step | Earlier hardcoded secret/debug issues were removed | Passed |
| `Semgrep` | No blocking issue remained in the final version | GitHub Actions security workflow | N/A | Passed |
| `pip-audit` | No blocking vulnerable dependency remained in the final version | GitHub Actions security workflow | N/A | Passed |
| `Gitleaks` | Initial CI failure due to shallow checkout history, not an actual leaked secret | First failed GitHub Actions run | Updated `actions/checkout` to use `fetch-depth: 0` | Passed after workflow fix |

## Tools That Ran Successfully

- `pytest`
- `Bandit`
- `Semgrep`
- `pip-audit`
- `Gitleaks`
- GitHub Actions workflow

## CI Result

The GitHub Actions security workflow completed successfully after the checkout configuration was corrected for the Gitleaks step. In the final version, the pipeline ran the test suite and the security tools without blocking findings.

## Issues Encountered and Fixed

1. Dashboard order count mismatch
   Staff users could only view their own orders on the orders page, but the dashboard originally showed the total number of all orders in the system. This was fixed by changing the dashboard count to use the same per-user order visibility logic as the orders page.

2. Local database mismatch after security upgrades
   The local SQLite database had been created before password hashing and schema updates were added. This caused login failures when the app began expecting hashed passwords. The issue was fixed by adding a lightweight migration path that upgrades older local databases automatically.

3. Gitleaks CI failure on GitHub Actions
   Gitleaks initially failed in CI because the repository checkout was shallow, so the action could not resolve the commit range it wanted to scan. This was fixed by setting `fetch-depth: 0` in the `actions/checkout` step.

## Gitleaks Note

The initial Gitleaks failure was caused by GitHub Actions checkout depth rather than a real secret leak. After updating the workflow to fetch full history with `fetch-depth: 0`, the Gitleaks step completed successfully.

## Reflection Prompts

- Which controls reduced likelihood versus impact?
- Which findings were true positives versus noisy?
- Which controls are preventive, detective, or corrective?
