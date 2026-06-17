# Security Policy

## Supported Versions

Only the latest version of the `waf-survival-guide` documentation, templates, and remediation strategies is actively supported. Security updates, mitigation adjustments, and tuning corrections will be applied strictly to the `main` branch.

| Version | Supported |
| ------- | --------- |
| Latest  | âœ… Yes    |
| < Older | âŒ No     |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If a recommended remediation strategy, target exclusion configuration, or tuning template within this guide introduces an unintended, critical vulnerability to an application infrastructure (such as an bypass vectors or complete rule neutralization), we want to fix it immediately.

Please report security flaws privately by following these steps:

1. Submit a detailed report via **GitHub Private Vulnerability Reporting** (accessible via the "Security" tab of this repository).

### What to Include in the Report:

- A thorough description of the exposure vector created by our recommended configuration.
- The specific file and line boundaries hosting the affected blueprint.
- A minimal proof-of-concept showing how an attacker could exploit the resulting rule exclusion.

---

## Our Response Process

- **Acknowledgement:** You will receive an initial response acknowledging receipt of your report within 48 business hours.
- **Triage & Validation:** The core maintainers and infrastructure leads will analyze the implementation footprint to validate the severity.
- **Remediation:** If verified, a targeted fix will be drafted, tested in isolated environments, and merged directly into production branches.
- **Disclosure:** A public advisory outlining the corrective steps and crediting your contribution will be released alongside the structural patch.
