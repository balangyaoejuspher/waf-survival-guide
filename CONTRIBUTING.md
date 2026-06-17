# Contributing to WAF Survival Guide

First off, thank you for taking the time to contribute! This project thrives on community-sourced false positives, triage workflows, and infrastructure adjustments. By contributing, you help bridge the gap between Development and Infrastructure teams.

All contributors are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## How Can I Contribute?

### 1. Reporting a WAF False Positive or Bug
Before submitting an issue, please search the existing Issues and Pull Requests to ensure it hasn't already been covered. If it is new, open an issue using the appropriate template and provide:
* **The Symptoms:** The exact HTTP status code (e.g., 403, 406, 429) and user impact.
* **The Infrastructure Context:** The cloud provider (GCP Cloud Armor, AWS WAF, Cloudflare) and the underlying engine/Ruleset version (e.g., OWASP CRS v3.3).
* **The Rule ID:** The specific signature ID triggered (e.g., `942100`).
* **Redacted Logs:** A safe, non-sensitive snippet showing the rule match parameters.

### 2. Proposing a New Guide or Tuning Blueprint
If you want to add a new remediation guide or Infrastructure-as-Code (Terraform/Ansible/CloudFormation) snippet:
1. Fork the repository.
2. Create a logically named branch (`feature/add-gcp-rule-942100`).
3. Ensure your file matches our **Handbook Structural Blueprint** (Symptom -> Diagnosis -> Log Evidence -> Remediation Matrix -> Audit Trail).
4. Submit a Pull Request targeting the `main` branch.

---

## Pull Request Guidelines

* **Atomic Changes:** Maintain one distinct feature, fix, or guide per Pull Request.
* **Documentation Quality:** Avoid dense prose. Prioritize scannability using bullet points, bold markers, and standard code blocks.
* **Infrastructure-as-Code (IaC) Rules:** Any provided snippets (e.g., HashiCorp Terraform configuration) must be valid syntax and follow security best practicesâ€”specifically minimizing surface area vulnerability (e.g., target exclusions over global rule deactivation).
* **Commit Messages:** Use clear, imperative commit summaries (e.g., `feat: add triage runbook for AWS WAF SQLi rule`).

---

## Style and Architecture Standards

When writing content inside the `docs/` folder, enforce the following constraints:
* **No Speculation:** Only document verified rulesets and confirmed cloud provider behaviors.
* **Format Unity:** Use standard Markdown table syntax for multi-provider configuration comparisons.
* **Code Isolation:** Always wrap commands (`gcloud`, `aws cli`, `curl`) and code snippets inside explicit multi-line markdown blocks with their respective language flag identifiers.