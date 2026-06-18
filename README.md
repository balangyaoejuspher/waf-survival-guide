# waf-survival-guide

[![CI](https://github.com/balangyaoejuspher/waf-survival-guide/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/balangyaoejuspher/waf-survival-guide/actions/workflows/ci.yml)
[![Pages](https://github.com/balangyaoejuspher/waf-survival-guide/actions/workflows/pages.yml/badge.svg?branch=main)](https://balangyaoejuspher.github.io/waf-survival-guide/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> A cross-provider, developer-first handbook for surviving Web Application Firewalls (WAFs) — Google Cloud Armor, AWS WAF, and Cloudflare — without disabling them.

If you have ever shipped code, watched your container logs stay empty, and been told _"the request never reached the app"_, this guide is for you.

📖 **Browse the docs site:** <https://balangyaoejuspher.github.io/waf-survival-guide/>

---

## Why this exists

Most teams run their WAF on **default managed rulesets**. Defaults are written for the "average" web app, not yours. Two things follow:

1. **Legitimate traffic gets blocked** — long session cookies, JWTs, WYSIWYG HTML payloads, and signed URLs routinely trip rules like OWASP CRS `942100` (SQLi via `libinjection`), `941xxx` (XSS), or rate-limit rules.
2. **Developers cannot see it.** The request is denied at the edge. Your application container never executes. Logs are empty. The browser shows `403`, `404`, or `429`. The reflexive guess — "my code is broken" — is wrong, and the next hour is wasted.

This repository closes that loop with a **shared vocabulary**, **a 5-minute triage workflow**, and **safe, targeted tuning patterns** (exclusions and preview mode — never "disable the rule group").

---

## Who this is for

| Role                          | What you get                                                                                                          |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **Developers**                | A 5-minute checklist to prove "WAF blocked it" vs "my code broke it" before opening a ticket.                         |
| **SecOps / Platform / Infra** | Evidence-based tuning requests with rule IDs, log queries, and ready-to-review Terraform diffs.                       |
| **SREs / On-call**            | A single lookup matrix that maps `403` / `404` / `429` symptoms to the rule families that produce them on each cloud. |

---

## Scope

| In scope                                                                  | Out of scope                                                                                 |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| OWASP CRS-based managed rules on GCP Cloud Armor, AWS WAF, Cloudflare WAF | Custom L7 DDoS architectures                                                                 |
| False-positive triage, target exclusions, preview/count mode rollouts     | Bot management product tuning (Cloudflare Bot Management, AWS Bot Control) — separate domain |
| Log queries (Cloud Logging, CloudWatch, Cloudflare Logpush)               | SIEM correlation rules                                                                       |
| Terraform / `gcloud` / `aws` CLI / Wrangler snippets                      | Provider pricing comparisons                                                                 |

---

## Triage lookup matrix

Use this as the **first stop** when an app misbehaves in production.

| HTTP symptom                                    | Likely WAF cause                                    | Common CRS rule family       | Start here                                                                         |
| ----------------------------------------------- | --------------------------------------------------- | ---------------------------- | ---------------------------------------------------------------------------------- |
| `403 Forbidden` on login / form submit          | SQLi false positive on cookie or JWT                | `942100`, `942130`, `942260` | [docs/concepts/cookie-false-positives.md](docs/concepts/cookie-false-positives.md) |
| `403 Forbidden` saving rich-text / HTML content | XSS false positive on body parameter                | `941100`, `941160`, `941310` | [docs/concepts/xss-rich-text.md](docs/concepts/xss-rich-text.md)                   |
| `429 Too Many Requests`                         | Rate-limit / throttling rule                        | Provider-specific            | [docs/concepts/rate-limiting.md](docs/concepts/rate-limiting.md)                   |
| `404 Not Found` but the route exists            | Path / method ACL or geo-block                      | Provider custom rule         | [docs/triage/identifying-blocks.md](docs/triage/identifying-blocks.md)             |
| Empty app logs + edge `5xx`                     | Origin rule / WAF action `BLOCK` upstream of origin | Provider-specific            | [docs/triage/README.md](docs/triage/README.md)                                     |

---

## Content philosophy

Every page in `docs/` follows the same five-section flow so you can scan, copy, and ship:

1. **The Symptom** — exactly what the user / browser / client sees.
2. **The Diagnosis** — the OWASP CRS rule ID and engine behavior (e.g. `libinjection`) responsible.
3. **The Log Evidence** — the precise log query needed to prove it, per cloud.
4. **The Remediation Matrix** — Console click-path **and** Terraform / CLI snippets for a **targeted exclusion** (never "disable the group").
5. **Audit trail entry** — what to record in [EXCEPTIONS.md](EXCEPTIONS.md) so the exception is reviewable later.

> **House rule:** if a proposed fix is "turn off rule `XXX` globally", the PR will be rejected. We tune by **target exclusion** + **preview mode** rollout. See [docs/triage/README.md](docs/triage/README.md).

---

## Quick start for developers

You think the WAF blocked you. Do this, in order:

1. **Reproduce in `curl` with `-v`.** Capture the response status, response headers, and any `X-Request-Id` / `X-Amzn-Trace-Id` / `cf-ray` header.
2. **Check the edge log, not the app log.** [docs/triage/README.md](docs/triage/README.md) lists the exact query string per provider.
3. **Find the rule ID.** Every managed WAF tags the matched rule in the log entry.
4. **Open a tuning request** using the template in [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md) — include rule ID, path, redacted payload, and proposed exclusion scope.

---

## Contributing

False-positive reports, log-query corrections, and provider-parity additions are all welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first — it includes the **payload redaction checklist** that every report must pass.

By participating you agree to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## Security

If you find that a configuration template in this repo would _weaken_ a deployment (e.g. an overly broad exclusion), please report it privately. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
