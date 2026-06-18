# EXCEPTIONS — WAF Tuning Audit Trail

Chronological ledger of every WAF rule exception this org has applied. Append-only. Newest entry at the **top**.

## Why this file exists

WAF exceptions are not "fire and forget". Every exclusion narrows the firewall's coverage of a specific service. Without a ledger:

- The same false positive gets re-debugged in 6 months by a different team.
- Exclusions outlive the deploy that needed them — a JWT format change makes the exclusion redundant, but it stays in production forever.
- During audit / pen test, nobody can explain why parameter `x` is whitelisted on path `/y`.

This file is the **single source of truth** that answers: *"who turned off what, when, why, and who approved it?"*

## Entry format

Every exception MUST include:

| Field | Required | Notes |
| --- | --- | --- |
| Date | yes | `YYYY-MM-DD` |
| Service / hostname | yes | e.g. `api.example.com`, `checkout-svc` |
| Provider | yes | `gcp-cloud-armor` / `aws-waf` / `cloudflare` |
| Rule ID | yes | CRS rule (`942100`) or vendor rule ARN / ID |
| Scope of exclusion | yes | Path, method, target field (e.g. `request_cookies.SESSIONID`) |
| Justification | yes | One sentence; link to issue / ticket |
| Evidence link | yes | Link to log query result or screenshot — proves the FP |
| Rollout mode | yes | `preview` first, then `enforce` — record the date each started |
| Approver | yes | GitHub handle / name of the reviewer who merged the change |
| Review date | yes | Date by which the exception is re-evaluated (default: +180 days) |

If any field is missing, the PR adding the exception will be blocked.

---

## Ledger

| Date | Service | Provider | Rule ID | Scope | Justification | Evidence | Mode | Approver | Review by |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| *example* `2026-06-17` | `app.example.com` | `gcp-cloud-armor` | `942100` | `request_cookies.SESSIONID` on `/login` | Long signed session cookie tripping `libinjection`; verified harmless. | (log query link) | `enforce` since `2026-06-20` (preview `2026-06-17 → 2026-06-20`) | `@platform-lead` | `2026-12-14` |

<!-- Add new rows above this line. Keep the example row last for reference. -->

---

## Review process

- Quarterly: open an issue listing every row whose **Review by** date has passed.
- For each row: re-run the original log query against the last 30 days of traffic with the exception **removed in preview mode**. If zero matches, delete the exception. If matches persist, refresh the row with a new **Review by** date + a one-line note explaining why it stays.
- A removed exception is **not deleted from this file** — strike-through the row and append a "removed `YYYY-MM-DD`" note. The audit trail is append-only.
