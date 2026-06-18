# Cloudflare WAF — Provider Reference

> Stub. Dashboard click-paths, API / Wrangler / `cf-terraforming` snippets for diagnosing and safely tuning Cloudflare's Managed Rulesets and Custom Rules. Expand alongside concrete reproductions.

---

## 1. The Symptom

- `403 Forbidden`, an HTML interstitial branded with `Cloudflare`, error codes like `1010`, `1015`, `1020`, or `Attention Required! | Cloudflare`.
- `cf-ray` header is present on the response — copy it; every Cloudflare log query keys off this.
- App / origin shows no log entry — request was terminated at Cloudflare's edge.

---

## 2. The Diagnosis

Cloudflare's request pipeline (simplified) for the **firewall** phases:

```
http_request_sanitize ──► http_request_firewall_custom ──► http_request_firewall_managed
```

| Phase                           | What it does                                                             |
| ------------------------------- | ------------------------------------------------------------------------ |
| `http_request_firewall_custom`  | Your zone's custom rules — IP lists, geo blocks, custom WAF expressions. |
| `http_request_firewall_managed` | Cloudflare Managed Ruleset (OWASP CRS + Cloudflare proprietary rules).   |

A request blocked in either phase produces a row in **Security → Events**.

---

## 3. The Log Evidence

### Dashboard

**Security → Events** → filter by:

- **Host** (hostname)
- **Action** (`Block`, `Managed Challenge`, `JS Challenge`, `Log`)
- **Ray ID** (paste your `cf-ray`)

Expand the matching row → **Match details** shows the matched field and value (if "Log full HTTP request" is enabled on the ruleset).

### API (Security Events / Firewall Events)

```bash
curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/security/events?datetime_geq=2026-06-17T10:00:00Z&host=app.example.com" \
  -H "Authorization: Bearer $CF_TOKEN" \
  | jq '.result[] | {ray_id, rule_id, rule_message, action, uri, occurred_at}'
```

### Logpush (production-grade)

For sustained tuning work, enable [Logpush](https://developers.cloudflare.com/logs/logpush/) for the `http_requests` and `firewall_events` datasets into your SIEM / object store. Sampling is configurable per dataset.

---

## 4. The Remediation Matrix

Cloudflare's modern tuning model is **`cloudflare_ruleset`** in the `http_request_firewall_managed` phase, with **overrides** scoped by expression.

### Managed-ruleset rule override, path-scoped, action = `log` (preview)

```hcl
resource "cloudflare_ruleset" "managed_waf_overrides" {
  zone_id     = var.zone_id
  name        = "Managed WAF overrides"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules {
    action = "execute"
    action_parameters {
      id = "efb7b8c949ac4650a09736fc376e9aee"   # Cloudflare Managed Ruleset

      overrides {
        rules {
          id     = "<rule-id-for-942100>"
          action = "log"           # preview-equivalent; promote to "skip" after soak
          status = "enabled"
        }
      }
    }

    expression  = "(http.host eq \"app.example.com\" and starts_with(http.request.uri.path, \"/login\"))"
    description = "Preview-skip 942100 on /login. EXCEPTIONS.md row YYYY-MM-DD."
    enabled     = true
  }
}
```

After 72h of clean **Security → Events** for the affected route, change `action = "log"` to `action = "skip"` and re-apply.

### Custom "skip managed rules" rule for finer scoping

For per-cookie / per-header scoping that the managed override does not expose, write a custom rule in the `http_request_firewall_custom` phase whose action is `skip` of the managed phase, gated on the request shape:

```hcl
resource "cloudflare_ruleset" "skip_managed_for_sessionid" {
  zone_id = var.zone_id
  name    = "Skip managed for SESSIONID on /login"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules {
    action = "skip"
    action_parameters {
      ruleset = "current"
      phases  = ["http_request_firewall_managed"]
    }
    expression  = "(starts_with(http.request.uri.path, \"/login\") and http.cookie contains \"SESSIONID=\")"
    description = "Skip managed WAF only when SESSIONID present on /login. EXCEPTIONS.md row YYYY-MM-DD."
    enabled     = true
  }
}
```

> This skips the **whole managed phase** for matching requests — broader than a per-rule override. Use only when the per-rule override is not granular enough, and document the wider scope clearly.

### Wrangler / API for emergency edits

`wrangler` does not directly manage WAF rulesets (it's primarily for Workers). For emergency edits without Terraform, use the API:

```bash
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/http_request_firewall_managed/entrypoint" \
  -H "Authorization: Bearer $CF_TOKEN" \
  -H "Content-Type: application/json" \
  --data @override.json
```

Anything done by emergency API call must be reconciled back into Terraform within 24h and recorded in [../../EXCEPTIONS.md](../../EXCEPTIONS.md).

---

## 5. Audit Trail

Every override / skip rule lands a row in [../../EXCEPTIONS.md](../../EXCEPTIONS.md) the moment it goes into preview (`log`) mode.

---

## Common pitfalls

- **"Skip" vs "Log" vs "Block" semantics.** `Log` evaluates the rule and records the would-be action without enforcing — the preview equivalent. `Skip` bypasses the rule entirely. Don't confuse them; promoting `log` → `skip` is intentional, not automatic.
- **Two zones, one hostname.** If a hostname is proxied through a partial-DNS zone and also covered by an account-level ruleset (e.g. for Enterprise customers), overrides at the zone level may not affect the account-level ruleset. Check both.
- **Ruleset IDs are stable, rule IDs are not always.** Cloudflare's managed-ruleset structure can shift rule IDs across CRS package versions. Pin to the ruleset version in Terraform when stability matters, and re-validate exclusions when bumping the package.
- **`Cache Reserve` / Edge cache of error responses.** A `403` cached at the edge survives the fix. Purge the affected path after promoting the exclusion.

---

## See also

- [../triage/README.md](../triage/README.md)
- [../concepts/cookie-false-positives.md](../concepts/cookie-false-positives.md)
- [gcp-cloud-armor.md](gcp-cloud-armor.md), [aws-waf.md](aws-waf.md)
- [../../EXCEPTIONS.md](../../EXCEPTIONS.md)
