# Rate Limiting & HTTP `429` — Webhooks, Cron Jobs, Batch Processors

> **Scope of this file:** how to design WAF and edge rate-limit rules that protect against L7 DDoS / brute force / scraping without false-positiving legitimate high-volume callers: webhooks (bursts from SaaS partners), cron jobs (predictable spikes at minute / hour boundaries), batch processors (sustained high concurrency from one IP), pagination consumers (sequential API pulls), and CI / CD runners (parallel test suites). Covers Google Cloud Armor, AWS WAF, and Cloudflare side by side.
>
> Cross-reference [docs/rules/913100.md](../rules/913100.md) for scanner-IP allow patterns and [docs/rules/921110.md](../rules/921110.md) for partner-IP allow patterns; the same IP-set discipline applies.

---

## 1. The Symptom

| Cross-provider signature                                                                                                                                              | Where you see it                           |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `HTTP 429 Too Many Requests` with a `Retry-After` header, returned by the **edge** rather than the app                                                                | Browser dev tools / partner logs / CI logs |
| A specific customer's batch import job fails halfway through with `429`; restarting helps briefly then fails again                                                    | Customer-side job runner                   |
| Webhook deliveries from a SaaS partner arrive in bursts (50 in 2 seconds, then nothing for 5 minutes) — partner shows "delivered 200 OK" but you only see ~30 of them | Webhook-receiver logs vs partner dashboard |
| CI nightly pipeline fails because the test runner hits 200 requests/min and the WAF rate-limit caps at 100/min                                                        | CI logs                                    |
| A shared NAT (corporate proxy, public Wi-Fi, mobile carrier CGNAT) causes "everyone behind this IP" to share a per-IP quota and trip 429                              | App-level user reports clustering by IP    |
| Pagination consumer (`?page=1&size=100`, `?page=2`, ...) of 50,000 pages from a partner integration gets blocked mid-walk                                             | Integration logs                           |

Distinguishing fingerprint: 429 from the edge, with a `Retry-After` header (or an edge-branded body), and no corresponding app-handler entry in your application log for the failing requests.

---

## 2. The Diagnosis

### 2.1 The three layers that can throw `429`

| Layer                                                                                                 | Where the limit lives                 | Typical signal                                                |
| ----------------------------------------------------------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------- |
| **Edge / CDN rate-limit** (Cloudflare, GCP Cloud Armor rate-based rule, AWS WAF rate-based statement) | Per-IP / per-key counters at the edge | Edge log shows `BLOCK` from the rate-based rule, no app log   |
| **Load balancer throttling** (GCP `outlier_detection`, AWS ALB / NLB connection limits)               | LB-level concurrency / RPS caps       | LB access log shows `429` or `503`, target log empty          |
| **Application rate limiter** (your code: token bucket per user, per API key)                          | App-side middleware                   | App log has the `429` entry; the request reached your handler |

The 3-query proof from [docs/triage/identifying-blocks.md](../triage/identifying-blocks.md) tells you which layer threw — re-read it; the principle is identical.

### 2.2 The four "high-volume legitimate" traffic shapes

| Shape                          | Example                                                                                   | Why it trips edge rate limits                                                                                                          |
| ------------------------------ | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| **Burst**                      | SaaS webhook delivery flushing 50 events in 2 seconds after a buffer drain                | Per-IP rate limit at 30 req/min on a 1-minute window: burst of 50 exceeds the bucket size, even though the per-minute average is fine. |
| **Sustained high concurrency** | Customer's batch import job running 20 parallel workers, each making sequential API calls | Per-IP rate at 600 req/min × 1 IP = trips. App-level per-customer quota would allow it; the edge doesn't know about customers.         |
| **Periodic spike**             | Cron-driven jobs across many customers all firing at `0 * * * *` (every hour at :00)      | A spike from many distinct IPs at the same instant; per-path limits triggered by aggregate volume; downstream backends overload.       |
| **Walk**                       | Pagination loop pulling page 1..N at 10 req/s from one IP                                 | Sustained per-IP rate; not bursty, but past the threshold.                                                                             |

### 2.3 The two configuration mistakes that cause most rate-limit FPs

1. **Keyed by client IP only.** Shared NATs (corporate proxies, mobile carriers, CGNAT) mean many users behind one IP — they share the quota. Single user's quota is fine; aggregate trips the rule. Fix: key by **client IP + cookie/header/API-key** composite.
2. **Threshold tuned for an interactive browser, applied to an API.** A browser session at 10 req/min is normal. An automated API caller at 600 req/min may also be normal. The same rate rule cannot serve both without massive headroom or wholesale FPs. Fix: per-path rate rules, or different rules keyed by API-key presence.

### 2.4 Provider mapping

| Provider            | Rate-limit mechanism                                                                                                                                                                                                | Notes                                                                                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **GCP Cloud Armor** | `rate_based_ban` and `throttle` action types on a security policy rule; configurable interval, count, ban duration, and `enforce_on_key` (`IP` / `IP_AND_PATH` / `HTTP_HEADER` / `XFF_IP` / `HTTP_COOKIE` / `SNI`). | Powerful key options; supports auto-deploying rate rules via Adaptive Protection.                                                                                  |
| **AWS WAF**         | `rate_based_statement` with an `aggregate_key_type` (`IP`, `FORWARDED_IP`, `CUSTOM_KEYS`, `CONSTANT`); rate is per **5-minute** window.                                                                             | The 5-minute window is fixed; bursts within it can be measured but the bucket size = limit. `CUSTOM_KEYS` (multi-field aggregation) was added relatively recently. |
| **Cloudflare**      | Rate Limiting rules (separate billing line on most plans); configurable `period`, `requests_per_period`, `mitigation_timeout`, characteristics (IP / header / cookie / hostname / region).                          | Most flexible characteristic combinations; tightly integrated with Cloudflare's bot management and analytics.                                                      |

---

## 3. The Log Evidence

### 3.1 GCP Cloud Armor

```text
resource.type="http_load_balancer"
AND jsonPayload.statusDetails="denied_by_rate_based_ban"
AND timestamp >= timestamp_sub(@end, INTERVAL 1 HOUR)
```

Or by status:

```text
resource.type="http_load_balancer"
AND httpRequest.status=429
```

Cluster by the **key** the rule used (helps identify whether shared-NAT is the cause):

```text
resource.type="http_load_balancer"
AND jsonPayload.statusDetails="denied_by_rate_based_ban"
| stats count() by httpRequest.remoteIp, httpRequest.requestUrl, httpRequest.userAgent
```

### 3.2 AWS WAF

```text
fields @timestamp, action, terminatingRuleId, terminatingRuleType, httpRequest.uri, httpRequest.clientIp
| filter action = "BLOCK"
| filter terminatingRuleType = "RATE_BASED"
| sort @timestamp desc
| limit 100
```

For `CUSTOM_KEYS` rate rules, the matched aggregate key appears in `rateBasedRuleList[].rateBasedRuleId` + the matched key values in `rateBasedRuleList[].limitKey`.

### 3.3 Cloudflare

```bash
curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/security/events?datetime_geq=2026-06-17T10:00:00Z" \
  -H "Authorization: Bearer $CF_TOKEN" \
  | jq '.result[] | select(.source == "ratelimit") |
        {ray_id, rule_id, rule_message, action, client_ip, uri, occurred_at}'
```

Cloudflare's Logpush `firewall_events` dataset with `Source = "ratelimit"` is the canonical source for rate-limit-specific blocks.

### 3.4 Local reproduction

Burst test:

```bash
seq 1 60 | xargs -P 10 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  "https://app.example.com/api/v1/items?page={}" | sort | uniq -c
```

A healthy rate-limit setup: most `200`, a small tail of `429` once the bucket drains.
A misconfigured setup: cliff to all `429` after the first few seconds.

### 3.5 Offline calculation

```bash
python - <<'PY'
# Token-bucket simulation for a webhook burst.
rate = 30 / 60.0   # 30 req per 60s
bucket = 30
tokens = bucket
events_sent = 50   # webhook burst
allowed = denied = 0
for _ in range(events_sent):
    if tokens >= 1:
        tokens -= 1
        allowed += 1
    else:
        denied += 1
print(f"Allowed: {allowed}, Denied: {denied}")
print(f"If you raise bucket to {events_sent}, all pass without raising the steady-state rate.")
PY
```

The lesson: **bucket size ≥ expected burst size** matters as much as steady-state rate.

---

## 4. The Remediation Matrix

> **Bucket sizing vs steady rate.** A rule with `rate = 100/min, bucket = 100` rejects a burst of 101 in 1 second even though the per-minute average is 100. A rule with `rate = 100/min, bucket = 300` allows a 3× burst that drains back to steady-state within the minute. Use bucket sizing to absorb bursts; use steady rate to define the long-run cap.

### 4.1 GCP Cloud Armor

Composite key (IP + API key header) for batch-processor workloads:

```hcl
rule {
  action      = "rate_based_ban"
  priority    = 200
  description = "Rate-limit /api/v1/* per (IP + X-API-Key) — webhook bursts up to 60 in 60s allowed, sustained 600/min cap. EXCEPTIONS.md row YYYY-MM-DD."
  preview     = true

  match {
    expr {
      expression = "request.path.startsWith('/api/v1/')"
    }
  }

  rate_limit_options {
    rate_limit_threshold {
      count        = 600
      interval_sec = 60
    }

    conform_action      = "allow"
    exceed_action       = "deny(429)"
    enforce_on_key      = "HTTP_HEADER"
    enforce_on_key_name = "X-API-Key"

    ban_duration_sec = 60

    ban_threshold {
      count        = 6000   # 10x steady-state cap = sustained-abuse signal
      interval_sec = 60
    }
  }
}
```

For the webhook burst case, **raise the count to absorb the burst** rather than lowering it. A SaaS partner that sends `50 events in 2 seconds, then nothing for 55 seconds` averages well under 60/min — the rule should fit the average shape, not the instantaneous rate.

### 4.2 AWS WAF

Rate-based with custom keys (IP + API key + URI path):

```hcl
resource "aws_wafv2_web_acl" "api" {
  name  = "api-acl"
  scope = "REGIONAL"

  default_action { allow {} }

  rule {
    name     = "rate-limit-api-v1-per-key"
    priority = 50

    action { block {} }

    statement {
      rate_based_statement {
        limit              = 3000     # per 5-min window = ~600/min steady
        aggregate_key_type = "CUSTOM_KEYS"

        custom_key {
          ip {}
        }
        custom_key {
          header {
            name = "x-api-key"
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        scope_down_statement {
          byte_match_statement {
            field_to_match { uri_path {} }
            positional_constraint = "STARTS_WITH"
            search_string         = "/api/v1/"
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-api-v1"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "api-acl"
    sampled_requests_enabled   = true
  }
}
```

AWS WAF's rate window is fixed at 5 minutes. Express your per-minute target as `× 5` for the `limit` field.

### 4.3 Cloudflare Rate Limiting

```hcl
resource "cloudflare_ruleset" "rate_limit_api_v1" {
  zone_id = var.zone_id
  name    = "Rate limit /api/v1 per (IP + API key)"
  kind    = "zone"
  phase   = "http_ratelimit"

  rules {
    action = "block"
    ratelimit {
      characteristics     = ["ip.src", "http.request.headers[\"x-api-key\"]"]
      period              = 60
      requests_per_period = 600
      mitigation_timeout  = 60
    }
    expression  = "(starts_with(http.request.uri.path, \"/api/v1/\"))"
    description = "Rate-limit /api/v1 600 req/min per (IP+API key). EXCEPTIONS.md row YYYY-MM-DD."
    enabled     = true
  }
}
```

For webhook bursts, prefer **`http_request_firewall_custom` with `Skip → Rate Limit`** for the known partner IPs:

```hcl
resource "cloudflare_ruleset" "skip_ratelimit_for_partner_webhooks" {
  zone_id = var.zone_id
  name    = "Skip rate-limit for partner webhooks"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules {
    action = "skip"
    action_parameters {
      ruleset = "current"
      phases  = ["http_ratelimit"]
    }
    expression  = "(ip.src in {198.51.100.0/24} and starts_with(http.request.uri.path, \"/webhook/\"))"
    description = "Bypass rate-limit for partner-x webhook IPs on /webhook/* (burst delivery, HMAC-verified). EXCEPTIONS.md row YYYY-MM-DD."
    enabled     = true
  }
}
```

### 4.4 Verification

- Webhook delivery from partner: all 50 events arrive within 2 seconds, all return 200, partner dashboard matches your receiver count.
- Batch import: 20-worker job completes without 429s.
- A non-partner IP attempting 600 req/min from one (IP, API key) pair still hits 429 after the threshold.

---

## 5. Audit Trail

```
| 2026-06-17 | api.example.com | gcp-cloud-armor | rate_based_ban /api/v1/* | (IP + X-API-Key), 600/min, ban 60s | Composite key replaces IP-only key; corporate-NAT customers were sharing quota. | <link to before/after log query> | preview 2026-06-17 → enforce 2026-06-20 | @platform-lead | 2026-12-14 |
```

```
| 2026-06-17 | api.example.com | cloudflare | skip rate-limit for partner-x | ip.src in {198.51.100.0/24} on /webhook/* | Partner-x webhook bursts; HMAC-verified at app layer (commit a1b2c3d). | <link> | log 2026-06-17 → skip 2026-06-20 | @secops-lead | 2026-09-15 (review when partner switches to delivery pacing) |
```

---

## 6. Common pitfalls

- **IP-only keying breaks for shared NATs.** Always combine with a second characteristic (cookie, header, API key, JWT subject).
- **Bucket size ≤ expected burst size.** A bucket of 30 with a 50-event burst will deny 20 events even at low steady-state rate. Size the bucket for the largest legitimate burst.
- **AWS 5-minute fixed window.** AWS WAF rate-based rules count over 5 minutes, not 1. A 100 req/min cap on AWS is `limit = 500` per 5 min — and a 50-req burst followed by 4.5 min of nothing still consumes a portion of the budget.
- **Cloudflare rate-limit billing.** Rate-limit rules are a separate paid product on most Cloudflare plans. Confirm plan inclusion before adding many rules.
- **`Retry-After` is advisory.** Many clients ignore it and immediately retry, deepening the ban. If you can, set the response headers to non-trivial `Retry-After` values to encourage well-behaved retry.
- **Don't 10× the threshold to "make noise go away".** That hides the next abuse pattern. Tune by **composite key** + **path-scoped rules**, not by blanket threshold increases.
- **Ban duration > steady rate window.** A 60s ban after exceeding a 60s rate window is the right shape; a 1-hour ban after a 60s window punishes transient bursts way out of proportion.
- **Cron-aligned spikes.** Many customers schedule jobs at `0 * * * *`. Aggregate spike at :00 each hour can trip path-level rate rules even when no single customer exceeds. Spread customer cron offsets (or use a queue), and size per-path limits with this in mind.
- **Adaptive Protection (GCP) auto-deploys rate rules.** During suspected attacks, Cloud Armor Adaptive Protection can auto-create rate-based deny rules with system-generated names. If your FP coincides with an Adaptive Protection alert, inspect `enforcedSecurityPolicy.name` before tuning your own rules.

---

## See also

- [docs/triage/identifying-blocks.md](../triage/identifying-blocks.md) — the 3-query proof for diagnosing which layer threw `429`.
- [docs/rules/913100.md](../rules/913100.md), [docs/rules/921110.md](../rules/921110.md) — same IP-set + audit discipline applies to allow rules referenced from this page.
- [docs/provider-guides/gcp-cloud-armor.md](../provider-guides/gcp-cloud-armor.md), [docs/provider-guides/aws-waf.md](../provider-guides/aws-waf.md), [docs/provider-guides/cloudflare-waf.md](../provider-guides/cloudflare-waf.md)
- [EXCEPTIONS.md](../../EXCEPTIONS.md)

---

## References

### Standards & general

- RFC 6585 §4 (`429 Too Many Requests`) — [https://datatracker.ietf.org/doc/html/rfc6585#section-4](https://datatracker.ietf.org/doc/html/rfc6585#section-4).
- RFC 7231 §7.1.3 (`Retry-After`) — [https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.3](https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.3).

### Google Cloud Armor

- Rate-limiting rules — [https://cloud.google.com/armor/docs/rate-limiting-overview](https://cloud.google.com/armor/docs/rate-limiting-overview).
- `enforce_on_key` options (IP, IP_AND_PATH, HTTP_HEADER, XFF_IP, HTTP_COOKIE, SNI) — [https://cloud.google.com/armor/docs/rate-limiting-overview#enforce-on-key](https://cloud.google.com/armor/docs/rate-limiting-overview#enforce-on-key).
- Adaptive Protection auto-deploy of rate rules — [https://cloud.google.com/armor/docs/adaptive-protection-overview](https://cloud.google.com/armor/docs/adaptive-protection-overview).
- Terraform `google_compute_security_policy` `rate_limit_options` — [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_security_policy](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_security_policy).

### AWS WAF

- Rate-based rule statements — [https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html).
- Custom aggregate keys (`CUSTOM_KEYS`) — [https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-aggregation-keys.html](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-aggregation-keys.html).
- Terraform `aws_wafv2_web_acl` rate-based examples — [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl).

### Cloudflare

- Rate Limiting rules (modern Rulesets-engine form) — [https://developers.cloudflare.com/waf/rate-limiting-rules/](https://developers.cloudflare.com/waf/rate-limiting-rules/).
- Characteristics (composite keying) — [https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/#characteristics](https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/#characteristics).
- Custom rules with `Skip` action targeting `http_ratelimit` phase — [https://developers.cloudflare.com/waf/custom-rules/skip/](https://developers.cloudflare.com/waf/custom-rules/skip/).
- Logpush `firewall_events` dataset (`Source = "ratelimit"`) — [https://developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events/](https://developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events/).
