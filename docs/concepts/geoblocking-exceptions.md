# Geoblocking Exceptions — Multi-Region CDNs and Localized Third-Party APIs

> **Scope of this file:** how to write geoblock rules that protect against high-risk-country traffic without false-positiving legitimate edge-cached requests from multi-region CDNs (Cloudflare → your origin, Akamai → your origin), localized third-party API consumers (Stripe webhooks from country-specific PoPs, Twilio callbacks, payment-network confirmations), traveling employees on VPNs, and federated partners whose traffic egresses through unexpected regions. Covers Google Cloud Armor, AWS WAF, and Cloudflare side by side.

---

## 1. The Symptom

| Cross-provider signature                                                                                                                                            | Where you see it                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `HTTP 403` returned only to users in specific countries; the response body or error code identifies the geoblock rule                                               | Customer support ticket "site is broken in [country]" |
| Legitimate webhook deliveries from a SaaS partner fail intermittently — partner serves from multiple regions and the failing deliveries come from "unexpected" PoPs | Partner-side webhook retry queue                      |
| CDN-to-origin pulls failing: your origin geoblocks "anything outside US" but Akamai's pulling edge nodes are in Asia                                                | Origin access log                                     |
| Internal employee on VPN gets blocked because the VPN exit is in a country on the geoblock list                                                                     | Employee support                                      |
| Payment-network confirmation traffic (3-D Secure, ACS callbacks) fails intermittently — bank's PoP is in a "high risk" country per your geoblock                    | Payments-team alerts                                  |
| A federated identity provider's token-validation endpoint can't reach your callback URL because their authorization service is in a different country               | OAuth flow break                                      |

Distinguishing fingerprint: the failing requests originate from one or a small set of countries, and the source IP is **legitimate infrastructure** (a CDN PoP, a partner's edge, a VPN exit), not an end-user.

---

## 2. The Diagnosis

### 2.1 How edge geoblock decisions are made

All three providers attribute requests to a country via a GeoIP lookup of the client's IP address. There is no DNS lookup, no reverse-DNS check, no TLS-SNI inspection. The country attribution is **whatever the GeoIP database says about the source IP at the time of the request**.

Three operational implications:

1. **GeoIP databases lag reality.** IP ranges get reassigned across countries. A range that was in Country A last quarter may now be in Country B. Most providers refresh GeoIP weekly; some monthly.
2. **CDN PoPs route from "nearest" edge.** A request from a user in Country X may be served by a CDN PoP in Country Y if the routing path is shorter. The origin sees the CDN PoP's IP, not the original user's.
3. **Anycast IPs span continents.** A single IP can serve users from multiple continents. GeoIP attribution for anycast addresses is best-effort.

### 2.2 The "legitimate infrastructure" cases

| Source                                         | Why it falls in an unexpected country                                                                                                                                                                         |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cloudflare → origin pull                       | Cloudflare's pulling edge is the nearest to your origin, which may be in any country Cloudflare has a PoP in. Your origin sees `162.158.x.x` (Cloudflare range), GeoIP attributes it to wherever that PoP is. |
| Akamai → origin pull                           | Same model. Akamai publishes its origin-pull IP ranges; they span multiple continents.                                                                                                                        |
| Fastly → origin pull                           | Same. Fastly publishes IP ranges per PoP.                                                                                                                                                                     |
| Stripe webhooks                                | Stripe serves webhooks from multi-region infrastructure. Their published IP list spans 8+ countries.                                                                                                          |
| Twilio callbacks                               | Same.                                                                                                                                                                                                         |
| GitHub Actions runners                         | GitHub-hosted runners are primarily in `us-east-1` but can spill to other regions.                                                                                                                            |
| Customer SaaS integrations                     | A customer in Country X using a SaaS that runs in Country Y will have their integration traffic appear to come from Country Y.                                                                                |
| VPN-using employees                            | Whatever country the VPN exit node is in.                                                                                                                                                                     |
| Payment-network confirmation (3-D Secure, ACS) | Bank's ACS infrastructure may be in a different country than the cardholder.                                                                                                                                  |

### 2.3 The two design mistakes that cause most geoblock FPs

1. **Allow-list a small set of countries.** "Only allow US, CA, UK" sounds safe but breaks any partner / CDN / VPN traffic from anywhere else, including legitimate users traveling. Hard to maintain.
2. **Deny-list "high-risk" countries.** "Block CN, RU, KP, IR" is more permissive but still breaks legitimate users from those countries (research collaborators, customers, journalists) and third-party traffic legitimately routed through those regions.

The correct default for most B2B SaaS: **don't blanket-geoblock at the edge.** Geoblock by **path** (e.g. block country X only on `/admin/*`), by **risk** (compounded with bot-management signals), or by **per-customer policy** (compliance / sanctions list — applied at the application layer, not the WAF).

### 2.4 Provider mapping

| Provider            | Mechanism                                                                                                                                                      | Notes                                                                                                                                                                                |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **GCP Cloud Armor** | CEL expression `origin.region_code == 'CN'` or `origin.region_code in ['CN', 'RU']`; can be combined with path / IP-range conditions. GeoIP DB is GCP-managed. | `origin.region_code` is the ISO 3166-1 alpha-2 country code.                                                                                                                         |
| **AWS WAF**         | `geo_match_statement` with `country_codes`; can be combined with other statements via `and_statement` / `not_statement`. GeoIP DB is AWS-managed.              | Country codes are ISO 3166-1 alpha-2. `forwarded_ip_config` is needed when traffic transits an additional CDN to look up the X-Forwarded-For IP rather than the immediate client IP. |
| **Cloudflare**      | Rules-language expression `ip.geoip.country eq "CN"` (or `in {"CN" "RU"}`) in `http_request_firewall_custom` phase. GeoIP from Cloudflare's own database.      | Cloudflare additionally exposes `ip.geoip.subdivision_1_iso_code` for sub-country regions (US states, etc.).                                                                         |

---

## 3. The Log Evidence

### 3.1 GCP Cloud Armor

Find requests denied by a country-matching rule:

```text
resource.type="http_load_balancer"
AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
AND jsonPayload.enforcedSecurityPolicy.name="geo-deny-policy"
```

Identify which countries are denied most:

```text
resource.type="http_load_balancer"
AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
AND jsonPayload.enforcedSecurityPolicy.name="geo-deny-policy"
| stats count() by jsonPayload.enforcedSecurityPolicy.priority, httpRequest.remoteIp
```

`gcloud` shortcut to see remote-IPs + their attributed country (requires correlation; Cloud Armor logs include `httpRequest.remoteIp` but not the country code directly):

```bash
gcloud logging read \
  'resource.type="http_load_balancer"
   AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
   AND jsonPayload.enforcedSecurityPolicy.name="geo-deny-policy"' \
  --freshness=1h --limit=50 \
  --format='value(httpRequest.remoteIp,httpRequest.requestUrl,httpRequest.userAgent)'
```

Then look up the IPs in any GeoIP tool (`mmdblookup`, MaxMind GeoLite2) to attribute country.

### 3.2 AWS WAF

```text
fields @timestamp, action, terminatingRuleId, httpRequest.country, httpRequest.uri, httpRequest.clientIp
| filter action = "BLOCK"
| filter terminatingRuleId like /geo/
| sort @timestamp desc
| limit 100
```

`httpRequest.country` is the WAF's GeoIP attribution; visible in WAF logs by default.

### 3.3 Cloudflare

```bash
curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/security/events?datetime_geq=2026-06-17T10:00:00Z" \
  -H "Authorization: Bearer $CF_TOKEN" \
  | jq '.result[] | select(.rule_id == "geo-deny") |
        {ray_id, action, client_country: .client.country, client_ip, uri, occurred_at}'
```

### 3.4 Local reproduction

Use a VPN exit in the target country, or a `curl --interface` with a known IP in that range:

```bash
curl -v --resolve app.example.com:443:<ip-in-target-country> \
     https://app.example.com/ 2>&1 | tail -20
```

Or use a third-party HTTP relay (`https://anytool.example.com/echo`) that exposes its egress IP and confirms its GeoIP attribution.

### 3.5 Offline GeoIP check

```bash
# MaxMind GeoLite2 (free with sign-up).
mmdblookup --file GeoLite2-Country.mmdb --ip 162.158.1.1 country iso_code
# -> "US"
```

For Cloudflare ranges, cross-check with the published list:

```bash
curl -s https://www.cloudflare.com/ips-v4 | head -10
```

If a denied IP is in a published CDN / partner IP range, the geoblock is the wrong tool — switch to an IP allow-list for the partner's range instead of a country-based exception.

---

## 4. The Remediation Matrix

> **Allow-list specific IP ranges, not whole countries.** Cloudflare, Akamai, Fastly, Stripe, Twilio publish authoritative IP-range lists for their infrastructure. Pull those lists into an IP-set allow rule that runs before the geoblock — much narrower than "allow CN" or "allow RU".
>
> **Scope the geoblock by path, not zone-wide.** Blocking `/admin/*` from country X is a defensible posture. Blocking your entire public marketing site from country X loses real customers and creates Support tickets that the WAF tuning playbook can't solve.

### 4.1 GCP Cloud Armor

Geoblock scoped to `/admin/*` with partner-IP allow override:

```hcl
resource "google_compute_security_policy" "geo_policy" {
  name = "geo-deny-policy"

  # Highest precedence: allow published CDN / partner IP ranges everywhere.
  rule {
    action   = "allow"
    priority = 100
    match {
      expr {
        expression = <<-CEL
          inIpRange(origin.ip, '162.158.0.0/15')   // Cloudflare
          || inIpRange(origin.ip, '54.187.174.169/32') // Stripe webhook range, refresh from API quarterly
        CEL
      }
    }
    description = "Allow published CDN/partner IP ranges. Refresh schedule documented in EXCEPTIONS.md."
  }

  # Then: geoblock high-risk countries on /admin/* only.
  rule {
    action   = "deny(403)"
    priority = 500
    match {
      expr {
        expression = <<-CEL
          request.path.startsWith('/admin/')
          && origin.region_code in ['CN', 'RU', 'KP', 'IR']
        CEL
      }
    }
    description = "Geo-deny /admin/* from CN, RU, KP, IR. Marketing/site otherwise open. EXCEPTIONS.md row YYYY-MM-DD."
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config { src_ip_ranges = ["*"] }
    }
    description = "Default allow"
  }
}
```

### 4.2 AWS WAF

Allow partner IP set; then geoblock-on-path; then default-allow:

```hcl
resource "aws_wafv2_ip_set" "partner_and_cdn_ips" {
  name               = "partner-and-cdn"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses = [
    "162.158.0.0/15",          # Cloudflare
    "54.187.174.169/32",       # Stripe webhook (refresh quarterly from Stripe API)
  ]
}

rule {
  name     = "allow-partner-and-cdn"
  priority = 1
  action { allow {} }

  statement {
    ip_set_reference_statement {
      arn = aws_wafv2_ip_set.partner_and_cdn_ips.arn
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "allow-partner-cdn"
    sampled_requests_enabled   = true
  }
}

rule {
  name     = "geo-deny-admin-from-high-risk"
  priority = 50

  action { block {} }

  statement {
    and_statement {
      statement {
        geo_match_statement {
          country_codes = ["CN", "RU", "KP", "IR"]
        }
      }
      statement {
        byte_match_statement {
          field_to_match { uri_path {} }
          positional_constraint = "STARTS_WITH"
          search_string         = "/admin/"
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
    metric_name                = "geo-deny-admin"
    sampled_requests_enabled   = true
  }
}
```

### 4.3 Cloudflare

Custom rule for allow + geoblock:

```hcl
resource "cloudflare_ruleset" "geo_policy" {
  zone_id = var.zone_id
  name    = "Geo policy + partner allow"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules {
    action      = "skip"
    action_parameters {
      ruleset = "current"
      phases  = ["http_request_firewall_managed"]
    }
    expression  = "(ip.src in {54.187.174.169/32})"
    description = "Allow Stripe webhook IPs (refresh quarterly). EXCEPTIONS.md row YYYY-MM-DD."
    enabled     = true
  }

  rules {
    action      = "block"
    expression  = "(starts_with(http.request.uri.path, \"/admin/\") and ip.geoip.country in {\"CN\" \"RU\" \"KP\" \"IR\"})"
    description = "Geo-deny /admin/* from CN/RU/KP/IR. EXCEPTIONS.md row YYYY-MM-DD."
    enabled     = true
  }
}
```

### 4.4 Verification

- Stripe / Twilio webhook deliveries succeed (check partner dashboard for delivery success).
- Internal `curl` from a VPN exit in CN reaching `/admin/login` returns 403.
- Same `curl` reaching `/` returns 200 (marketing site unaffected).
- Traveling employee in CN can reach `/dashboard` (non-admin) without issue.

---

## 5. Audit Trail

```
| 2026-06-17 | app.example.com | gcp-cloud-armor | geo-deny CN/RU/KP/IR on /admin/* | request.path.startsWith('/admin/') | Risk-based scoping: admin endpoints only. Partner IP allow at priority 100 (Cloudflare, Stripe). IP-list refresh schedule: quarterly via vendor API; tracked in JIRA-9202. | <link to log query showing reduced /admin denies>  | preview 2026-06-17 → enforce 2026-06-20 | @secops-lead | 2026-09-15 (quarterly refresh checkpoint) |
```

For partner-IP allows, the **Review by** is whatever the partner's IP-list-refresh cadence is. Stale partner IP lists = silent partial outages.

---

## 6. Common pitfalls

- **Allow whole country instead of partner IP range.** "Allow US so Stripe works" allows all 300 million IPs in the US, including potential attackers. Allow the **published Stripe range** instead — it's typically a few hundred IPs.
- **Static partner IP lists go stale.** Stripe, Twilio, GitHub, Cloudflare, etc. publish IP-list APIs. Pull them on a schedule (quarterly minimum) and update the IP set. Track refresh cadence in the audit row.
- **GeoIP is best-effort.** A blocked IP may be misattributed. Always reproduce with a known-good IP in the target country, and have an explicit appeal path documented for customers who report incorrect blocks.
- **CDN-to-origin attribution.** If your origin is behind Cloudflare/Akamai, your origin sees the CDN PoP's IP. Country attribution will reflect the PoP location, not the end user. To geoblock the end user accurately, either configure the WAF to read `True-Client-IP` / `X-Forwarded-For` (with `forwarded_ip_config` on AWS WAF) or apply the geoblock at the CDN layer where the original client IP is known.
- **Sanctions compliance is an application concern, not a WAF concern.** OFAC / EU sanctions list enforcement must happen at the user account / payment / data layer where you can record the decision auditably. The WAF geoblock is a defense-in-depth helper, not a compliance control.
- **VPN-exit allow rules are sensitive.** Don't allow a VPN-provider IP range globally; it allows all the provider's customers worldwide. Coordinate with your IT / security team for an internal-VPN-only allow scoped to a specific egress IP your VPN concentrator uses.
- **`ip.geoip.country` vs `cf-ipcountry` header.** Cloudflare exposes both. The rules-language form is authoritative for WAF decisions; the header is what your app sees and may be tampered with by a proxy in between. Don't conflate them.
- **Subdivision-level rules (US state, etc.).** Cloudflare and Cloud Armor expose subdivision codes. Use sparingly — US-state-level geoblock for "California only" is rarely the right tool; per-customer policies almost always are.

---

## See also

- [docs/concepts/rate-limiting.md](rate-limiting.md) — same IP-set + Allow-then-Deny composition pattern.
- [docs/rules/913100.md](../rules/913100.md), [docs/rules/921110.md](../rules/921110.md) — IP-allow disciplines for scanners and partner webhooks.
- [docs/provider-guides/gcp-cloud-armor.md](../provider-guides/gcp-cloud-armor.md), [docs/provider-guides/aws-waf.md](../provider-guides/aws-waf.md), [docs/provider-guides/cloudflare-waf.md](../provider-guides/cloudflare-waf.md)
- [EXCEPTIONS.md](../../EXCEPTIONS.md)

---

## References

### Standards & general

- ISO 3166-1 alpha-2 country codes — [https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2).
- MaxMind GeoLite2 (offline GeoIP DB) — [https://dev.maxmind.com/geoip/geolite2-free-geolocation-data](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).

### Partner / CDN IP-list sources

- Cloudflare IP ranges — [https://www.cloudflare.com/ips/](https://www.cloudflare.com/ips/).
- Akamai origin IP ranges — [https://techdocs.akamai.com/origin-ip-acl/docs](https://techdocs.akamai.com/origin-ip-acl/docs).
- Fastly IP ranges — [https://api.fastly.com/public-ip-list](https://api.fastly.com/public-ip-list).
- Stripe webhook IP ranges — [https://stripe.com/docs/ips](https://stripe.com/docs/ips).
- Twilio IP ranges — [https://www.twilio.com/docs/sip-trunking/ip-addresses](https://www.twilio.com/docs/sip-trunking/ip-addresses).
- GitHub Actions runner IP ranges — [https://api.github.com/meta](https://api.github.com/meta).

### Google Cloud Armor

- Custom rules — geo expressions (`origin.region_code`) — [https://cloud.google.com/armor/docs/rules-language-reference#attributes](https://cloud.google.com/armor/docs/rules-language-reference#attributes).
- Cloud Armor request logging — [https://cloud.google.com/armor/docs/request-logging](https://cloud.google.com/armor/docs/request-logging).

### AWS WAF

- `geo_match_statement` — [https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-geo-match.html](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-geo-match.html).
- `forwarded_ip_config` for X-Forwarded-For-based geo lookup — [https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-forwarded-ip.html](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-forwarded-ip.html).

### Cloudflare

- Rules language — geographic fields (`ip.geoip.country`, `ip.geoip.subdivision_1_iso_code`) — [https://developers.cloudflare.com/ruleset-engine/rules-language/fields/#field-ip-geoip-country](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/#field-ip-geoip-country).
- IP Access Rules (zone-level allow / challenge / block by country) — [https://developers.cloudflare.com/waf/tools/ip-access-rules/](https://developers.cloudflare.com/waf/tools/ip-access-rules/).
