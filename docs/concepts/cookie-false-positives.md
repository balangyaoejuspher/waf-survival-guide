# Cookie & JWT False Positives — OWASP CRS Rule `942100`

> The flagship false positive. A long session cookie or JWT trips the SQL-injection detector and every authenticated request returns `403`. This page is the canonical playbook.

---

## 1. The Symptom

What the user / browser / client sees:

- **HTTP `403 Forbidden`** on every authenticated request.
- The failure is **per-user**, not global — it correlates with users whose session cookie or JWT happens to contain certain byte sequences.
- The failure starts **immediately after** an unrelated change: a new auth provider, a JWT signing-key rotation, a longer session payload, a new "remember me" cookie.
- `curl` without the `Cookie:` / `Authorization:` header returns `401` or `200` (depending on route) — the **presence of the credential** is what trips the block.
- The response body is typically a generic provider block page (Google "Your client does not have permission...", AWS generic `Forbidden`, Cloudflare branded error 1020), **not** your app's own JSON error envelope.
- Application container logs are **empty** for the failing request.

If those five lines match, you are almost certainly looking at rule `942100` (or a sibling in the `942xxx` family) firing on a cookie or header parameter.

---

## 2. The Diagnosis

### Why this happens

OWASP CRS rule `942100` is the **`libinjection`-based** SQL-injection detector. Unlike pattern-based SQLi rules, `libinjection` tokenizes the input and decides if the **token stream** looks like SQL grammar.

Three properties of modern session credentials make `libinjection` very twitchy:

1. **High entropy / base64-ish payloads.** A JWT is three dot-separated base64url segments. A signed session cookie often base64-encodes a serialized struct. `libinjection`'s tokenizer happily reads base64 padding (`==`), separators (`.`, `-`, `_`) and the occasional `select`/`from`/`or`/`and` substring that randomly appears in base64 output as SQL tokens.
2. **Length.** Long inputs give the tokenizer more opportunities to assemble a "fingerprint" that matches a known SQLi grammar.
3. **Field type.** `942100` inspects **all `ARGS`** by default, including `request_cookies` and selected headers. Cookies are the highest-cardinality, highest-entropy field in most requests — they win the false-positive lottery.

### Sibling rules to be aware of

| Rule     | What it catches                          | Why it co-fires                                                        |
| -------- | ---------------------------------------- | ---------------------------------------------------------------------- | --- |
| `942100` | `libinjection` SQLi fingerprint          | The base rule — usually the terminating one.                           |
| `942130` | SQL boolean-based injection patterns     | Hits on strings like `or 1=1` that appear by chance in base64.         |
| `942260` | Basic SQL authentication bypass attempts | Hits on `' or '1'='1` sub-patterns.                                    |
| `932xxx` | OS command injection                     | Occasionally co-fires when a cookie contains characters like `;` `&` ` | `.  |

**You will commonly see two or three of these in the same log row.** Treat the _terminating_ rule (the one that actually blocked) as the target for the exclusion, but verify in preview mode that the others don't fire next.

### What the rule is **not** wrong about

`libinjection` is not buggy. It is doing exactly what it is designed to do — flagging inputs that look like SQL grammar. The mismatch is **deployment context**: a session cookie is structurally indistinguishable from a SQLi payload to a generic SQL parser. The fix is to tell the WAF _"this specific field on this specific path is not a SQL surface"_, not to silence the detector globally.

---

## 3. The Log Evidence

You need to confirm: (a) rule `942100` fired, (b) the matched field was a cookie or header, (c) the matched value is the user's legitimate session credential.

### GCP Cloud Armor (Cloud Logging)

```text
resource.type="http_load_balancer"
AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
AND jsonPayload.enforcedSecurityPolicy.preconfiguredExprIds:"owasp-crs-v030301-id942100-sqli"
```

Inspect on the matching row:

- `jsonPayload.enforcedSecurityPolicy.name` — which security policy triggered.
- `jsonPayload.enforcedSecurityPolicy.preconfiguredExprIds` — full list of CRS rules matched on this request (often includes `942130`, `942260` alongside `942100`).
- `httpRequest.requestUrl` — the path. Note it; the exclusion will be scoped to it.
- `httpRequest.userAgent`, `httpRequest.remoteIp` — sanity-check it's a real client, not a scanner.

Cloud Armor does **not** log request headers or bodies by default. To prove which cookie tripped the rule, reproduce the request with `curl -v` and correlate by timestamp + remote IP + path.

### AWS WAF (CloudWatch Logs Insights)

```text
fields @timestamp, action, terminatingRuleId, terminatingRuleMatchDetails, httpRequest.uri
| filter action = "BLOCK"
| filter terminatingRuleId like /942100/ or terminatingRuleId like /SQLi/
| sort @timestamp desc
| limit 50
```

`terminatingRuleMatchDetails` contains the **matched field name and the matched data** (redacted by default; full visibility requires the WAF to be configured with sampled requests or `LoggingFilter` rules). Look for `Cookie` or specific cookie-name keys.

### Cloudflare (Security Events)

Dashboard → **Security → Events** → filter:

- **Action:** `Managed Challenge` or `Block`
- **Rule:** `OWASP_CRS_V032_942100` (the exact rule ID surfaces under the _Rule_ column once you expand a row).
- **Host:** your hostname.

Each event row exposes the matched field under **Match details** when "Log full HTTP request" is enabled for the ruleset (it is **off** by default; enabling it has cost and privacy implications — confirm with SecOps first).

---

## 4. The Remediation Matrix

The fix is **always the same shape**: scope a **target exclusion** that removes the _specific cookie field_ from the input set of _rule `942100`_ on the _specific path_, then roll out in **preview / count mode** for 72 hours before enforcing.

> **Never** blanket-disable `942100`. It is the most effective rule in the CRS SQLi family. Scope. Always scope.

### GCP Cloud Armor

**Console click-path:**

1. **Cloud Console → Network Security → Cloud Armor policies**.
2. Open the policy attached to your backend service.
3. **Rules → + Add rule** → **Mode: Preconfigured WAF rules**.
4. Expression: `evaluatePreconfiguredWaf('sqli-v33-stable', {'opt_out_rule_ids': ['owasp-crs-v030301-id942100-sqli']})` — **on a higher-priority rule scoped by path** (`request.path.matches('/login')`).
5. Action: `Allow` (or `Deny` with `preconfiguredExprIds` removed for that path).
6. Set **Preview mode** ON. Save.
7. Wait 72h. Inspect `previewedSecurityPolicy` entries in the log. If clean, flip preview OFF.

> Cloud Armor does not support per-field exclusions at the same granularity as AWS / Cloudflare. The accepted pattern is **path-scoped `opt_out_rule_ids`** for the affected route only.

**Terraform (path-scoped opt-out):**

```hcl
resource "google_compute_security_policy" "app" {
  name = "app-armor-policy"

  rule {
    action   = "allow"
    priority = 900
    preview  = true

    match {
      expr {
        expression = "request.path.matches('/login')"
      }
    }

    preconfigured_waf_config {
      exclusion {
        target_rule_set = "sqli-v33-stable"
        target_rule_ids = ["owasp-crs-v030301-id942100-sqli"]

        request_cookie {
          operator = "EQUALS"
          value    = "SESSIONID"
        }
      }
    }

    description = "Exclude SESSIONID cookie from 942100 on /login. See EXCEPTIONS.md row YYYY-MM-DD."
  }

  rule {
    action   = "deny(403)"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config { src_ip_ranges = ["*"] }
    }
    description = "Default rule"
  }
}
```

After 72h of clean preview logs:

```bash
gcloud compute security-policies rules update 900 \
  --security-policy=app-armor-policy \
  --no-preview
```

### AWS WAF

**Console click-path:**

1. **WAF & Shield → Web ACLs → your ACL → Rules**.
2. Edit the rule group `AWSManagedRulesCommonRuleSet` (or your equivalent SQLi group) → **Rule group action overrides** → set rule `SQLi_COOKIE` (or the specific `942100`-equivalent) to **Count** for the ACL.
3. Better: add a **scope-down statement** so the override applies only to `URI path starts with /login` AND inspect `Cookie: SESSIONID` only.
4. Save. Monitor `Count` metric in CloudWatch for 72h.
5. Once clean, convert the override to a permanent rule-action override **scoped to the path**.

**Terraform (scoped override + cookie exclusion):**

```hcl
resource "aws_wafv2_web_acl" "app" {
  name  = "app-acl"
  scope = "REGIONAL"

  default_action { allow {} }

  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action { none {} }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        rule_action_override {
          name = "SQLi_COOKIE"
          action_to_use { count {} }
        }

        scope_down_statement {
          byte_match_statement {
            field_to_match { uri_path {} }
            positional_constraint = "STARTS_WITH"
            search_string         = "/login"
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
      metric_name                = "common-ruleset"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "app-acl"
    sampled_requests_enabled   = true
  }
}
```

`Count` is AWS's equivalent of preview mode. Promote to `none {}` override (full allow, scoped) once the count metric is stable and the alternative — adding an explicit allow with cookie inspection exclusion — has been reviewed.

### Cloudflare WAF

**Dashboard click-path:**

1. **Security → WAF → Managed rules → Cloudflare Managed Ruleset → Edit**.
2. Find rule `OWASP_CRS_V032_942100` (or the active CRS package equivalent).
3. **+ Add override** → scope by **URI Path equals `/login`** → **Action: Log** (Cloudflare's preview equivalent).
4. Save. Watch **Security → Events** for 72h.
5. Once clean, change the override action from **Log** to **Skip** — and keep the URI path scope.

**Terraform (managed-ruleset override, scoped):**

```hcl
resource "cloudflare_ruleset" "managed_waf_override" {
  zone_id     = var.zone_id
  name        = "Managed WAF overrides"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules {
    action = "execute"
    action_parameters {
      id = "efb7b8c949ac4650a09736fc376e9aee" # Cloudflare Managed Ruleset

      overrides {
        rules {
          id             = "<rule-id-for-942100>"
          action         = "log"        # preview-equivalent; switch to "skip" after soak
          status         = "enabled"
        }
      }
    }

    expression  = "(http.host eq \"app.example.com\" and starts_with(http.request.uri.path, \"/login\"))"
    description = "Preview-skip 942100 on /login for SESSIONID cookie FP. See EXCEPTIONS.md YYYY-MM-DD."
    enabled     = true
  }
}
```

Cloudflare's managed rules do not expose per-cookie field exclusions in the same way AWS does; the standard pattern is **path scoping** + rule-level skip. If you need finer granularity, convert to a custom rule that runs `Skip → Managed rules` for requests that match `http.cookie ~ "SESSIONID="` on `/login` only.

---

## 5. Audit Trail Entry

Append the following row to [../../EXCEPTIONS.md](../../EXCEPTIONS.md) the moment the exclusion lands in preview mode (not after enforce — preview hits matter):

```
| 2026-06-17 | app.example.com | gcp-cloud-armor | 942100 | request_cookies.SESSIONID on /login | Long signed session cookie tripping libinjection; verified harmless via reproduction in staging. | <link to log query result + curl trace> | preview 2026-06-17 → enforce 2026-06-20 | @platform-lead | 2026-12-14 |
```

The **Review by** date defaults to +180 days. At that point, the exclusion gets re-validated against current traffic — if zero hits in preview mode without it, the row is struck through and the exclusion removed.

---

## Common pitfalls

- **Excluding the wrong field name.** Field-name matching is exact and case-sensitive on most providers. `Cookie` vs `cookie` vs `SESSIONID` vs `sessionid` will silently fail to match. Verify via a preview-mode hit count after applying — if hits stay at zero **and** the original `942100` denies persist, your exclusion is misnamed.
- **Excluding too broadly.** "Exclude all cookies from 942100 site-wide" is the _default tempting fix_. It also removes SQLi inspection from every cookie on every path, including `admin_token` on `/admin`. Always scope by **path** AND **specific cookie name**.
- **Forgetting the sibling rules.** After the exclusion, watch the next 72h of preview logs for `942130` / `942260` firing on the same field. If they do, extend the exclusion to those rule IDs **only** — never to the whole `942xxx` family.
- **Re-using the exclusion across services.** Each service is its own audit trail row in `EXCEPTIONS.md`. Do not copy-paste exclusions across security policies without re-validating the cookie shape.
- **Cookie value changes after auth-provider migration.** If you migrate to a new SSO and cookie format changes, the _original_ exclusion may become unnecessary and a _new_ false positive may emerge. Re-run triage; do not assume the existing exclusion still applies.

---

## See also

- [../triage/README.md](../triage/README.md) — the 5-minute flow that leads here.
- [../provider-guides/gcp-cloud-armor.md](../provider-guides/gcp-cloud-armor.md) — full Cloud Armor reference: log fields, preview/enforce, opt-out vs allow patterns.
- [../provider-guides/aws-waf.md](../provider-guides/aws-waf.md) — full AWS WAF reference: scope-down statements, rule-action overrides, Count metric soak.
- [../provider-guides/cloudflare-waf.md](../provider-guides/cloudflare-waf.md) — full Cloudflare reference: managed rule overrides, custom skip rules.
- [../../EXCEPTIONS.md](../../EXCEPTIONS.md) — the ledger where the approved exclusion lives.
