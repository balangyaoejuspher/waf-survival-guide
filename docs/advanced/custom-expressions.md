# Multi-Conditional Custom Expressions

> **Scope of this file:** writing complex multi-conditional WAF expressions across Google Cloud Armor (CEL), AWS WAF (Statement composition), and Cloudflare (Rules Language) — including operator precedence, regex inside expressions, IP-set composition, header / cookie / body field references, anti-patterns that look like they work but don't, performance characteristics, and idioms for the common patterns (per-customer carve-outs, per-method scoping, time-windowed allows, region + path + IP composition).

---

## 1. The Symptom

| Cross-provider signature | Where you see it |
| --- | --- |
| A custom rule "works in staging" but blocks legitimate traffic in production because operator precedence behaves differently than expected | Production incident |
| `terraform plan` reports the rule changed but `terraform apply` produces no behavior change because the expression parses but matches nothing | CI logs |
| An expression involving a header that may be missing returns rule-evaluation errors and the rule is treated as no-match | Edge log shows "rule evaluation error" or rule appears to be silently ignored |
| Same rule expressed in two providers behaves differently because of subtle operator semantics (case sensitivity, default behavior on missing field, list vs set membership) | Cross-cloud migration |
| Expressions get long and fragile; a small typo in one branch causes the whole rule to behave incorrectly | Code review pain |

Distinguishing fingerprint: the rule is doing **something different than what was intended**, and the gap is usually in the expression's logic, not the action.

---

## 2. The Diagnosis

### 2.1 The three expression languages

| Provider | Language | Style |
| --- | --- | --- |
| **GCP Cloud Armor** | CEL (Common Expression Language), Google's subset | Boolean expressions over named attributes (`request.path`, `origin.ip`, `request.headers['user-agent']`); functions like `inIpRange()`, `evaluatePreconfiguredWaf()` |
| **AWS WAF** | Structured JSON of nested "statements" (no expression language — every operator is a JSON object type) | Boolean tree of `AndStatement`, `OrStatement`, `NotStatement`, `ByteMatchStatement`, `RegexMatchStatement`, `IPSetReferenceStatement`, `GeoMatchStatement`, etc. |
| **Cloudflare** | Wireshark-like filter syntax, custom Rules Language | Field-and-operator expressions: `(http.request.uri.path eq "/admin" and ip.geoip.country in {"CN"})` |

### 2.2 Operator precedence and grouping

**Cloud Armor CEL:**

- Precedence: `!` > `*`, `/`, `%` > `+`, `-` > `<`, `<=`, `>`, `>=` > `==`, `!=` > `in` > `&&` > `||`
- **Always parenthesize** AND/OR mixes: `(A && B) || C` and `A && (B || C)` are different rules.
- CEL short-circuits AND/OR left-to-right; put cheap checks first.

**AWS WAF JSON:**

- No precedence question — explicit `AndStatement` / `OrStatement` / `NotStatement` nesting.
- The pain is verbosity: a 3-condition AND is ~80 lines of nested JSON.
- `NotStatement` wraps exactly one child; "not (A and B)" requires `NotStatement{ AndStatement{...} }`.

**Cloudflare Rules Language:**

- Precedence: `not` > `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `contains`, `matches`, `in` > `and` > `xor` > `or`
- Always parenthesize AND/OR mixes — same rule as CEL.
- Short-circuits left-to-right.

### 2.3 Field defaults when missing

**Cloud Armor CEL:**

- A missing header (`request.headers['x-foo']` when header is absent) → empty string `""`, not an error.
- `inIpRange(origin.ip, '...')` on a missing/unknown IP → false.
- Type coercion is strict: `request.headers['x'] == 1` is a type error.

**AWS WAF:**

- Missing fields produce "rule evaluation error" → the rule is treated as **no-match** for that request.
- Use `OversizeHandling` (`MATCH` / `NO_MATCH` / `CONTINUE`) on body fields to control behavior when content exceeds inspection size.

**Cloudflare:**

- Missing fields → expression treats them as not-present. `http.request.headers["x-foo"][0] eq "y"` on absent header → false (not error).
- `http.cookie contains "SESSION="` on absent Cookie header → false.

### 2.4 Regex inside expressions

| Provider | Regex form | Notes |
| --- | --- | --- |
| **Cloud Armor CEL** | `request.path.matches('^/admin/.*$')` — Google RE2 syntax | No backreferences. |
| **AWS WAF** | `RegexMatchStatement` + standalone `RegexPatternSet`; AWS regex flavor is PCRE-like with restrictions | Regex match is a separate statement; can be combined with `AndStatement`. |
| **Cloudflare** | `http.request.uri.path matches "^/admin/.*$"` — RE2 | No backreferences. |

### 2.5 IP-set composition

| Provider | IP set form | Notes |
| --- | --- | --- |
| **Cloud Armor CEL** | `inIpRange(origin.ip, '10.0.0.0/8')` — single CIDR per call; combine with OR for multiple | No native named IP-set object; use lists in code or `inIpRange()` chains. |
| **AWS WAF** | Named `aws_wafv2_ip_set` referenced via `IPSetReferenceStatement` | Updatable independently of rules; supports very large sets. |
| **Cloudflare** | `ip.src in {10.0.0.0/8 192.168.0.0/16}` literal, or named **IP Lists** referenced via `$list_name` | IP Lists support tens of thousands of entries; updatable via API/Terraform. |

---

## 3. Worked Examples — Same Policy Across Three Providers

The example policy: **block POST /api/v1/users from country X UNLESS the request carries a known internal-API key OR comes from an allow-listed CIDR, and only block when the bot score is below 30**.

### 3.1 Cloud Armor (CEL)

```hcl
rule {
  action   = "deny(403)"
  priority = 500
  preview  = true

  match {
    expr {
      expression = <<-CEL
        request.path == '/api/v1/users'
        && request.method == 'POST'
        && origin.region_code == 'CN'
        && !(
          request.headers['x-internal-api-key'] == 'expected-value-from-secret'
          || inIpRange(origin.ip, '10.0.0.0/8')
        )
        && origin.bot.score < 30
      CEL
    }
  }
  description = "Block POST /api/v1/users from CN unless internal API key or internal CIDR, low bot score only. EXCEPTIONS.md row YYYY-MM-DD."
}
```

Notes:
- `!(allow_set)` inverts the carve-out — the canonical pattern for "block X EXCEPT when Y or Z".
- The header check is plain equality; for secret-rotation, prefer `request.headers['x-internal-api-key'].matches('^(sig1|sig2)$')` and rotate the regex on schedule.
- Bot score on Cloud Armor requires Bot Management; without it, drop that clause.

### 3.2 AWS WAF (JSON / Terraform)

```hcl
rule {
  name     = "deny-post-users-cn-unless-internal"
  priority = 500
  action { block {} }

  statement {
    and_statement {
      statement {
        byte_match_statement {
          field_to_match { uri_path {} }
          positional_constraint = "EXACTLY"
          search_string         = "/api/v1/users"
          text_transformation { priority = 0; type = "NONE" }
        }
      }
      statement {
        byte_match_statement {
          field_to_match { method {} }
          positional_constraint = "EXACTLY"
          search_string         = "POST"
          text_transformation { priority = 0; type = "NONE" }
        }
      }
      statement {
        geo_match_statement {
          country_codes = ["CN"]
        }
      }
      statement {
        not_statement {
          statement {
            or_statement {
              statement {
                byte_match_statement {
                  field_to_match {
                    single_header { name = "x-internal-api-key" }
                  }
                  positional_constraint = "EXACTLY"
                  search_string         = "expected-value-from-secret"
                  text_transformation { priority = 0; type = "NONE" }
                }
              }
              statement {
                ip_set_reference_statement {
                  arn = aws_wafv2_ip_set.internal_cidrs.arn
                }
              }
            }
          }
        }
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "deny-cn-post-users"
    sampled_requests_enabled   = true
  }
}
```

Bot score on AWS requires `AWSManagedRulesBotControlRuleSet` enabled; you'd either chain a `ManagedRuleGroupStatement` allowing only when bot signals indicate human, or use AWS Shield Advanced's bot signals — both are heavier patterns than the CF / GCP equivalents.

### 3.3 Cloudflare (Rules Language)

```hcl
rules {
  action     = "block"
  expression = <<-RL
    (http.request.uri.path eq "/api/v1/users"
     and http.request.method eq "POST"
     and ip.geoip.country eq "CN"
     and not (
       http.request.headers["x-internal-api-key"][0] eq "expected-value-from-secret"
       or ip.src in $internal_cidrs
     )
     and cf.bot_management.score lt 30)
  RL
  description = "Block POST /api/v1/users from CN unless internal API key or internal IPs, low bot score only. EXCEPTIONS.md row YYYY-MM-DD."
  enabled     = true
}
```

Notes:
- `$internal_cidrs` is a named Cloudflare IP List (defined separately).
- `http.request.headers["x-internal-api-key"][0]` — headers are arrays (can repeat); `[0]` takes the first value.
- `cf.bot_management.score` requires Bot Management subscription.

---

## 4. Common Idioms

### 4.1 Per-customer carve-out (allow customer A on path X)

**CEL:**

```
inIpRange(origin.ip, '203.0.113.0/24')
|| request.headers['x-customer-id'] == 'customer-a'
```

**Cloudflare:**

```
(ip.src in $customer_a_cidrs or http.request.headers["x-customer-id"][0] eq "customer-a")
```

**AWS:** `OrStatement` over `IPSetReferenceStatement` + `ByteMatchStatement{ field=single_header{name="x-customer-id"} }`.

### 4.2 Time-windowed allow (allow during scheduled maintenance window)

Most WAFs don't have built-in time conditions. Three approaches:

1. **Manual enable/disable.** Terraform `count = var.maintenance_window ? 1 : 0` on the allow rule; `terraform apply` before the window, again after.
2. **Cloudflare Workers / GCP Cloud Functions.** A small function at the edge that checks the current time before allowing.
3. **External orchestration.** Have a scheduler (Jenkins, GitHub Actions) flip the rule via API at window start/end.

Approach 1 is the cleanest for predictable windows; document the planned enable/disable in the audit row.

### 4.3 Method-set scoping (POST/PUT/PATCH together)

**CEL:**

```
request.method in ['POST', 'PUT', 'PATCH']
```

**Cloudflare:**

```
http.request.method in {"POST" "PUT" "PATCH"}
```

**AWS:** `OrStatement` of three `ByteMatchStatement{ field=method, search_string="POST"/"PUT"/"PATCH", positional_constraint=EXACTLY }`.

### 4.4 Header-presence check (header exists vs has specific value)

**CEL:**

```
size(request.headers['x-foo']) > 0   // present and non-empty
request.headers['x-foo'] == 'bar'    // present and equals 'bar'
```

**Cloudflare:**

```
any(http.request.headers.names[*] == "x-foo")    // present (any value)
http.request.headers["x-foo"][0] eq "bar"        // present and equals 'bar'
```

**AWS:** `SizeConstraintStatement{ field=single_header{name="x-foo"}, size=0, comparison=GREATER_THAN }`.

### 4.5 JSON body field reference (require `Content-Type: application/json` for the WAF to parse JSON)

**Cloud Armor:** configure `advanced_options_config.json_parsing = "STANDARD"` on the security policy; then `ARGS` exposes leaf JSON field values.

**AWS WAF:** use `JsonBody` field-to-match with `JsonMatchScope = "VALUE"` and an optional `JsonMatchPattern`.

**Cloudflare:** the `lookup_json_string(http.request.body.raw, "field.path")` function in expressions; or use `Transform Rule` + `Skip` patterns.

### 4.6 Regex matching against multiple alternatives (efficient form)

Single regex with alternation is **much** cheaper than multiple OR-ed regex statements:

```
# Bad (one regex per alternative — N regex evaluations per request):
request.path.matches('^/admin/.*$') || request.path.matches('^/api/v1/admin/.*$') || ...

# Good (one regex with alternation):
request.path.matches('^/(?:admin|api/v1/admin)/.*$')
```

This is a real cost driver at high RPS.

---

## 5. Anti-patterns

### 5.1 The "AND with OR without parens"

**Bug:**

```
ip.src in $partners or http.request.uri.path eq "/" and http.request.method eq "POST"
```

This parses as `partners OR (path=="/" AND method=="POST")` because `and` binds tighter than `or`. It is **not** "partners AND (path=="/" OR method=="POST")" or anything similar. Always parenthesize.

### 5.2 The "missing field → silent no-match"

**Bug (AWS):** rule "block when X-Custom-Header is `bad`" — without an `OversizeHandling` or a presence-check, an absent header makes the rule no-match (the request passes). If the intent was "block requests without the right header value too", express it as `NotStatement{ ByteMatchStatement{ ... "good" ... } }`.

### 5.3 The "regex of doom"

A regex with nested quantifiers can blow up evaluation time (`(a+)+`-style — ReDoS in the WAF). Most WAF regex engines are RE2-based and immune to ReDoS, but PCRE-based ones aren't. Test regex performance with worst-case inputs before deploying.

### 5.4 The "header value injection"

Some apps look at `X-Forwarded-For` and pick the first IP. An attacker who can set `X-Forwarded-For: 10.0.0.1, attacker-ip` defeats your IP-based logic. Either trust only the **last** XFF entry (the one set by your immediate proxy) or use `origin.ip` / equivalent provider-controlled fields.

### 5.5 The "case sensitivity surprise"

Cloud Armor's `request.headers['user-agent']` is case-insensitive on lookup (HTTP header names are case-insensitive), but the **value comparison** is case-sensitive. `request.headers['user-agent'] == 'Mozilla/5.0'` will not match `mozilla/5.0`. Apply transformations (`t:lowercase` on AWS) or use `.contains()` / `.matches('(?i)...')` for case-insensitive comparisons.

---

## 6. Performance and operational notes

- **Short-circuit cheap checks first.** Path match is cheap; regex match is medium; IP-set match is fast for small sets but cost grows with set size. Put cheap, high-selectivity conditions first.
- **Named IP sets > literal CIDR lists.** Updatable independently of the rule; faster lookup; auditable separately.
- **One rule per intent, not per condition.** A 20-condition rule is hard to read and easy to mis-tune. Split into multiple rules with different priorities/actions when feasible.
- **Test in preview / count / log mode before enforcing.** Especially for compound rules — the FP rate can be unexpectedly high when an `and` chain accidentally narrows or widens the match.
- **Document the rule's intent in the description field.** "Block CN POST to /api/v1/users unless internal" — future you needs to know what the original goal was.
- **Cross-cloud parity is non-trivial.** A literal-translation between providers may behave differently because of operator semantics, missing-field defaults, or IP-list behavior. Test the translated rule against representative requests, not just review the syntax.

---

## See also

- [docs/concepts/rate-limiting.md](../concepts/rate-limiting.md), [docs/concepts/geoblocking-exceptions.md](../concepts/geoblocking-exceptions.md), [docs/concepts/payload-size.md](../concepts/payload-size.md) — concrete cases that drive multi-conditional rule design.
- [docs/rules/942100.md](../rules/942100.md), [docs/rules/941160.md](../rules/941160.md), [docs/rules/913100.md](../rules/913100.md), [docs/rules/921110.md](../rules/921110.md) — per-rule pages whose remediation matrices contain real multi-conditional expressions.
- [docs/advanced/anomaly-scoring.md](anomaly-scoring.md) — multi-axis composition (anomaly + bot + reputation) is itself a multi-conditional pattern.
- [docs/provider-guides/gcp-cloud-armor.md](../provider-guides/gcp-cloud-armor.md), [docs/provider-guides/aws-waf.md](../provider-guides/aws-waf.md), [docs/provider-guides/cloudflare-waf.md](../provider-guides/cloudflare-waf.md)
- [EXCEPTIONS.md](../../EXCEPTIONS.md)

---

## References

### Google Cloud Armor

- Rules language reference (full attribute / function list) — [https://cloud.google.com/armor/docs/rules-language-reference](https://cloud.google.com/armor/docs/rules-language-reference).
- CEL specification (Google's subset) — [https://github.com/google/cel-spec](https://github.com/google/cel-spec).
- Custom rules in Cloud Armor — [https://cloud.google.com/armor/docs/rules-language-reference](https://cloud.google.com/armor/docs/rules-language-reference).

### AWS WAF

- WAF Statements (Boolean composition) — [https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statements.html](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statements.html).
- Regex pattern sets — [https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-regex-pattern-set-match.html](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-regex-pattern-set-match.html).
- IP-set reference statement — [https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-ipset-match.html](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-ipset-match.html).
- JSON body inspection — [https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields-body-json.html](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields-body-json.html).
- Terraform `aws_wafv2_web_acl` — [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl).

### Cloudflare

- Rules Language overview — [https://developers.cloudflare.com/ruleset-engine/rules-language/](https://developers.cloudflare.com/ruleset-engine/rules-language/).
- Operators and precedence — [https://developers.cloudflare.com/ruleset-engine/rules-language/operators/](https://developers.cloudflare.com/ruleset-engine/rules-language/operators/).
- Field index (all `http.*`, `ip.*`, `cf.*` fields) — [https://developers.cloudflare.com/ruleset-engine/rules-language/fields/](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/).
- Functions (`lookup_json_string`, `any`, `lower`, `concat`, etc.) — [https://developers.cloudflare.com/ruleset-engine/rules-language/functions/](https://developers.cloudflare.com/ruleset-engine/rules-language/functions/).
- IP Lists — [https://developers.cloudflare.com/waf/tools/lists/](https://developers.cloudflare.com/waf/tools/lists/).
- Terraform `cloudflare_ruleset` — [https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/ruleset](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/ruleset).
