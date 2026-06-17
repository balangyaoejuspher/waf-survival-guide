# AWS WAF â€” Provider Reference

> Stub. Console click-paths, AWS CLI, and Terraform / CloudFormation snippets for diagnosing and safely tuning AWS WAF v2 Web ACLs. Expand alongside concrete reproductions.

---

## 1. The Symptom

- `403 Forbidden` returned by an ALB / CloudFront / API Gateway endpoint that has a Web ACL attached.
- Response body is a small generic page (CloudFront branded if served at CloudFront edge).
- App / target group log shows no entry for the request.

---

## 2. The Diagnosis

AWS WAF v2 evaluates a **Web ACL** of rules on each request. A rule can be:

- A managed rule group (`AWSManagedRulesCommonRuleSet`, `AWSManagedRulesSQLiRuleSet`, etc. â€” these map to OWASP CRS-like rule families).
- A rate-based statement.
- A custom rule (regex / IP set / byte match / SQLi / XSS statement).

A managed rule's action can be overridden at the ACL level via **rule-action override** (per rule name) or **override action: Count** (entire group switched to count-only).

---

## 3. The Log Evidence

Web ACL logging must be enabled (Kinesis Firehose â†’ S3 / CloudWatch Logs). With CloudWatch Logs Insights:

```text
fields @timestamp, action, terminatingRuleId, terminatingRuleType, terminatingRuleMatchDetails, httpRequest.uri, httpRequest.clientIp
| filter action = "BLOCK"
| sort @timestamp desc
| limit 100
```

Key fields:

| Field                         | Meaning                                                                 |
| ----------------------------- | ----------------------------------------------------------------------- |
| `action`                      | `ALLOW` / `BLOCK` / `COUNT` / `CAPTCHA` / `CHALLENGE`                   |
| `terminatingRuleId`           | The rule that decided the action                                        |
| `terminatingRuleType`         | `MANAGED_RULE_GROUP`, `RATE_BASED`, `REGULAR`                           |
| `terminatingRuleMatchDetails` | For SQLi/XSS managed rules, includes matched field name + redacted data |
| `nonTerminatingMatchingRules` | Other rules that matched but didn't terminate                           |
| `httpRequest.headers`         | Request headers (subject to logging filter)                             |

### AWS CLI shortcuts

```bash
# List Web ACLs in a region
aws wafv2 list-web-acls --scope REGIONAL --region us-east-1

# Get rules of a Web ACL
aws wafv2 get-web-acl --name app-acl --scope REGIONAL --id <id> --region us-east-1

# Sampled requests for a rule in last hour
aws wafv2 get-sampled-requests \
  --web-acl-arn <acl-arn> \
  --rule-metric-name common-ruleset \
  --scope REGIONAL \
  --time-window StartTime=$(date -u -d '1 hour ago' +%s),EndTime=$(date -u +%s) \
  --max-items 100
```

---

## 4. The Remediation Matrix

AWS WAF tunes via **rule-action overrides** + **scope-down statements**. Always pair with **Count action** (AWS's preview equivalent) for the 72h soak.

### Rule-action override on a managed group, path-scoped

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
          action_to_use { count {} }   # 72h soak, then promote
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

After 72h with CloudWatch metric `BlockedRequests` flat for that rule, promote the override from `count {}` to the more permanent `none {}` form (allow with the scope-down statement intact), or replace it with an explicit allow rule above the managed group.

### Field-redaction logging filter

To inspect cookie / header values in sampled requests without leaking them to long-term storage, attach a `LoggingFilter` that **redacts** the credential field:

```hcl
resource "aws_wafv2_web_acl_logging_configuration" "app" {
  resource_arn            = aws_wafv2_web_acl.app.arn
  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf.arn]

  redacted_fields {
    single_header { name = "cookie" }
  }
  redacted_fields {
    single_header { name = "authorization" }
  }
}
```

---

## 5. Audit Trail

Each `rule_action_override` whose `action_to_use` is anything other than the managed group's default gets a row in [../../EXCEPTIONS.md](../../EXCEPTIONS.md). Reference the row in a Terraform `description` or comment on the resource so the link survives `terraform plan` diffs.

---

## Common pitfalls

- **`override_action { count {} }` is NOT a per-rule override.** It switches the **entire managed group** to count. Use `rule_action_override` for per-rule overrides.
- **Scope-down statements only apply to managed groups / rate-based rules**, not to custom regular rules. For regular rules, encode the path filter directly in the statement.
- **Default action precedence.** Default-allow + block rules is the standard pattern. If you accidentally configure default-block + scattered allow rules, a missing allow looks like a WAF false positive but is actually configuration intent.
- **CloudFront vs Regional scope.** A CloudFront-scoped ACL lives in `us-east-1` only; a Regional ACL lives in the same region as the protected resource. Looking in the wrong region returns "no rules" which is misleading.

---

## See also

- [../triage/README.md](../triage/README.md)
- [../concepts/cookie-false-positives.md](../concepts/cookie-false-positives.md)
- [gcp-cloud-armor.md](gcp-cloud-armor.md), [cloudflare-waf.md](cloudflare-waf.md)
- [../../EXCEPTIONS.md](../../EXCEPTIONS.md)
