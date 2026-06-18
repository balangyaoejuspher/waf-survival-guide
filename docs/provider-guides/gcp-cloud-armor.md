# GCP Cloud Armor — Provider Reference

> Console click-paths, `gcloud` commands, and Terraform snippets for diagnosing and safely tuning Cloud Armor security policies. Pairs with the concept pages in [../concepts/](../concepts/).

---

## 1. The Symptom

User sees `403 Forbidden`. Response body resembles:

```
<!DOCTYPE html><html lang=en><meta charset=utf-8>
<title>Error 403 (Forbidden)!!1</title>
...
<p>Your client does not have permission to get URL <code>/path</code> from this server.
```

`Server: Google Frontend` header is the giveaway. Application backend (GKE pod, Cloud Run service, GCE MIG) shows **no log entry** for the request.

---

## 2. The Diagnosis

Cloud Armor sits **in front of** the HTTPS Load Balancer. Enforcement happens at Google's edge. A `DENY` outcome stops the request before it reaches your backend service — which is why your app logs are empty.

Three enforcement modes you will encounter:

| Mode                    | What it does                                                                        | Where it logs                           |
| ----------------------- | ----------------------------------------------------------------------------------- | --------------------------------------- |
| **Enforce**             | Action (`allow` / `deny(403)` / `deny(404)` / `deny(502)`) takes effect.            | `jsonPayload.enforcedSecurityPolicy`    |
| **Preview**             | Rule is evaluated; action is **not** applied; what _would_ have happened is logged. | `jsonPayload.previewedSecurityPolicy`   |
| **Adaptive Protection** | ML-based L7 DDoS detection; surfaces alerts, optionally auto-deploys rules.         | Cloud Logging + Security Command Center |

For false-positive triage you care almost exclusively about the first two.

---

## 3. The Log Evidence

### Baseline "show me everything Cloud Armor denied recently" query

```text
resource.type="http_load_balancer"
AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
```

### Scoped to a path and rule family

```text
resource.type="http_load_balancer"
AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
AND httpRequest.requestUrl=~"/login"
AND jsonPayload.enforcedSecurityPolicy.preconfiguredExprIds:"owasp-crs-v030301-id942100-sqli"
```

### Preview-mode hits (what _would_ be blocked if you flipped enforce)

```text
resource.type="http_load_balancer"
AND jsonPayload.previewedSecurityPolicy.outcome="DENY"
```

### Useful fields on a Cloud Armor log row

| Field                                                     | Meaning                                                                |
| --------------------------------------------------------- | ---------------------------------------------------------------------- |
| `jsonPayload.enforcedSecurityPolicy.name`                 | Which security policy denied the request.                              |
| `jsonPayload.enforcedSecurityPolicy.priority`             | Which rule (by priority) within the policy.                            |
| `jsonPayload.enforcedSecurityPolicy.outcome`              | `ACCEPT` / `DENY`.                                                     |
| `jsonPayload.enforcedSecurityPolicy.preconfiguredExprIds` | List of CRS rule IDs matched (e.g. `owasp-crs-v030301-id942100-sqli`). |
| `httpRequest.requestUrl`, `httpRequest.requestMethod`     | The request.                                                           |
| `httpRequest.remoteIp`, `httpRequest.userAgent`           | The client.                                                            |
| `jsonPayload.statusDetails`                               | E.g. `denied_by_security_policy`.                                      |

> Cloud Armor does **not** log request headers, cookies, or bodies. To prove which field tripped a rule, reproduce locally with `curl -v` and correlate by timestamp + remote IP + path.

### `gcloud` shortcuts

```bash
# List your security policies
gcloud compute security-policies list

# Describe a policy + its rules in priority order
gcloud compute security-policies describe app-armor-policy

# Tail Cloud Armor denies as JSON
gcloud logging read \
  'resource.type="http_load_balancer"
   AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"' \
  --limit 20 --format=json --freshness=10m
```

---

## 4. The Remediation Matrix

Cloud Armor preconfigured WAF rules (the OWASP CRS bundle) are tuned via **`evaluatePreconfiguredWaf()` opt-outs** and **`preconfigured_waf_config.exclusion`** blocks. Both can be scoped by path; the `exclusion` block can additionally narrow by field (cookie name, header name, query arg, POST arg).

> **Default rollout pattern:** create the rule with `preview = true`. Watch `previewedSecurityPolicy` log entries for 72h. If clean, set `preview = false`. Document in [../../EXCEPTIONS.md](../../EXCEPTIONS.md).

### A. Path-scoped opt-out (simplest)

Use when: a specific CRS rule produces FPs on one route and the exact offending field is hard to pin down.

**Console:**

1. **Network Security → Cloud Armor policies → `<your-policy>` → Add rule**.
2. **Mode:** Advanced mode (CEL).
3. **Match:** `request.path.matches('/login') && evaluatePreconfiguredWaf('sqli-v33-stable', {'opt_out_rule_ids': ['owasp-crs-v030301-id942100-sqli']})`
4. **Action:** Allow.
5. **Priority:** lower (higher precedence) than your global SQLi-deny rule.
6. **Preview:** ON. Save.

**Terraform:**

```hcl
rule {
  action   = "allow"
  priority = 900
  preview  = true

  match {
    expr {
      expression = <<-CEL
        request.path.matches('/login')
        && evaluatePreconfiguredWaf('sqli-v33-stable', {
          'opt_out_rule_ids': ['owasp-crs-v030301-id942100-sqli']
        })
      CEL
    }
  }

  description = "Opt out 942100 on /login. EXCEPTIONS.md row YYYY-MM-DD."
}
```

### B. Field-scoped exclusion (preferred when you know the offending field)

Use when: you know it is `request_cookies.SESSIONID` (or a specific header / query arg) and want to keep SQLi inspection on every _other_ field.

**Terraform:**

```hcl
rule {
  action   = "allow"
  priority = 910
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

  description = "Exclude SESSIONID cookie from 942100 on /login. EXCEPTIONS.md row YYYY-MM-DD."
}
```

Supported exclusion targets inside `preconfigured_waf_config.exclusion`:

| Block                                     | Targets                         |
| ----------------------------------------- | ------------------------------- |
| `request_header { operator, value }`      | Specific request header by name |
| `request_cookie { operator, value }`      | Specific cookie by name         |
| `request_query_param { operator, value }` | Specific query string parameter |
| `request_uri { operator, value }`         | Specific URI pattern            |

`operator` is one of `EQUALS`, `EQUALS_ANY`, `STARTS_WITH`, `ENDS_WITH`, `CONTAINS`.

### Promoting from preview to enforce

After 72h of clean preview logs (zero `previewedSecurityPolicy.outcome="DENY"` for the failing service that would have been _prevented_ by the exclusion):

**Console:** edit the rule → uncheck **Preview** → save.

**Terraform:** flip `preview = false`, `terraform apply`.

**`gcloud`:**

```bash
gcloud compute security-policies rules update 910 \
  --security-policy=app-armor-policy \
  --no-preview
```

---

## 5. Audit Trail

Every rule created in Steps A/B above gets a row in [../../EXCEPTIONS.md](../../EXCEPTIONS.md) the moment it lands in preview. The `description` field of the rule should reference the row ID / date so future maintainers can cross-reference without leaving the policy.

---

## Common pitfalls

- **CEL match cost.** Complex CEL expressions are evaluated per-request and have a non-trivial cost; the [Cloud Armor pricing & quotas docs](https://cloud.google.com/armor/quotas) cap rule expression size. Prefer the simpler `preconfigured_waf_config.exclusion` form over hand-rolled CEL when both are options.
- **Priority ordering.** Cloud Armor evaluates rules in **ascending priority**. Your exclusion rule MUST have a lower priority number than the rule that would otherwise deny — otherwise the deny wins first and never reaches the allow.
- **Two policies on one backend.** Cloud Armor attaches one policy per backend service. If a service has multiple URL maps (e.g. classic + global LB), each has its own backend service and may need the same exclusion applied twice.
- **Adaptive Protection auto-deploys.** Adaptive Protection can deploy rate-based deny rules **automatically** during a suspected attack. If your false positive coincides with an Adaptive Protection alert, check `jsonPayload.enforcedSecurityPolicy.name` — it will be a system-generated name. Tuning is separate from CRS exclusions; see the Adaptive Protection docs.
- **Preview hits without enforce hits during rollback.** If you remove an exclusion and immediately see `previewedSecurityPolicy.outcome="DENY"` again, the underlying false positive has not gone away — that is your signal to keep the exclusion (and bump the **Review by** date on the `EXCEPTIONS.md` row).

---

## See also

- [../triage/README.md](../triage/README.md)
- [../concepts/cookie-false-positives.md](../concepts/cookie-false-positives.md) — Rule `942100` deep dive.
- [aws-waf.md](aws-waf.md), [cloudflare-waf.md](cloudflare-waf.md) — sibling provider references.
- [../../EXCEPTIONS.md](../../EXCEPTIONS.md)
