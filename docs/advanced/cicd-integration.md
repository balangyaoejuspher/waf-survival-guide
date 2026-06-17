# CI/CD Infrastructure Integration â€” Managing WAF Tunings via GitOps

> **Scope of this file:** how to manage WAF policies â€” preconfigured rule exclusions, custom rules, IP sets, rate-limit configurations, anomaly-scoring thresholds â€” through GitOps pipelines using Terraform / CloudFormation / Pulumi / Wrangler, with mandatory CI checks (plan diffs, policy linting, audit-row enforcement, change-window guards), staged rollouts (preview â†’ enforce gates), drift detection, secret handling, and rollback procedures. Covers Google Cloud Armor, AWS WAF, and Cloudflare side by side.

---

## 1. The Symptom (operational pain this solves)

| Pain point | Reality without GitOps |
| --- | --- |
| Late-night console click to add an exclusion during an incident | No diff in version control; no audit row; no review |
| Two engineers add overlapping exclusions to the same rule on different days | Drift; conflicts; one silently undoes the other |
| Console-edited rules don't match what Terraform thinks the state is | `terraform plan` shows "12 resources to update" the next day |
| Exclusion was for a "temporary" partner; 18 months later it still exists | No automated expiry / review enforcement |
| Tuning lands in prod but staging never received it; future staging tests don't predict prod behavior | Environment drift |
| Rule order matters (priority), but two PRs that both add priority-100 rules collide silently | Merge wins, priority duplication, undefined evaluation order |
| Secrets (API keys for partner allow lists, signing secrets for custom rules) end up in code | Credential leak risk |

GitOps for WAF policy fixes all of these â€” at the cost of upfront tooling discipline.

---

## 2. The architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Git repo: waf-policy/                                      â”‚
â”‚   modules/                  Reusable per-provider modules  â”‚
â”‚   envs/                                                     â”‚
â”‚     prod/                   Per-environment instantiation  â”‚
â”‚     staging/                                                â”‚
â”‚     dev/                                                    â”‚
â”‚   ip-sets/                  IP lists pulled from vendors    â”‚
â”‚   policies/                  YAML or HCL policy definitions â”‚
â”‚   EXCEPTIONS.md             Audit ledger (this repo's root)â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
              â”‚
              â”‚ Pull request
              â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ CI pipeline (GitHub Actions / GitLab CI / similar)         â”‚
â”‚                                                             â”‚
â”‚  1. terraform fmt + validate                                â”‚
â”‚  2. tflint / cfn-lint / wrangler check                      â”‚
â”‚  3. Custom: lint rule priorities (no duplicates)            â”‚
â”‚  4. Custom: lint EXCEPTIONS.md (every new rule = new row)   â”‚
â”‚  5. Custom: lint description fields reference EXCEPTIONS rowâ”‚
â”‚  6. terraform plan (staging)                                â”‚
â”‚  7. Apply on merge to main (staging auto, prod gated)       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
              â”‚
              â”‚ Apply
              â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Cloud (GCP Cloud Armor / AWS WAF / Cloudflare)             â”‚
â”‚   Policy enforced; events flow to log destination          â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
              â”‚
              â”‚ Drift detection (nightly cron)
              â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Drift CI job: terraform plan -refresh-only                  â”‚
â”‚   Fails CI if console-edits introduced state drift         â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

---

## 3. Per-provider tooling

### 3.1 Google Cloud Armor â€” Terraform + `gcloud`

**Module layout:**

```
modules/cloud-armor-policy/
â”œâ”€â”€ main.tf              # google_compute_security_policy + rules
â”œâ”€â”€ variables.tf         # exclusions, rate limits, custom rules as inputs
â”œâ”€â”€ outputs.tf           # policy ID for attachment
â””â”€â”€ README.md            # contract: what inputs do
```

**Per-env instantiation:**

```hcl
# envs/prod/main.tf
module "app_armor" {
  source = "../../modules/cloud-armor-policy"

  policy_name = "app-armor-policy-prod"

  preconfigured_exclusions = [
    {
      path           = "/login"
      target_rule_set = "sqli-v33-stable"
      target_rule_ids = ["owasp-crs-v030301-id942100-sqli"]
      cookie_name    = "SESSIONID"
      preview        = false   # already promoted
      audit_row_date = "2026-06-17"
    },
    # ... more exclusions
  ]

  rate_limits = [
    {
      path           = "/api/v1/"
      rate           = 600
      interval       = 60
      enforce_on_key = "HTTP_HEADER"
      header_name    = "X-API-Key"
      preview        = false
    },
  ]

  ip_allow_sets = {
    "internal_probes" = ["10.0.0.0/8"]
    "partner_x"       = ["198.51.100.0/24"]
  }
}
```

**Apply gate:** `gcloud compute security-policies list` should match Terraform state. Drift job runs daily:

```bash
terraform plan -refresh-only -detailed-exitcode  # exit 2 if drift
```

### 3.2 AWS WAF â€” Terraform + `aws wafv2`

**Module layout:**

```
modules/waf-acl/
â”œâ”€â”€ main.tf              # aws_wafv2_web_acl + ip_sets + regex_pattern_sets
â”œâ”€â”€ variables.tf
â”œâ”€â”€ outputs.tf
â””â”€â”€ README.md
```

**Per-env:**

```hcl
# envs/prod/main.tf
module "api_acl" {
  source = "../../modules/waf-acl"

  acl_name = "api-acl-prod"
  scope    = "REGIONAL"

  managed_rule_groups = [
    {
      vendor = "AWS"
      name   = "AWSManagedRulesCommonRuleSet"
      overrides = [
        {
          rule_name           = "SQLi_COOKIE"
          action              = "count"
          scope_down_path     = "/login"
          audit_row_date      = "2026-06-17"
        },
      ]
    },
    {
      vendor = "AWS"
      name   = "AWSManagedRulesUnixRuleSet"
      overrides = [
        {
          rule_name           = "UNIXShellCommandsVariables_URIPATH"
          action              = "count"
          scope_down_path     = "/files/"
          audit_row_date      = "2026-06-17"
        },
      ]
    },
  ]

  custom_rules = [
    {
      name       = "allow-pre-approved-scanners"
      priority   = 1
      action     = "allow"
      ip_set     = "pre_approved_scanners"
      audit_row_date = "2026-06-17"
    },
  ]

  ip_sets = {
    pre_approved_scanners = ["198.51.100.0/29", "203.0.113.10/32"]
    partner_x_webhooks    = ["198.51.100.32/27"]
  }

  rate_based_rules = [
    {
      name        = "rate-api-v1"
      priority    = 50
      limit       = 3000  # per 5-min window
      key_type    = "CUSTOM_KEYS"
      keys        = ["ip", "header:x-api-key"]
      scope_down_path = "/api/v1/"
    },
  ]
}
```

### 3.3 Cloudflare â€” Terraform (preferred) or Wrangler

**Module layout:**

```
modules/cloudflare-zone-waf/
â”œâ”€â”€ main.tf                      # cloudflare_ruleset(s) per phase
â”œâ”€â”€ ip-lists.tf                  # cloudflare_list resources
â”œâ”€â”€ variables.tf
â”œâ”€â”€ outputs.tf
â””â”€â”€ README.md
```

**Per-env:**

```hcl
# envs/prod/main.tf
module "zone_waf" {
  source = "../../modules/cloudflare-zone-waf"

  zone_id = var.prod_zone_id

  managed_overrides = [
    {
      ruleset_id     = "efb7b8c949ac4650a09736fc376e9aee"  # OWASP CRS
      rule_id        = "<id-for-942100>"
      action         = "skip"
      expression     = "(starts_with(http.request.uri.path, \"/login\"))"
      audit_row_date = "2026-06-17"
    },
  ]

  custom_rules = [
    {
      name           = "skip-managed-for-partner-webhooks"
      phase          = "http_request_firewall_custom"
      action         = "skip"
      skip_phases    = ["http_request_firewall_managed", "http_ratelimit"]
      expression     = "(ip.src in $partner_x and starts_with(http.request.uri.path, \"/webhook/\"))"
      audit_row_date = "2026-06-17"
    },
  ]

  ip_lists = {
    partner_x = ["198.51.100.0/24"]
  }

  rate_limits = [
    {
      name                = "rate-api-v1-per-key"
      phase               = "http_ratelimit"
      action              = "block"
      characteristics     = ["ip.src", "http.request.headers[\"x-api-key\"]"]
      period              = 60
      requests_per_period = 600
      mitigation_timeout  = 60
      expression          = "(starts_with(http.request.uri.path, \"/api/v1/\"))"
    },
  ]
}
```

Wrangler is primarily for Workers. For Cloudflare WAF / Rate Limit / managed-rule config, prefer Terraform.

---

## 4. Mandatory CI checks

### 4.1 Rule-priority uniqueness

A custom linter that scans Terraform output:

```python
# .ci/lint-rule-priorities.py
import json, sys, subprocess

plan_json = subprocess.check_output(["terraform", "show", "-json", "tfplan"])
plan = json.loads(plan_json)

priorities = {}
for change in plan["resource_changes"]:
    res_type = change["type"]
    if res_type not in ("google_compute_security_policy_rule",
                        "aws_wafv2_web_acl_rule",
                        "cloudflare_ruleset"):
        continue
    addr = change["address"]
    after = change["change"].get("after") or {}
    pri = after.get("priority")
    if pri is None:
        continue
    if pri in priorities:
        print(f"DUPLICATE PRIORITY {pri}: {addr} and {priorities[pri]}", file=sys.stderr)
        sys.exit(1)
    priorities[pri] = addr

print("OK: no priority duplicates")
```

Fails CI before apply.

### 4.2 Audit-row enforcement

Every new rule MUST reference a row in `EXCEPTIONS.md`. A grep-based check:

```bash
#!/bin/bash
# .ci/lint-audit-rows.sh
set -e

# Extract description fields from terraform plan
new_descriptions=$(terraform show -json tfplan \
  | jq -r '.resource_changes[]
           | select(.change.actions[] | contains("create"))
           | .change.after.description // ""
           | select(. != "")')

# Each description should match "EXCEPTIONS.md row YYYY-MM-DD"
missing=()
while IFS= read -r desc; do
  if ! echo "$desc" | grep -qE 'EXCEPTIONS\.md row [0-9]{4}-[0-9]{2}-[0-9]{2}'; then
    missing+=("$desc")
  fi
done <<< "$new_descriptions"

if [ ${#missing[@]} -gt 0 ]; then
  echo "ERROR: the following new rules don't reference an EXCEPTIONS.md row:"
  printf '  - %s\n' "${missing[@]}"
  exit 1
fi

echo "OK: all new rules reference EXCEPTIONS.md"
```

### 4.3 Audit-row freshness

A cron CI job that fails if any row's `Review by` date has passed without being struck through:

```bash
#!/bin/bash
# .ci/audit-row-freshness.sh
set -e

today=$(date -u +%Y-%m-%d)
expired=$(awk -v today="$today" -F'|' '
  /^\|/ && !/striked/ {
    # 9th column is Review by (depending on table layout)
    review = $NF
    gsub(/[[:space:]]/, "", review)
    if (review ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/ && review < today) {
      print "EXPIRED: " $0
    }
  }
' EXCEPTIONS.md)

if [ -n "$expired" ]; then
  echo "$expired"
  echo "Run: review the rows above, either strike-through if removed, or bump Review by."
  exit 1
fi

echo "OK: no expired audit rows"
```

### 4.4 Change-window guard (deploy gate)

For production WAF changes outside business hours, gate the apply on a manual approver:

```yaml
# .github/workflows/apply-prod.yml
jobs:
  apply:
    runs-on: ubuntu-latest
    environment:
      name: production       # requires manual approval per repo settings
    steps:
      - uses: actions/checkout@v4
      - run: terraform init
      - run: terraform apply -auto-approve tfplan
```

Combined with a "no apply between 18:00 Friday and 09:00 Monday UTC unless emergency" calendar check.

### 4.5 Drift detection (nightly)

```yaml
# .github/workflows/drift.yml
on:
  schedule:
    - cron: '0 7 * * *'   # 07:00 UTC daily
jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: terraform init
      - run: |
          terraform plan -refresh-only -detailed-exitcode
          # exit 0 = no drift, 1 = error, 2 = drift detected
      - if: failure()
        run: gh issue create --title "WAF policy drift detected $(date -u +%F)" --body "$(terraform show tfplan)"
```

Drift = someone console-edited. Issue gets opened automatically; on-call reconciles.

---

## 5. Staged rollout: preview â†’ enforce

The standard pipeline:

| Step | What happens | Where |
| --- | --- | --- |
| 1. PR opened | Linters run, plan generated, audit row review starts | GitHub PR |
| 2. Merge to main | Apply to **dev** with `preview = true` | dev environment |
| 3. 7-day soak | Monitor preview hits in dev; tune contributors | Logs Explorer / CloudWatch / Security Events |
| 4. Promote to staging | PR flips `preview = true â†’ false` for that rule in staging; apply | staging environment |
| 5. 72-hour soak in staging | Monitor enforce mode behavior | Same dashboards as dev |
| 6. Promote to prod | PR flips `preview = true â†’ false` in prod; manual-approval gate | prod environment |
| 7. Update audit row | `Preview YYYY-MM-DD â†’ Enforce YYYY-MM-DD` updated in same PR | EXCEPTIONS.md |

Implement the staged-flag toggle in module inputs:

```hcl
variable "preview_per_env" {
  description = "Per-environment preview mode toggles for each exclusion"
  type        = map(bool)
  default = {
    dev     = true
    staging = false   # already promoted
    prod    = true    # still in soak
  }
}
```

This lets a single PR contain the policy change but applies preview/enforce per environment based on the per-env input.

---

## 6. Secret handling

WAF policies often reference partner API keys, signing keys, allow-listed JWT subjects. Never commit secrets:

| Provider | Secret store | Reference pattern |
| --- | --- | --- |
| **GCP** | Secret Manager | `data "google_secret_manager_secret_version" "key" { ... }` â†’ use the value in `request.headers['x-internal-api-key'] == data.google_secret_manager_secret_version.key.secret_data` |
| **AWS** | Secrets Manager / SSM Parameter Store | `data "aws_secretsmanager_secret_version" ...` |
| **Cloudflare** | No built-in secret store for rules; use **Workers Secrets** or a vault accessed at plan time | `data "vault_generic_secret" ...` |

For partner IP lists pulled from vendor APIs, fetch at plan time via a data source or sidecar script, never paste manually:

```hcl
data "http" "cloudflare_ips" {
  url = "https://www.cloudflare.com/ips-v4"
}

locals {
  cloudflare_cidrs = compact(split("\n", data.http.cloudflare_ips.response_body))
}

resource "aws_wafv2_ip_set" "cdn_passthrough" {
  name               = "cdn-passthrough"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = local.cloudflare_cidrs
}
```

---

## 7. Rollback procedure

**Always rollable:**

| Change | Rollback |
| --- | --- |
| Added an exclusion rule | Revert the PR; `terraform apply` removes the rule. |
| Bumped a threshold | Revert the PR. |
| Promoted preview â†’ enforce and saw immediate FP storm | Re-flip enforce â†’ preview via single PR + apply (typically < 5 minutes end-to-end). |
| Updated an IP set with new partner CIDRs that turned out to be hostile | Revert IP-set change. |

**Harder to rollback:**

| Change | Why | Mitigation |
| --- | --- | --- |
| Removed a managed rule group | Re-adding doesn't recover the request samples / metrics history from the deleted period. | Always `count`-override before removing; keep the group for at least 30 days in count mode. |
| Raised body inspection limit on AWS Web ACL | The inspection size change is associated with the ACL; downgrade is straightforward but in-flight cost during the change is locked-in. | Plan size changes during low-traffic windows. |
| Deleted an IP set referenced by other rules | Terraform deletion fails if referenced. | Always remove references first, then the set. |

For incidents, have an **emergency-bypass PR template**:

```markdown
## EMERGENCY: bypass WAF for {description}

- **Incident ID:** INC-2026-1234
- **What is broken:** {symptom}
- **Bypass scope:** {paths / IPs / methods}
- **Compensating control during bypass:** {app-layer check, monitoring}
- **Audit row:** added inline (no normal review window for emergency)
- **Cutover:** flip back within 24h or escalate

cc: @secops-lead @platform-lead
```

The PR uses preview = false directly (no soak), gated on an emergency-approver group.

---

## 8. Common pitfalls

- **Console edits during incidents.** They feel fast but break the GitOps state. Always make the change via PR â€” if the incident is critical, the emergency-bypass PR template above takes ~5 minutes; not slower than console + retroactive sync.
- **One Terraform state for all environments.** Disaster recipe. Per-env state files (or workspaces) keep blast radius contained.
- **Apply via long-lived admin credentials.** Use short-lived OIDC-federated tokens from CI (GitHub Actions OIDC â†’ GCP / AWS / Cloudflare). Service-account JSON keys checked into the repo or env-files are credential-leak vectors.
- **Skipping the audit-row check because "it's just a small change".** Small changes accumulate. Without the check, after 12 months you have a few hundred undocumented rules.
- **No drift detection.** Without it, console edits and Terraform diverge silently. Plan output starts showing "drift" results as a normal noisy state and the team learns to ignore them â€” defeating the GitOps premise.
- **IP-list refresh via manual paste.** Vendor IP lists change. Pull them from the vendor's API at plan time, or via a scheduled CI job that opens an auto-PR.
- **Same priority numbers across PRs.** Use a reserved-priority-band convention per change type (e.g. 1â€“99 emergency, 100â€“199 partner allows, 200â€“499 rate limits, 500â€“999 geoblocks, 1000â€“1999 managed-rule exclusions, etc.); document the reservation in the module README.
- **No replay-with-policy testing.** When you change a rule, replay a small set of representative legitimate AND attack requests through the new policy in preview. Many "looked right in plan" rules behave differently than expected on real traffic.
- **Forgetting that managed-rule-group versions update.** AWS / Cloudflare / GCP can update the underlying rule sets on their own cadence. Pin to specific versions where supported; subscribe to vendor change notifications for the rest.
- **Rate-limit costs.** Cloudflare Rate Limit rules are paid features; provisioning many "for safety" can produce a bill surprise. Audit rate-rule count per env and remove inactive ones.

---

## 9. Reference repo skeleton

A practical starting layout:

```
waf-policy/
â”œâ”€â”€ .github/workflows/
â”‚   â”œâ”€â”€ ci.yml                  # fmt + validate + lint + plan on PR
â”‚   â”œâ”€â”€ apply-dev.yml            # auto-apply on merge
â”‚   â”œâ”€â”€ apply-staging.yml        # apply on tag
â”‚   â”œâ”€â”€ apply-prod.yml           # apply on tag + manual approval
â”‚   â””â”€â”€ drift.yml                # nightly drift check
â”œâ”€â”€ .ci/
â”‚   â”œâ”€â”€ lint-rule-priorities.py
â”‚   â”œâ”€â”€ lint-audit-rows.sh
â”‚   â””â”€â”€ audit-row-freshness.sh
â”œâ”€â”€ modules/
â”‚   â”œâ”€â”€ cloud-armor-policy/
â”‚   â”œâ”€â”€ waf-acl/
â”‚   â””â”€â”€ cloudflare-zone-waf/
â”œâ”€â”€ envs/
â”‚   â”œâ”€â”€ dev/{main.tf, terraform.tfvars}
â”‚   â”œâ”€â”€ staging/{main.tf, terraform.tfvars}
â”‚   â””â”€â”€ prod/{main.tf, terraform.tfvars}
â”œâ”€â”€ ip-lists/
â”‚   â”œâ”€â”€ stripe.txt             # refreshed via cron PR
â”‚   â”œâ”€â”€ twilio.txt
â”‚   â””â”€â”€ cdn-passthrough.txt
â”œâ”€â”€ EXCEPTIONS.md               # audit ledger
â”œâ”€â”€ README.md                    # repo intro
â””â”€â”€ CODEOWNERS                   # require secops + platform on changes
```

`CODEOWNERS` example:

```
# Production WAF changes require both secops + platform approvers.
envs/prod/  @secops-lead @platform-lead
# Audit ledger changes require secops sign-off.
EXCEPTIONS.md  @secops-lead
# Module changes require platform.
modules/  @platform-lead
```

---

## See also

- [docs/concepts/rate-limiting.md](../concepts/rate-limiting.md), [docs/concepts/geoblocking-exceptions.md](../concepts/geoblocking-exceptions.md), [docs/concepts/payload-size.md](../concepts/payload-size.md) â€” concrete policies that GitOps manages.
- [docs/advanced/anomaly-scoring.md](anomaly-scoring.md), [docs/advanced/custom-expressions.md](custom-expressions.md) â€” rule-content patterns that flow through the same pipeline.
- All [docs/rules/*.md](../rules/) pages â€” each has Terraform snippets that drop directly into the per-env modules.
- [EXCEPTIONS.md](../../EXCEPTIONS.md) â€” the ledger that the audit-row linter enforces.

---

## References

### Terraform

- HashiCorp Terraform â€” [https://developer.hashicorp.com/terraform](https://developer.hashicorp.com/terraform).
- Google provider â€” [https://registry.terraform.io/providers/hashicorp/google/latest](https://registry.terraform.io/providers/hashicorp/google/latest).
- AWS provider â€” [https://registry.terraform.io/providers/hashicorp/aws/latest](https://registry.terraform.io/providers/hashicorp/aws/latest).
- Cloudflare provider â€” [https://registry.terraform.io/providers/cloudflare/cloudflare/latest](https://registry.terraform.io/providers/cloudflare/cloudflare/latest).
- `terraform plan -refresh-only` â€” [https://developer.hashicorp.com/terraform/cli/commands/plan#planning-modes](https://developer.hashicorp.com/terraform/cli/commands/plan#planning-modes).

### CI / OIDC federation

- GitHub Actions OIDC for cloud providers â€” [https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect).
- GCP Workload Identity Federation â€” [https://cloud.google.com/iam/docs/workload-identity-federation](https://cloud.google.com/iam/docs/workload-identity-federation).
- AWS IAM Identity Provider for GitHub Actions â€” [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html).
- Cloudflare API tokens (least-privilege for Terraform) â€” [https://developers.cloudflare.com/fundamentals/api/get-started/create-token/](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/).

### CloudFormation / Pulumi / Wrangler alternatives

- AWS CloudFormation for WAFv2 â€” [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html).
- Pulumi WAF examples â€” [https://www.pulumi.com/registry/](https://www.pulumi.com/registry/).
- Cloudflare Wrangler (Workers / Pages, limited WAF coverage) â€” [https://developers.cloudflare.com/workers/wrangler/](https://developers.cloudflare.com/workers/wrangler/).

### Policy as code adjacent

- OPA / Conftest for Terraform policy enforcement â€” [https://www.openpolicyagent.org/docs/latest/terraform/](https://www.openpolicyagent.org/docs/latest/terraform/).
- HashiCorp Sentinel â€” [https://developer.hashicorp.com/sentinel](https://developer.hashicorp.com/sentinel).
- tflint â€” [https://github.com/terraform-linters/tflint](https://github.com/terraform-linters/tflint).
- cfn-lint â€” [https://github.com/aws-cloudformation/cfn-lint](https://github.com/aws-cloudformation/cfn-lint).
