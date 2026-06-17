# Anomaly Scoring Models â€” Tuning WAFs That Block on Cumulative Risk

> **Scope of this file:** advanced tuning of anomaly-scoring engines (OWASP CRS scoring on Cloud Armor and Cloudflare; AWS WAF's per-rule model as the contrasting case) â€” how scoring works under the hood, how to instrument scoring decisions for analysis, how to set and migrate thresholds without producing FP storms, how to combine anomaly scoring with bot scores / reputation scores, and how to operate scoring at scale across multiple environments.
>
> Pairs with [docs/rules/949110.md](../rules/949110.md) (the inbound-anomaly-score-exceeded blocker rule) and [docs/concepts/rate-limiting.md](../concepts/rate-limiting.md) (anomaly scoring frequently interacts with rate-limit decisions in unified policies).

---

## 1. The Symptom

| Cross-provider signature | Where you see it |
| --- | --- |
| `HTTP 403` denials clustered around a per-path "score threshold", with the terminating rule being the score-aggregator (e.g. `949110`) rather than any individual content rule | Edge log |
| After bumping CRS paranoia from PL1 â†’ PL2, the FP rate spikes overnight even though no individual rule was changed | Deploy timeline |
| Two endpoints with identical rules behave differently â€” one is fine, the other 403s â€” because the second endpoint's typical request hits more low-scoring matches by chance | Per-endpoint stats |
| Scoring policy works in staging but FPs in production because traffic mix differs (different UAs, longer cookies, more complex query strings) | Staging vs prod incident |
| Combined scoring + bot-management + rate-limit decisions are hard to debug because the final block reason aggregates multiple subsystems | Triage thread |

Distinguishing fingerprint: failures correlate with **request complexity** rather than presence of any single attack pattern, and the per-rule contribution is visible in the log.

---

## 2. The Diagnosis

### 2.1 The anomaly-scoring model in detail

Recap from [docs/rules/949110.md Â§2.1](../rules/949110.md#21-what-949110-does--the-anomaly-scoring-model): OWASP CRS in anomaly-scoring mode treats each match as a **score increment** rather than an immediate block. A separate "blocking evaluation" rule blocks at end-of-phase if the total score exceeds a threshold.

The full model has more levers than the basic description:

| Lever | Where it lives | Effect |
| --- | --- | --- |
| **Severity scores per rule** | Default `tx.critical_anomaly_score=5, error=4, warning=3, notice=2` | The score each matching rule adds. Adjustable in `crs-setup.conf`. |
| **Inbound threshold** | `tx.inbound_anomaly_score_threshold` (default `5`) | Aggregate score at which `949110` blocks. |
| **Outbound threshold** | `tx.outbound_anomaly_score_threshold` (default `4`) | Aggregate score at which `980130` blocks the response (sensitive data leak detection). |
| **Paranoia level** | `tx.paranoia_level` (1â€“4, default `1`) | Which tranches of rules are enabled. Higher levels add more aggressive heuristics â€” more matches, more contributing scores. |
| **Detection paranoia level** | `tx.detection_paranoia_level` | Rules above this level *log* (contribute to score) but only above `paranoia_level` actually count toward blocking. Useful for soft-rolling new paranoia levels. |
| **Per-rule severity overrides** | `SecAction` rules that bump or lower specific rule severities | Surgical adjustment without touching the rule itself. |

### 2.2 Paranoia-level migration math

The dominant operational risk in anomaly scoring is **paranoia-level bumps without corresponding threshold bumps**. Worked example:

- Current: PL1, threshold 5. Average legit request hits 0â€“2 low-severity matches. ~0.1% FP rate.
- Bump to PL2 without changing threshold: ~20â€“40 more rules enabled, average legit request now hits 1â€“4 matches. Many push past threshold 5. FP rate rises to ~3â€“5%.
- Bump threshold to 7 along with PL2 bump: aggregate FP rate stays near baseline; new attack coverage is gained.

The pattern: **whenever you raise PL, simultaneously raise threshold by ~2â€“3 (more for higher PL bumps)**. Calibrate by running PL2 detection-only for a week, tallying the per-request score distribution, and choosing a threshold at the ~99.5 percentile of legitimate traffic scores.

### 2.3 Per-environment threshold strategy

| Environment | Suggested setting | Rationale |
| --- | --- | --- |
| **Production** | PL1 / threshold 5 (default), tune up cautiously | Highest stakes; FPs cost real revenue/trust. |
| **Staging / pre-prod** | Same as prod, plus PL2 in detection-only | Mirrors prod block behavior; logs PL2 contributors for tuning. |
| **Dev** | PL2 / threshold 7 enforcing | Catches issues earlier; devs are tolerant of FPs in dev. |
| **CI / security testing** | PL4 / threshold 3 detection-only | Maximum coverage to drive scanner findings; not blocking real users. |

### 2.4 Combining anomaly scoring with bot scores / reputation

Modern WAFs combine multiple scoring subsystems. Each provider exposes them differently:

| Subsystem | GCP | AWS | Cloudflare |
| --- | --- | --- | --- |
| **OWASP CRS anomaly score** | `inbound-anomaly-stable` ruleset, total in `tx.inbound_anomaly_score` (not directly exposed in logs) | N/A (per-rule blocking only) | Score visible per event in Security Events when payload logging enabled |
| **Bot score** | Bot Management product (separate); `bot.score` in CEL | AWS WAF Bot Control rules contribute their own scores | `cf.bot_management.score` (1â€“99); separate from WAF anomaly score |
| **Reputation / IP-based** | Cloud Armor reputation lists | `AWSManagedRulesAmazonIpReputationList` (deny/count by reputation) | `cf.threat_score` (0â€“100) and `ip.src in $cf.tag.bad_reputation` |
| **Adaptive Protection / ML** | GCP Adaptive Protection auto-creates rules during attacks | AWS Shield Advanced + Bot Control | Cloudflare Bot Management ML signals |

Combining them in a rule is what produces "good but precise" policies. Example: deny only if **CRS anomaly score â‰¥ 5** AND **bot score < 30** AND **path is `/login`** â€” the intersection is narrow enough that FPs collapse.

### 2.5 Provider mapping recap (advanced)

| Provider | Anomaly engine | Exposes per-rule scores in logs? | Tunable threshold | Paranoia levels exposed? |
| --- | --- | --- | --- | --- |
| **GCP Cloud Armor** | CRS via `inbound-anomaly-stable` | No (only matching rule IDs) | Via `sensitivity` 1â€“4 on `evaluatePreconfiguredWaf()` (maps to thresholds 5/7/10/15 roughly) | Implicit â€” `sensitivity` controls which rule tranches contribute |
| **AWS WAF** | Per-rule blocking; no aggregate score | N/A | N/A | N/A |
| **Cloudflare** | CRS via OWASP Core Ruleset + Cloudflare Managed Ruleset | Yes (in Security Events with payload logging) | Per ruleset under WAF managed rules config | Yes (PL1â€“PL4 selector in dashboard / Terraform) |

---

## 3. The Log Evidence

### 3.1 GCP Cloud Armor â€” per-rule contribution profiling

Cloud Armor does not expose the running score, but the **list of matched rules** in `enforcedSecurityPolicy.preconfiguredExprIds` lets you reconstruct it offline:

```text
resource.type="http_load_balancer"
AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
AND jsonPayload.enforcedSecurityPolicy.preconfiguredExprIds:"owasp-crs-v030301-id949110-inbound-anomaly"
| stats count() by jsonPayload.enforcedSecurityPolicy.preconfiguredExprIds
```

For each unique combination, calculate the cumulative score using the default severity map (critical=5, error=4, warning=3, notice=2). The top 5 combinations + their scores tell you exactly which contributing rules to consider tuning.

### 3.2 AWS WAF â€” surrogate-score by frequency

AWS doesn't have aggregate scoring, but you can build a similar view:

```text
fields @timestamp, action, terminatingRuleId, nonTerminatingMatchingRules.0.ruleId, nonTerminatingMatchingRules.1.ruleId
| filter action = "BLOCK"
| stats count() by terminatingRuleId, nonTerminatingMatchingRules.0.ruleId
| sort count desc
| limit 30
```

This identifies "groups of rules that frequently match together" â€” the AWS equivalent of "contributing rules to an aggregate".

### 3.3 Cloudflare â€” explicit score in events

```bash
curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/security/events?datetime_geq=2026-06-17T10:00:00Z" \
  -H "Authorization: Bearer $CF_TOKEN" \
  | jq '.result[] | select(.rule_id == "<owasp-crs-blocker-id>") |
        {ray_id, score: .matched_data.score, contributing: .matched_data.matching_rules, action, occurred_at}'
```

For per-path score distribution:

```bash
curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/security/events?datetime_geq=2026-06-17T00:00:00Z" \
  -H "Authorization: Bearer $CF_TOKEN" \
  | jq -r '.result[] | select(.matched_data.score != null) |
           [.uri, .matched_data.score] | @tsv' \
  | awk -F'\t' '{ paths[$1]+=1; scores[$1]+=$2 } END { for (p in paths) printf "%s\t%d hits\tavg score %.2f\n", p, paths[p], scores[p]/paths[p] }' \
  | sort -k4 -rn | head -20
```

### 3.4 Detection-only paranoia bump

To safely measure FP impact of a paranoia bump before enforcing:

**Cloud Armor:** add a new rule with the higher-sensitivity preconfigured expression in **preview mode** at a higher priority than the current rule. Both run; only the lower priority enforces. Track `previewedSecurityPolicy` rows for what *would* be blocked.

**Cloudflare:** clone the OWASP CRS managed ruleset config, set the new paranoia level, leave the action as `log` on all newly-enabled rules. Soak for 7 days. Promote to `block` once score distribution is acceptable.

**AWS:** create the new managed rule groups in a second Web ACL attached to a CloudWatch-only listener, send 1% of traffic there via a routing rule. Compare metrics.

### 3.5 Offline score reconstruction tool

```python
# score_reconstruct.py â€” feed it Cloud Armor log JSON, get cumulative scores.
import json, sys

SEVERITY = {  # CRS default severities
    "warning": 3,
    "notice":  2,
    "error":   4,
    "critical": 5,
}

RULE_SEVERITY = {  # map known rule IDs to severity tags from CRS source
    "owasp-crs-v030301-id942100-sqli": "critical",
    "owasp-crs-v030301-id942130-sqli": "critical",
    "owasp-crs-v030301-id941100-xss": "critical",
    "owasp-crs-v030301-id932100-rce": "critical",
    "owasp-crs-v030301-id913120-scannerdetection": "notice",
    "owasp-crs-v030301-id920170-protocolattack": "warning",
    # ... extend as needed
}

for line in sys.stdin:
    row = json.loads(line)
    ids = row.get("jsonPayload", {}).get("enforcedSecurityPolicy", {}).get("preconfiguredExprIds", [])
    score = sum(SEVERITY[RULE_SEVERITY.get(rid, "warning")] for rid in ids if rid != "owasp-crs-v030301-id949110-inbound-anomaly")
    print(f"score={score:>3}  rules={ids}")
```

Run it against an exported `gcloud logging read --format=json` dump to build a histogram of legitimate-traffic scores; the 99.5 percentile is a defensible new threshold.

---

## 4. The Remediation Matrix

> **Operating principle:** anomaly scoring is a **two-axis problem** â€” threshold setting and per-rule severity. Tune one axis at a time, measure for 7 days, then tune the other. Never bump paranoia + threshold simultaneously in production; the two changes interact in ways the FP rate won't show until 2â€“3 days later.

### 4.1 Threshold migration playbook

1. **Baseline (week 1).** Run a per-path score-distribution analysis (Â§3.1â€“3.3). Record the p50, p95, p99, p99.5, p99.9 scores.
2. **Target threshold (week 2).** Choose a threshold ~1 unit higher than the p99.5. This blocks the worst 0.5% of legitimate traffic â€” they will need exception scoping â€” and 100% of anything past it.
3. **Soak in preview (week 3).** Apply the new threshold in preview / log / count mode. Confirm that real attack patterns still hit the new threshold (test with sample SQLi / XSS payloads from your security team).
4. **Cutover (week 4).** Promote to enforce. Continue monitoring per-path score distribution.
5. **Audit row.** Record the before/after thresholds + the score distribution snapshot at cutover.

### 4.2 Per-rule severity adjustment

Lower the severity of a contributing rule on a specific path when the rule is "correctly identifying weird shape, but the shape is legitimate for this path":

**Cloud Armor:** wrap the rule's evaluation in a path-scoped allow that uses `opt_out_rule_ids` (effectively zero severity on that path).

```hcl
rule {
  action   = "allow"
  priority = 920
  preview  = true
  match {
    expr {
      expression = <<-CEL
        request.path.startsWith('/api/v1/notes')
        && evaluatePreconfiguredWaf('rce-stable', {
          'opt_out_rule_ids': ['owasp-crs-v030301-id932130-rce']
        })
      CEL
    }
  }
  description = "Effectively zero out 932130 contribution on /api/v1/notes (legitimate backticks in code snippets). Reduces anomaly score by 5 per matching request; brings sustained 949110 FPs to zero per Â§3.1 analysis. EXCEPTIONS.md row YYYY-MM-DD."
}
```

**Cloudflare:** managed-ruleset override sets the contributing rule's action to `log` on the scoped expression â€” score contribution stops on that path.

### 4.3 Combining anomaly + bot + reputation in one decision

Compose multiple subsystems into a single block decision for narrower precision:

**Cloud Armor:**

```hcl
rule {
  action   = "deny(403)"
  priority = 200
  match {
    expr {
      expression = <<-CEL
        request.path == '/login'
        && evaluatePreconfiguredWaf('sqli-stable', { 'sensitivity': 2 })
        && origin.bot.score < 30                                 // Bot Management
        && !inIpRange(origin.ip, '198.51.100.0/24')             // trusted partner allow
      CEL
    }
  }
  description = "Compound block on /login: anomaly + low bot score + not-trusted-IP. False-positives only when all three align; tightens precision over single-axis denies. EXCEPTIONS.md row YYYY-MM-DD."
}
```

**Cloudflare:**

```hcl
rules {
  action     = "block"
  expression = "(http.request.uri.path eq \"/login\" and cf.threat_score gt 30 and cf.bot_management.score lt 30 and not ip.src in {198.51.100.0/24})"
  description = "Login compound: threat score AND bot score AND not-trusted-IP. EXCEPTIONS.md row YYYY-MM-DD."
}
```

This pattern (multi-axis composition) is what separates "default WAF on" deployments from carefully-tuned production policies.

### 4.4 Verification

- Run a baseline + post-change score distribution diff (Â§3.1â€“3.3). Per-path p99 score should drop or stay flat; threshold breach rate should drop.
- Replay a small set of known-good production requests; none should newly hit the threshold.
- Replay a small set of canned attack payloads (security-team-provided); all should still block.

---

## 5. Audit Trail

```
| 2026-06-17 | api.example.com | gcp-cloud-armor | anomaly threshold raised from sensitivity 1 â†’ 2 on /api/v1/notes | path-scoped via evaluatePreconfiguredWaf('inbound-anomaly-stable', {sensitivity: 2}) | Score distribution: pre p99.5 = 5, post p99.5 = 7. Per Â§3.1 analysis, 932130 contributed +5 on legitimate code-snippet content. Compensating: app-layer validation in note handler (commit a1b2c3d) rejects exec/eval as content. | <link to before/after score histograms> | preview 2026-06-17 â†’ enforce 2026-06-24 | @platform-lead + @secops-lead | 2026-12-14 |
```

Two approvers (platform + secops); long review (180d) because this is a wide envelope change.

---

## 6. Common pitfalls

- **Bumping paranoia without bumping threshold.** Adds rule contributions without adding scoring headroom. Always pair the changes.
- **Per-environment threshold drift.** Staging and production having different thresholds means staging tests don't predict prod behavior. Keep them synchronized except for explicit detection-only paranoia experiments.
- **Treating a single FP as a threshold problem.** A single FP often is a per-rule problem (one contributing rule fires too easily). Threshold bumps widen the envelope unnecessarily. Tune contributing rules first; threshold last.
- **Ignoring outbound anomaly score (`980130`).** Outbound rules detect sensitive-data leaks in responses (DB error strings, stack traces, SSNs). Tuning inbound without thinking about outbound is half a model.
- **Bot score interactions.** Bot Management scores have their own dynamics; combining them naively can produce "perfect storm" blocks during normal Googlebot indexing. Test composed rules against known good crawler IPs.
- **AWS doesn't have this complexity, then customers try to simulate it.** Some teams build custom Lambda@Edge or CloudFront Functions to compose scores out of multiple AWS rule signals. This is technically possible but operationally expensive â€” consider whether you really need the model, or whether per-rule tuning is sufficient on AWS.
- **Adaptive Protection / ML-deployed rules interact with scoring.** GCP Adaptive Protection can auto-deploy rate-based rules during attacks. If your FP coincides with an Adaptive Protection event, the score isn't the culprit â€” disable the auto-deployed rule and re-evaluate.
- **Reproducibility across CRS package versions.** A CRS upstream version bump can rebalance severities (warning â†” error) on existing rules. Score distributions shift overnight. Always run a re-baseline after CRS updates.

---

## See also

- [docs/rules/949110.md](../rules/949110.md) â€” the score-aggregator blocker rule itself; this page is the operating manual.
- [docs/rules/941100.md](../rules/941100.md), [docs/rules/942100.md](../rules/942100.md), [docs/rules/932100.md](../rules/932100.md) â€” common contributing rules.
- [docs/concepts/rate-limiting.md](../concepts/rate-limiting.md), [docs/concepts/geoblocking-exceptions.md](../concepts/geoblocking-exceptions.md) â€” neighboring decision systems frequently composed with anomaly scoring.
- [docs/provider-guides/gcp-cloud-armor.md](../provider-guides/gcp-cloud-armor.md), [docs/provider-guides/aws-waf.md](../provider-guides/aws-waf.md), [docs/provider-guides/cloudflare-waf.md](../provider-guides/cloudflare-waf.md)
- [EXCEPTIONS.md](../../EXCEPTIONS.md)

---

## References

### OWASP Core Rule Set

- Anomaly scoring concepts â€” [https://coreruleset.org/docs/concepts/anomaly_scoring/](https://coreruleset.org/docs/concepts/anomaly_scoring/).
- Paranoia levels â€” [https://coreruleset.org/docs/concepts/paranoia_levels/](https://coreruleset.org/docs/concepts/paranoia_levels/).
- `crs-setup.conf.example` (severity-score mapping) â€” [https://github.com/coreruleset/coreruleset/blob/main/crs-setup.conf.example](https://github.com/coreruleset/coreruleset/blob/main/crs-setup.conf.example).
- Rule `949110` (inbound blocker) and `980130` (outbound blocker) â€” [https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-949-BLOCKING-EVALUATION.conf](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-949-BLOCKING-EVALUATION.conf), [https://github.com/coreruleset/coreruleset/blob/main/rules/RESPONSE-980-CORRELATION.conf](https://github.com/coreruleset/coreruleset/blob/main/rules/RESPONSE-980-CORRELATION.conf).

### Google Cloud Armor

- `evaluatePreconfiguredWaf` sensitivity tuning â€” [https://cloud.google.com/armor/docs/rule-tuning#tuning-by-sensitivity-level](https://cloud.google.com/armor/docs/rule-tuning#tuning-by-sensitivity-level).
- Bot Management (`bot.score`) â€” [https://cloud.google.com/armor/docs/bot-management](https://cloud.google.com/armor/docs/bot-management).
- Adaptive Protection â€” [https://cloud.google.com/armor/docs/adaptive-protection-overview](https://cloud.google.com/armor/docs/adaptive-protection-overview).

### AWS WAF

- WAF rule processing model â€” [https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works.html](https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works.html).
- `AWSManagedRulesAmazonIpReputationList` â€” [https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html#aws-managed-rule-groups-list-ipreputation](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html#aws-managed-rule-groups-list-ipreputation).
- AWS WAF Bot Control â€” [https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html](https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html).

### Cloudflare

- OWASP Core Ruleset paranoia + threshold config â€” [https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/](https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/).
- Bot Management score (`cf.bot_management.score`) â€” [https://developers.cloudflare.com/bots/concepts/bot-score/](https://developers.cloudflare.com/bots/concepts/bot-score/).
- Threat score (`cf.threat_score`) â€” [https://developers.cloudflare.com/ruleset-engine/rules-language/fields/#field-cf-threat_score](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/#field-cf-threat_score).
