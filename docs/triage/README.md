# The 5-Minute Emergency Triage Flow

> Production is broken. Browser shows `403` / `404` / `429`. App logs are empty. Use this page before you wake anyone up.

The goal: in **5 minutes**, decide whether the cause is **(A) your application code** or **(B) the WAF blocking upstream of your app**. Each path has a very different fix.

---

## Step 0 — Capture one good reproduction (30 seconds)

Do this once. Every later step depends on it.

```bash
curl -v -X POST "https://app.example.com/login" \
  -H "Content-Type: application/json" \
  -H "Cookie: SESSIONID=<the-real-failing-cookie>" \
  --data '{"user":"alice"}' \
  -o /tmp/body.txt 2>&1 | tee /tmp/trace.txt
```

From `/tmp/trace.txt`, write down:

| Field | Where to find it |
| --- | --- |
| HTTP status | `< HTTP/2 403` |
| `X-Request-Id` / `X-Amzn-Trace-Id` / `cf-ray` | `< x-request-id: ...` |
| `server:` header | `< server: ...` (often reveals the WAF — `cloudflare`, `awselb/2.0`, `Google Frontend`) |
| Response body | `/tmp/body.txt` — WAFs frequently serve a branded HTML block page |

---

## Step 1 — Is the response shape "WAF-shaped"? (30 seconds)

| Signal | Verdict |
| --- | --- |
| Body is **HTML** (branded "Access denied", "Attention Required", "Error 1020") on a route that normally returns **JSON** | Almost certainly WAF |
| `Server: cloudflare` + `cf-ray` header + `403` | Cloudflare WAF / firewall rule |
| `Server: awselb/2.0` + tiny generic body + `403` | AWS WAF |
| Body says "Your client does not have permission..." / `Google Frontend` server | GCP Cloud Armor |
| `429` with `Retry-After` header but **no** request reached your app log | WAF rate-limit, not your app's rate limiter |
| Body matches your app's normal error envelope (e.g. your own JSON error schema) | Your app — go fix code |

If two or more rows above are true, treat it as a WAF block and continue.

---

## Step 2 — Pull the edge log (2 minutes)

The request never hit your container; **do not look at app logs**. Look at the edge.

### GCP Cloud Armor (Cloud Logging)

```text
resource.type="http_load_balancer"
AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
AND httpRequest.requestUrl=~"/login"
```

Optional time-narrowing: `timestamp >= "2026-06-17T10:00:00Z"`.

Look for: `jsonPayload.enforcedSecurityPolicy.name`, `jsonPayload.enforcedSecurityPolicy.preconfiguredExprIds` (rule IDs like `owasp-crs-v030301-id942100-sqli`).

### AWS WAF (CloudWatch Logs Insights)

```text
fields @timestamp, action, terminatingRuleId, httpRequest.uri, httpRequest.headers
| filter action = "BLOCK"
| filter httpRequest.uri like /\/login/
| sort @timestamp desc
| limit 50
```

Look for: `terminatingRuleId` (e.g. `AWS-AWSManagedRulesCommonRuleSet`), `terminatingRuleMatchDetails`.

### Cloudflare (Logpush / Firewall Events API)

Dashboard → **Security → Events** → filter by host + URI + timestamp.
Or via API:

```bash
curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/security/events?datetime_geq=2026-06-17T10:00:00Z&host=app.example.com" \
  -H "Authorization: Bearer $CF_TOKEN"
```

Look for: `rule_id`, `rule_message`, `action: block`, `ray_id` (matches your `cf-ray`).

---

## Step 3 — Map the rule ID to a concept page (1 minute)

| Rule family | Engine / behavior | Deep dive |
| --- | --- | --- |
| `942xxx` (e.g. `942100`, `942130`, `942260`) | SQL injection via `libinjection` — triggers on cookies / JWTs / base64 blobs | [../concepts/cookie-false-positives.md](../concepts/cookie-false-positives.md) |
| `941xxx` (e.g. `941100`, `941160`, `941310`) | XSS — triggers on HTML/JS in request bodies, common with WYSIWYG editors | [../concepts/xss-rich-text.md](../concepts/xss-rich-text.md) |
| `913xxx` | Scanner detection — uncommon false positive | provider page |
| Rate-limit rule (provider-specific ID) | Token bucket exhausted | [../concepts/rate-limiting.md](../concepts/rate-limiting.md) |
| Custom rule by your SecOps team | Org-specific deny list | provider page + ask SecOps |

---

## Step 4 — File the tuning request (1 minute)

Open a ticket / PR with these fields filled in. Anything less will bounce.

```markdown
**Service:** app.example.com
**Path / method:** POST /login
**WAF provider:** gcp-cloud-armor
**Rule ID:** 942100 (owasp-crs-v030301-id942100-sqli)
**Symptom:** HTTP 403 on every login since 2026-06-17 10:00 UTC
**Edge log evidence:** <link to log query result, redacted>
**Hypothesized target field:** request_cookies.SESSIONID (long signed cookie)
**Proposed exclusion scope:** exclude request_cookies.SESSIONID from rule 942100 on /login only
**Rollout:** preview mode for 72h, then enforce; review +180d
```

Send to the team that owns the WAF policy. Do **not** ask for "disable rule 942100" — that PR will be rejected.

---

## What "5 minutes" looks like in practice

```
0:00  Step 0 — reproduce with curl -v
0:30  Step 1 — is response body WAF-shaped?
1:00  Step 2 — open edge log console, paste query
3:00  Step 2 — find the log row, copy rule ID + cf-ray / request-id
4:00  Step 3 — open the concept page for that rule family
5:00  Step 4 — draft the tuning request from the template
```

If you are still in app logs at the 5-minute mark, you are looking in the wrong place.

---

## What NOT to do

- **Do not** retry-loop the request. Many WAFs have an escalating rate-limit on denied requests — you will lock yourself out and make the symptom look like a rate-limit problem.
- **Do not** ask for the rule group to be disabled. Always tune by **target exclusion** + **preview mode**. See the house rule in the root [README](../../README.md).
- **Do not** paste the raw failing cookie / JWT into a public ticket. Use the redaction checklist in `.github/CONTRIBUTING.md`.

---

## See also

- [identifying-blocks.md](identifying-blocks.md) — deeper "is it the app or the WAF?" decision tree.
- [../provider-guides/gcp-cloud-armor.md](../provider-guides/gcp-cloud-armor.md) — console click-paths + Terraform for exclusions.
- [../../EXCEPTIONS.md](../../EXCEPTIONS.md) — where the approved exclusion gets logged.
