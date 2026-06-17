# Identifying Blocks: App Error vs WAF Block

> A longer-form decision tree for when [the 5-minute flow](README.md) was inconclusive â€” usually because the symptom is `404` or `5xx` and the response body looks plausibly like your app.

---

## The Symptom

You are seeing one of:

- `403 Forbidden` but your app **does** have `/that-path` and the user **is** authenticated.
- `404 Not Found` on a route that definitely exists and works in staging.
- `5xx` with no corresponding stack trace in your application logs.
- `429 Too Many Requests` but your app-level rate limiter shows the client is well under quota.
- Intermittent failures correlated with payload **size** (works for small inputs, fails for large ones).

All five have a non-trivial chance of being a WAF, not your code.

---

## The Diagnosis: where the request actually died

A request to a typical production app crosses **at least four** enforcement points. Knowing which one denied you is the whole game.

```
Client â”€â”€â–º CDN/Edge â”€â”€â–º WAF â”€â”€â–º Load Balancer â”€â”€â–º Reverse proxy â”€â”€â–º Your app
                       (1)         (2)              (3)              (4)
```

| If it died at                    | You'll see in the app log                                  | Edge log shows            |
| -------------------------------- | ---------------------------------------------------------- | ------------------------- |
| (1) WAF                          | **nothing**                                                | `action=BLOCK` + rule ID  |
| (2) Load Balancer                | nothing (e.g. SSL handshake fail, backend timeout from LB) | `5xx` from LB, no `BLOCK` |
| (3) Reverse proxy (nginx, Envoy) | maybe an access-log line, no app handler entry             | request reached LB        |
| (4) Your app                     | full stack trace / handler log                             | request reached LB        |

**Rule of thumb:** if your app log has **no entry at all** for the failing request ID, the request never reached your app â€” and the WAF is the most likely suspect.

---

## The Log Evidence: a 3-query proof

Run these three queries with the **same time window and same request identifier** (`X-Request-Id`, `cf-ray`, `X-Amzn-Trace-Id`, or just a 1-minute window if no ID is propagated).

### Query A â€” Did the WAF block it?

GCP Cloud Armor:

```text
resource.type="http_load_balancer"
AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
AND httpRequest.requestUrl=~"/your-path"
```

AWS WAF:

```text
fields @timestamp, action, terminatingRuleId, httpRequest.uri
| filter action = "BLOCK" and httpRequest.uri like /\/your-path/
| sort @timestamp desc
```

Cloudflare (Security Events):

```
Action: Block
Host: app.example.com
Path: /your-path
```

If **any** row matches â†’ it's a WAF block. Stop here and go to the matching concept page.

### Query B â€” Did the load balancer ever see the request as `2xx`?

GCP:

```text
resource.type="http_load_balancer"
AND httpRequest.requestUrl=~"/your-path"
AND httpRequest.status>=200 AND httpRequest.status<300
```

AWS (ALB access logs in Athena):

```sql
SELECT request_url, elb_status_code, target_status_code
FROM alb_access_logs
WHERE request_url LIKE '%/your-path%'
  AND from_iso8601_timestamp(time) > now() - interval '15' minute
ORDER BY time DESC;
```

If `elb_status_code = 200` but `target_status_code != 200` â†’ app-side error.
If `elb_status_code = 403/404` with **no** matching WAF block in Query A â†’ likely a load-balancer ACL or routing issue, not the WAF.

### Query C â€” Did your app handler run?

Your app log, narrowed to the request ID or the same minute. If empty: request did not reach the app.

### Verdict table

| Query A (WAF)   | Query B (LB)                       | Query C (app)             | Verdict                                                                                                                                      |
| --------------- | ---------------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| BLOCK row found | â€”                                  | empty                     | **WAF block.** Go to [../concepts/](../concepts/) and pick the rule family.                                                                  |
| no rows         | `2xx` to client                    | empty                     | LB / routing problem, not WAF, not app. Page the network team.                                                                               |
| no rows         | `5xx` to client, `2xx` to target   | handler ran, error logged | **Your app.** Debug the stack trace.                                                                                                         |
| no rows         | `5xx` to client, target also `5xx` | empty                     | Origin / health-check / backend down. Not WAF.                                                                                               |
| no rows         | `429` to client                    | empty                     | LB-level throttling or upstream rate-limit, not WAF rule. Check [../concepts/rate-limiting.md](../concepts/rate-limiting.md).                |
| BLOCK row found | â€”                                  | handler also ran          | Rare. Means a _previous_ request was blocked; you correlated the wrong row. Re-run with a tighter time filter and exact `cf-ray`/request id. |

---

## The Remediation Matrix

Remediation depends on the verdict, not on the symptom.

| Verdict      | Owner                                        | Action                                                                                                                                                             |
| ------------ | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| WAF block    | SecOps / platform team owning the WAF policy | Open a tuning request using the template in [README â€” Step 4](README.md#step-4--file-the-tuning-request-1-minute). Reference the concept page for the rule family. |
| LB / routing | Network / platform team                      | File a routing ticket with the LB access-log rows.                                                                                                                 |
| App          | You                                          | Normal debugging â€” the request reached the app, the log is yours.                                                                                                  |
| Origin down  | SRE / on-call                                | Page on-call; this is a health issue, not a coding issue.                                                                                                          |

---

## Audit trail

If the verdict is **WAF block** and a tuning request is approved and applied, the exception MUST be recorded in [../../EXCEPTIONS.md](../../EXCEPTIONS.md) with all required fields. No exception lands without a ledger entry.

---

## Common gotchas

- **Preview-mode rules don't `BLOCK`** â€” they only log `ALLOW` with a `previewedAction=DENY` (GCP) or `Count` (AWS). If your edge log shows a _preview_ hit, the WAF is **not** the cause of the failing response â€” but it's telling you what would block once promoted to enforce.
- **Two WAFs in series** (e.g. Cloudflare in front of AWS WAF). Check **both** edge logs; the outer one will block first and the inner one will see nothing.
- **Cached error responses.** A CDN can cache a `403` from a brief misconfiguration and keep serving it after the WAF is fixed. Purge the cached path before declaring the fix verified.
- **HEAD vs GET vs OPTIONS.** Preflight `OPTIONS` failures often have a different rule path than the `POST` they precede. Reproduce with the exact method.
