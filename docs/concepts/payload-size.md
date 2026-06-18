# Payload & Body Size Violations — Heavy Multi-Part Uploads

> **Scope of this file:** how to safely raise payload and body-size inspection limits for endpoints that legitimately accept large multi-part uploads (file uploads, video / image ingest, bulk-import CSVs, EDI / HL7 / FHIR healthcare payloads, log-ingest bulk endpoints, scientific data uploads) — and what additional defenses must compensate for the wider exposure. Covers Google Cloud Armor, AWS WAF, and Cloudflare side by side.

---

## 1. The Symptom

| Cross-provider signature                                                                                                                                    | Where you see it                                   |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `HTTP 413 Payload Too Large` or `HTTP 403` returned at the edge for uploads above a threshold (commonly 1, 8, or 32 MB)                                     | Browser dev tools / upload UI                      |
| Upload UI shows "Uploading… 99%" then fails; no entry in the backend application log                                                                        | App access log                                     |
| The same upload **smaller than the threshold** succeeds and produces a normal handler-entry log line                                                        | Manual repro by shrinking the file                 |
| Multi-part forms with many fields (each individually small, but aggregate > limit) fail                                                                     | Bulk-form endpoint                                 |
| WAF managed-rule **does not detect** an attack pattern in a large body that exceeds the inspection limit (the body is silently un-inspected past the limit) | Sec-team alert that the WAF "didn't see" something |
| Bulk CSV imports fail at row 50,000 with a generic edge error                                                                                               | Bulk-import job                                    |
| Log-ingest webhook from a high-volume customer drops random batches                                                                                         | Log-ingest pipeline                                |

Distinguishing fingerprint: failure correlates with **payload size**, not content. A 1 KB JSON request with a hostile payload still triggers the appropriate WAF rule; a 100 MB upload may fail before WAF rules run, or may pass with un-inspected bytes past the limit.

---

## 2. The Diagnosis

### 2.1 Two distinct concepts often conflated

1. **Maximum body size accepted by the edge.** If the request body exceeds this, the edge rejects with `413` (or `403` framed as protocol violation). Examples: GCP HTTPS LB default `32 MB`; AWS API Gateway default `10 MB`; Cloudflare default `100 MB` (paid plan dependent); nginx `client_max_body_size 1m`.
2. **Maximum body size inspected by the WAF.** Even when the edge accepts the body, WAF rules may only inspect the first N bytes. Beyond N, the body is **not** inspected — meaning attack patterns past the cutoff slip through silently. Examples: AWS WAF default 8 KB (regional ACL) / 16 KB (CloudFront-scoped), raisable to 16/32/64 KB at cost; Cloud Armor inspects body for preconfigured WAF rules according to the policy's `body_inspection_size` setting; Cloudflare body inspection depends on rule type and plan.

The first is a hard limit (rejects the request). The second is a silent partial-inspection limit (the request goes through but is partially un-checked).

### 2.2 The legitimate large-payload cases

| Workload                                                                   | Typical size            | Why it must be allowed       |
| -------------------------------------------------------------------------- | ----------------------- | ---------------------------- |
| Video / image uploads (CMS, ad-network creative uploads)                   | 10 MB – 500 MB          | Core product functionality.  |
| Bulk CSV imports (customer onboarding, data migration)                     | 1 MB – 1 GB             | One-off but high-impact.     |
| Multi-part HL7 / FHIR healthcare payloads (with attachments, scanned PDFs) | 5 MB – 50 MB            | Compliance-driven workflows. |
| EDI X12 / EDIFACT batches                                                  | 1 MB – 100 MB           | B2B integrations.            |
| Log-ingest webhooks (Datadog, Splunk forwarders)                           | 1 MB – 100 MB per batch | High-volume telemetry.       |
| Scientific data (genomic sequences, sensor readings)                       | 100 MB – multiple GB    | Domain-specific.             |
| Backup uploads / archive submissions                                       | 1 GB+                   | Infrastructure workflows.    |

### 2.3 The two compensating-control patterns

When you raise the body-size limit, you widen the exposure surface. Two patterns make this safe:

1. **Pre-signed-URL pattern (preferred).** Issue a short-lived pre-signed URL (S3 / GCS / Azure Blob) from your application. The client uploads **directly to object storage**, bypassing your WAF entirely. Your application receives an upload-complete event (via S3 events / GCS Pub/Sub) and processes the file from storage. The WAF only sees the small "request a presigned URL" call, which has a tiny body.
2. **Streaming / chunked upload with per-chunk inspection.** The client uploads in chunks (each small enough for full WAF inspection); the application reassembles. Common for resumable uploads (tus protocol, Google's resumable upload protocol).

If neither pattern is feasible, raise the limits and document the **compensating controls at the app layer** (MIME-sniff the actual file content, scan with AV — ClamAV / Defender — before persisting, enforce per-customer size quotas at the app, monitor for upload-size anomalies).

### 2.4 Provider mapping

| Provider                             | Edge body limit                                                                    | WAF inspection limit                                                                                                                                             | Notes                                                      |
| ------------------------------------ | ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| **GCP Cloud Armor**                  | HTTPS LB max 32 MB by default; can be increased via backend service configuration. | `body_inspection_size` on the security policy; default 8 KB; raisable; affects all preconfigured WAF rules.                                                      | Larger inspection = higher policy cost / latency.          |
| **AWS WAF (Regional, ALB-attached)** | ALB max 1 MB → 10 MB depending on target type; API Gateway max 10 MB.              | Default 8 KB; raisable via `AssociationConfig.RequestBody` settings to 16 / 32 / 64 KB per resource type. Beyond `RequestBody` limit, body is **not** inspected. | WCU costs increase with inspection size.                   |
| **AWS WAF (CloudFront-attached)**    | CloudFront max 32 MB upload by default (HTTP body), higher for chunked.            | Default 16 KB on CloudFront-scoped ACLs; raisable to 32/64 KB via `AssociationConfig`.                                                                           | Same cost trade-off.                                       |
| **Cloudflare**                       | 100 MB default body size on most plans; higher on Enterprise.                      | Body inspection for managed rules depends on plan and rule; payload logging for inspection is gated behind plan tiers.                                           | Configure via dashboard or API; some inspection is opaque. |

---

## 3. The Log Evidence

### 3.1 GCP Cloud Armor

Find requests denied for body-size violations (when the LB rejects, before Cloud Armor runs):

```text
resource.type="http_load_balancer"
AND httpRequest.status=413
```

When Cloud Armor itself rejects (preconfigured rule fires on something inside the body):

```text
resource.type="http_load_balancer"
AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
AND httpRequest.requestSize>1048576   // requests > 1 MB
```

### 3.2 AWS WAF

```text
fields @timestamp, action, terminatingRuleId, httpRequest.uri, httpRequest.httpMethod, httpRequest.bodyParsingFallbackBehavior
| filter action = "BLOCK"
| filter @message like /SizeRestrictionExceeded/ or @message like /BodyLimit/
| sort @timestamp desc
| limit 100
```

`httpRequest.bodyParsingFallbackBehavior` (when set) tells you whether the WAF inspected the body fully, fell back to a partial inspection, or skipped inspection altogether.

CloudWatch metric: `RequestBodyMissingError` and `RequestBodyTooLarge` per Web ACL.

### 3.3 Cloudflare

```bash
curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/security/events?datetime_geq=2026-06-17T10:00:00Z" \
  -H "Authorization: Bearer $CF_TOKEN" \
  | jq '.result[] | select(.rule_message | test("size|payload|body")) |
        {ray_id, rule_id, rule_message, action, occurred_at}'
```

For Logpush `http_requests`, fields `EdgeRequestHost`, `EdgeResponseStatus`, `ClientRequestBytes` show body size and disposition.

### 3.4 Local reproduction

```bash
# Generate a 20 MB random file and try uploading.
dd if=/dev/urandom of=/tmp/big.bin bs=1M count=20
curl -v -X POST "https://app.example.com/api/v1/uploads" \
     -H "Content-Type: application/octet-stream" \
     --data-binary @/tmp/big.bin 2>&1 | tail -20
```

Bisect to find the exact threshold:

```bash
for size in 1 5 8 16 32 64; do
  dd if=/dev/urandom of=/tmp/test.bin bs=1M count=$size 2>/dev/null
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://app.example.com/api/v1/uploads" \
         -H "Content-Type: application/octet-stream" --data-binary @/tmp/test.bin)
  echo "${size}MB -> $code"
done
```

### 3.5 Offline check

For the AWS-WAF-truncated-body case (the WAF saw only the first N bytes):

```bash
# Verify whether an attack pattern fell past the inspection window.
python - <<'PY'
inspection_limit = 8 * 1024   # 8 KB AWS default
body = b"benign-prefix " * 600   # ~7.8 KB benign
attack = b"<script>alert(1)</script>"
body += attack
print(f"body size: {len(body)} bytes")
print(f"inspection window: {inspection_limit} bytes")
print(f"attack offset: {body.find(attack)} (visible: {body.find(attack) < inspection_limit})")
PY
```

This kind of analysis is what makes the inspection-limit gap dangerous — attackers can intentionally pad benign content to push the malicious payload past the inspection window.

---

## 4. The Remediation Matrix

> **Strong preference: pre-signed URLs.** If the upload can go to object storage directly, do that. The WAF only sees the tiny pre-sign-request, which is fully inspectable. This is the right answer for nearly all "I need to upload a 500 MB file" cases.
>
> If you must accept the upload through your WAF, raise the limit **only on the specific upload endpoint** (scope by path), document the compensating controls in the audit row, and use the strictest body inspection budget you can afford.

### 4.1 GCP Cloud Armor

Raise body inspection size on a security policy:

```hcl
resource "google_compute_security_policy" "uploads" {
  name = "uploads-policy"

  advanced_options_config {
    json_parsing = "STANDARD"
    log_level    = "VERBOSE"

    json_custom_config {
      content_types = ["application/json", "application/json+ld"]
    }
  }

  # Note: body inspection size is configured at the security policy level
  # via Cloud Armor Enterprise (CAEP) — confirm tier before raising.
  # For Standard tier, body inspection is limited; rely on path-scoped exclusions
  # and app-layer scanning for large uploads.

  rule {
    # Standard preconfigured rules ...
    priority = 1000
    # ...
  }
}
```

The architectural recommendation for GCP large-upload workloads: **route uploads through Cloud Storage signed URLs**, not through the LB:

```hcl
# In your application code (Terraform doesn't generate signed URLs; this is illustrative).
# Client requests POST /api/uploads/presign -> small request, fully WAF-inspected.
# Server returns a signed URL valid for 15 min with object size cap.
# Client PUTs directly to https://storage.googleapis.com/<bucket>/<obj>?X-Goog-Signature=...
# Storage event triggers Pub/Sub -> Cloud Function/Run handler to process.
```

If direct-to-storage is impractical, raise the LB's request size limit on the upload backend service only, and add app-layer ClamAV scanning:

```hcl
resource "google_compute_backend_service" "uploads" {
  name = "uploads-backend"
  # ... usual backend config

  # Per-backend security policy with exclusions on the upload path only:
  security_policy = google_compute_security_policy.uploads_policy.id
}
```

### 4.2 AWS WAF

Raise the body inspection limit via `association_config` on the Web ACL — affects the ALB resource type:

```hcl
resource "aws_wafv2_web_acl" "api" {
  name  = "api-acl"
  scope = "REGIONAL"

  default_action { allow {} }

  association_config {
    request_body {
      api_gateway {
        default_size_inspection_limit = "KB_16"
      }
      cloudfront {
        default_size_inspection_limit = "KB_32"
      }
      app_runner_service {
        default_size_inspection_limit = "KB_16"
      }
      cognito_user_pool {
        default_size_inspection_limit = "KB_16"
      }
      verified_access_instance {
        default_size_inspection_limit = "KB_16"
      }
    }
  }

  # ... rules
}
```

The inspection-limit raise is a Web-ACL-wide setting. For an upload-specific endpoint without raising globally, use a separate Web ACL on a dedicated upload subdomain (`uploads.example.com`) with its own larger limit, and keep the main API ACL at the default 8 KB.

For pre-signed-URL pattern on AWS, the upload route hits S3 directly and never traverses ALB+WAF — eliminating the inspection-limit issue entirely.

### 4.3 Cloudflare

Cloudflare's body-size handling is mostly opaque (managed per plan). To handle large uploads safely:

1. **Cloudflare R2 / Workers for pre-signed uploads** is the on-platform equivalent of the pre-signed-URL pattern.
2. For HTTP uploads through Cloudflare to origin: confirm your plan's body-size limit (100 MB on most paid plans; higher on Enterprise). For larger, contact Cloudflare for chunked-upload guidance.
3. **Skip managed-rule body inspection for the upload path** when relying on app-layer scanning:

```hcl
resource "cloudflare_ruleset" "skip_managed_for_uploads" {
  zone_id = var.zone_id
  name    = "Skip managed for /uploads — pre-signed body path"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules {
    action = "skip"
    action_parameters {
      ruleset = "current"
      phases  = ["http_request_firewall_managed"]
    }
    expression  = "(http.request.uri.path eq \"/api/v1/uploads\" and http.request.method eq \"POST\")"
    description = "Skip managed WAF on /api/v1/uploads (multipart bodies > inspection window). ClamAV scan + presigned-URL migration tracked in JIRA-9301. EXCEPTIONS.md row YYYY-MM-DD."
    enabled     = true
  }
}
```

### 4.4 Verification

- Upload of the target file size succeeds; backend handler-entry log line present.
- A known-malicious test payload uploaded **as content of a large file** is caught by app-layer AV scanning (ClamAV / Defender) before persistence; logged with rejection event.
- Per-customer upload quota enforcement at app layer still works (e.g. customer A is over their 1 GB monthly quota → app returns 413, not the WAF).

---

## 5. Audit Trail

```
| 2026-06-17 | uploads.example.com | aws-waf | Raised association_config request_body inspection to 32 KB on regional ALB | upload subdomain only | Video CMS allows up to 500 MB uploads; presigned-URL migration in flight (JIRA-9301, ETA Q3). Compensating: ClamAV scan in upload handler (commit a1b2c3d), per-customer monthly quota (commit d4e5f6g). | <link to before/after CloudWatch metrics + curl bisection> | preview 2026-06-17 → enforce 2026-06-20 | @platform-lead + @secops-lead | 2026-09-15 (review at presigned-URL launch) |
```

Two approvers: platform (because it raises infra cost) and secops (because it widens inspection gap).

---

## 6. Common pitfalls

- **Conflating edge body-size with WAF inspection size.** They are different limits with different consequences. Edge limit = hard reject; WAF inspection limit = silent partial check. Tune them as two separate decisions.
- **Raising WAF inspection limit globally.** Each Web ACL tunable affects every resource attached to it. Use a dedicated upload-subdomain ACL with its own larger limit rather than raising the main API ACL.
- **Forgetting the inspection-gap exposure.** When the WAF only inspects the first N bytes, attackers can pad with benign content and put the payload past N. App-layer scanning is the compensating control.
- **MIME-type spoofing.** Don't trust the client's `Content-Type` on uploads. Sniff the actual bytes (libmagic, fileTypeMagic.js, magic-bytes.js, etc.) before persisting.
- **AV scanning latency.** ClamAV scanning a 500 MB file takes seconds. Queue scans asynchronously; mark the upload as "pending scan" and don't expose it to consumers until scanning completes.
- **Per-customer quotas at the app layer are non-negotiable.** Without them, one over-eager customer can fill your storage. Enforce per-customer monthly upload caps in your application even if the platform has limits at the bucket level.
- **Pre-signed URLs are scoped — make sure scopes are tight.** The pre-signed URL should be issued for a single object key, single HTTP method (PUT), short TTL (15 min), and size-limited (use `Content-Length` constraints in the signed policy). A loose pre-signed URL becomes a "any file, any size, any time" capability.
- **CDN body buffering.** Some CDNs buffer the full body before forwarding to origin. Even with chunked uploads from the client, your origin may see a single large request. Check the CDN's documentation; configure streaming pass-through where available.
- **Health-check vs upload routing.** Route uploads through a separate ingress (NLB → upload service, or dedicated upload subdomain) so they don't compete with your normal API traffic for the same connection pool.

---

## See also

- [docs/concepts/rate-limiting.md](rate-limiting.md) — composite-key pattern relevant to per-customer upload quotas at the edge.
- [docs/concepts/geoblocking-exceptions.md](geoblocking-exceptions.md) — same IP-list + audit-row discipline.
- [docs/rules/941100.md](../rules/941100.md), [docs/rules/941160.md](../rules/941160.md) — bodies past the inspection window where XSS rules silently miss content.
- [docs/provider-guides/gcp-cloud-armor.md](../provider-guides/gcp-cloud-armor.md), [docs/provider-guides/aws-waf.md](../provider-guides/aws-waf.md), [docs/provider-guides/cloudflare-waf.md](../provider-guides/cloudflare-waf.md)
- [EXCEPTIONS.md](../../EXCEPTIONS.md)

---

## References

### Standards & general

- RFC 9110 §15.5.14 (`413 Content Too Large`) — [https://datatracker.ietf.org/doc/html/rfc9110#status.413](https://datatracker.ietf.org/doc/html/rfc9110#status.413).
- RFC 7578 (multipart/form-data) — [https://datatracker.ietf.org/doc/html/rfc7578](https://datatracker.ietf.org/doc/html/rfc7578).
- tus protocol (resumable uploads) — [https://tus.io/](https://tus.io/).

### Google Cloud Armor

- Tiers & quotas (body inspection availability) — [https://cloud.google.com/armor/quotas](https://cloud.google.com/armor/quotas).
- Cloud Storage signed URLs — [https://cloud.google.com/storage/docs/access-control/signed-urls](https://cloud.google.com/storage/docs/access-control/signed-urls).
- Resumable uploads (Cloud Storage) — [https://cloud.google.com/storage/docs/performing-resumable-uploads](https://cloud.google.com/storage/docs/performing-resumable-uploads).

### AWS WAF

- `AssociationConfig.RequestBody` (per-resource-type inspection limits) — [https://docs.aws.amazon.com/waf/latest/APIReference/API_AssociationConfig.html](https://docs.aws.amazon.com/waf/latest/APIReference/API_AssociationConfig.html).
- Inspecting request bodies — [https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-setting-body-inspection.html](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-setting-body-inspection.html).
- S3 pre-signed PUT URLs — [https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html).
- API Gateway payload limits — [https://docs.aws.amazon.com/apigateway/latest/developerguide/limits.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/limits.html).
- Terraform `aws_wafv2_web_acl` `association_config` — [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl).

### Cloudflare

- Cloudflare upload limits (per plan) — [https://developers.cloudflare.com/cache/concepts/default-cache-behavior/#cloudflare-response-limits](https://developers.cloudflare.com/cache/concepts/default-cache-behavior/#cloudflare-response-limits).
- R2 (S3-compatible object storage) pre-signed URLs — [https://developers.cloudflare.com/r2/api/s3/presigned-urls/](https://developers.cloudflare.com/r2/api/s3/presigned-urls/).
- Workers + R2 for streaming uploads — [https://developers.cloudflare.com/r2/api/workers/workers-multipart-usage/](https://developers.cloudflare.com/r2/api/workers/workers-multipart-usage/).

### Anti-virus / content scanning

- ClamAV — [https://www.clamav.net/](https://www.clamav.net/).
- AWS S3 + Lambda + ClamAV reference architecture — [https://aws.amazon.com/blogs/developer/virus-scan-s3-buckets-with-a-serverless-clamav-based-cdk-construct/](https://aws.amazon.com/blogs/developer/virus-scan-s3-buckets-with-a-serverless-clamav-based-cdk-construct/).
- libmagic (MIME sniffing) — [https://man7.org/linux/man-pages/man3/libmagic.3.html](https://man7.org/linux/man-pages/man3/libmagic.3.html).
