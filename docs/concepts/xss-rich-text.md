# XSS False Positives on Rich-Text / WYSIWYG Payloads â€” CRS `941xxx`

> WYSIWYG editors, Markdown-to-HTML pipelines, and any feature that lets a user submit HTML or JS-like content will eventually collide with the OWASP CRS `941xxx` XSS family. This page is a stub â€” expand as concrete reproductions land.

---

## 1. The Symptom

- `403 Forbidden` when **saving** content from a rich-text editor (TinyMCE, CKEditor, Quill, ProseMirror, Trix).
- Works fine for **plain-text** input on the same form; breaks the moment the user pastes formatted content, an `<iframe>`, an embedded image, or a code snippet containing `<script>` examples.
- The failing request is typically a `POST` / `PUT` with a JSON body whose `content` / `body` / `html` field contains HTML markup.
- May co-occur with **`913xxx`** (scanner detection) when the input contains tool-generated boilerplate.

---

## 2. The Diagnosis

The `941xxx` family covers reflected/stored XSS patterns:

| Rule     | Triggers on                                                                                |
| -------- | ------------------------------------------------------------------------------------------ |
| `941100` | XSS attack patterns in `ARGS` â€” `<script>`, `javascript:`, event handlers like `onerror=`. |
| `941110` | XSS via script tag attributes.                                                             |
| `941160` | NoScript XSS filters bypass.                                                               |
| `941170` | XSS via attribute vectors (`href=javascript:`, `src=data:`).                               |
| `941310` | UTF-7 encoded XSS attempt â€” fires on legitimate Asian-language content occasionally.       |

These rules inspect **request bodies** when `Content-Type` is form-encoded or JSON. Any field that legitimately carries HTML â€” blog posts, comments, descriptions, internal-knowledge-base entries, support-ticket bodies â€” is a candidate.

The fundamental conflict: there is **no syntactic difference** between an attacker's `<script>` payload and a user pasting a `<script>` example into a code-formatting block. The fix is to (a) sanitize on the app side with a strict HTML allow-list and (b) scope a WAF exclusion to the specific known-rich-text field.

---

## 3. The Log Evidence

Use the same provider queries as [cookie-false-positives.md](cookie-false-positives.md) Â§3, swapping the rule ID. Example for GCP:

```text
resource.type="http_load_balancer"
AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
AND jsonPayload.enforcedSecurityPolicy.preconfiguredExprIds:"owasp-crs-v030301-id941100-xss"
```

---

## 4. The Remediation Matrix

Same shape as cookie FPs: **path-scoped, field-scoped exclusion in preview, then enforce**.

- **GCP Cloud Armor:** `preconfigured_waf_config.exclusion` with `request_query_param` or â€” for JSON bodies â€” a `request_uri` scoping combined with `target_rule_set = "xss-v33-stable"` and the specific rule ID. See [../provider-guides/gcp-cloud-armor.md](../provider-guides/gcp-cloud-armor.md).
- **AWS WAF:** rule-action override on the XSS rule of the managed group, with a `scope_down_statement` matching the path. See [../provider-guides/aws-waf.md](../provider-guides/aws-waf.md).
- **Cloudflare:** managed-ruleset override for the XSS rule, scoped to the `http.request.uri.path`. See [../provider-guides/cloudflare-waf.md](../provider-guides/cloudflare-waf.md).

> **Non-negotiable prerequisite:** before requesting any `941xxx` exclusion, the affected endpoint MUST run server-side HTML sanitization (e.g. DOMPurify, OWASP Java HTML Sanitizer, Bleach) with a documented allow-list. The exclusion narrows WAF coverage; sanitization restores the defense. PRs without a sanitization reference will be rejected.

---

## 5. Audit Trail Entry

Standard row in [../../EXCEPTIONS.md](../../EXCEPTIONS.md). In the **Justification** column, include the link/commit SHA proving the sanitization is in place.

---

## See also

- [cookie-false-positives.md](cookie-false-positives.md) â€” same shape of exclusion, different rule family.
- [../triage/identifying-blocks.md](../triage/identifying-blocks.md)
- [../../EXCEPTIONS.md](../../EXCEPTIONS.md)
