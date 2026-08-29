---
name: nature-protocols-pdf-fetch
description: Check Nature Protocols access through local or self-hosted Browserless and download the official article PDF only when the rendered page shows entitlement. Use for nature.com Nature Protocols article URLs, especially when a citation PDF URL redirects back to a subscription page.
---

# Nature Protocols PDF Fetch

Check entitlement before attempting the article PDF. Use the bundled helper so the access decision and PDF validation are deterministic.

## Run

Use a local or user-controlled Browserless endpoint, not Browserless cloud:

```bash
export BROWSERLESS_TOKEN='your-browserless-token'
node scripts/fetch_nature_protocols_pdf.mjs \
  --endpoint http://127.0.0.1:3000 \
  --article 'https://www.nature.com/articles/s41596-ARTICLE_ID' \
  --out 'output/pdf/s41596-ARTICLE_ID.pdf'
```

Add `--residential` and the relevant geo selectors when the self-hosted server has a consenting residential agent connected:

```bash
node scripts/fetch_nature_protocols_pdf.mjs \
  --endpoint http://self-hosted-browserless.example:3000 \
  --article 'https://www.nature.com/articles/s41596-ARTICLE_ID' \
  --out 'output/pdf/s41596-ARTICLE_ID.pdf' \
  --residential --residential-country US --residential-region CA
```

## Entitlement rule

Inspect the rendered page's visible text and controls in Browserless before downloading anything.

- If the page shows `Access through your institution`, return exactly that message and stop. Do not request the main PDF, retry with CAPTCHA solving, or download a supplementary PDF as a substitute. The helper exits with status `3` and does not create the output file.
- If the access message is absent but the rendered main-article PDF link is visible, click that link in the same browser session and capture the PDF response.
- If neither condition is clear, report the ambiguity and stop. Do not infer entitlement from metadata alone.

## Lessons learned

- A `citation_pdf_url` meta tag exists even when the IP has no subscription. It is discovery metadata, not proof of access.
- For an unsubscribed session, Nature can return HTTP `303` from the `.pdf` URL back to the article. Treat that redirect as `Access through your institution` and stop.
- Supplementary Information and Reporting Summary PDFs hosted on `media.springernature.com` may remain downloadable while the main article is restricted. They are not the article PDF.
- IP rotation and CAPTCHA solving do not create subscription entitlement. Preserve Nature's access boundary.
- Require HTTP `200`, an `application/pdf` response, and `%PDF-` magic before saving. Preserve an existing output file rather than overwriting it.

On success, report the article URL, discovered PDF URL, output path, byte count, and SHA-256.
