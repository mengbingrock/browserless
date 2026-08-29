---
name: star-protocols-pdf-fetch
description: Fetch STAR Protocols article pages and download their official PDFs through a local or self-hosted Browserless server, with optional server-side 2Captcha solving. Use for cell.com/star-protocols full-text URLs, especially when the publisher PDF returns 403 to plain HTTP clients.
---

# STAR Protocols PDF Fetch

Retrieve the rendered article first, derive the publisher's PDF link from that content, and download the real PDF binary. Prefer the bundled helper because Cell commonly returns `403` to `curl`, while Chrome's PDF viewer can replace an accepted PDF response with an HTML wrapper.

## Requirements

- Use a local or user-controlled Browserless endpoint. Do not substitute Browserless cloud unless the user asks.
- Read the Browserless API token from `BROWSERLESS_TOKEN`; do not print it or place it in saved scripts.
- `--solve-captchas` uses the Browserless server's `TWO_CAPTCHA_API_KEY`. Never send the 2Captcha key in the request body. Because solving can consume paid balance, enable it only when the user requested or approved captcha solving.
- Treat publisher access restrictions and subscription requirements as authoritative. Do not attempt to bypass a paywall or authorization boundary.

## Run the workflow

Use [scripts/fetch_star_protocols_pdf.mjs](scripts/fetch_star_protocols_pdf.mjs):

```bash
export BROWSERLESS_TOKEN='your-browserless-token'
node scripts/fetch_star_protocols_pdf.mjs \
  --endpoint http://127.0.0.1:3000 \
  --article 'https://www.cell.com/star-protocols/fulltext/ARTICLE_ID' \
  --out 'output/pdf/ARTICLE_ID.pdf' \
  --solve-captchas
```

When Browserless is remote and only exposes plain HTTP, prefer an SSH tunnel instead of transmitting its token publicly. The helper accepts any endpoint reachable from the machine running it.

The helper performs these stages:

1. POST `/content` for the supplied full-text URL, optionally with `solveCaptchas: true`, and retain the rendered HTML.
2. Extract the actual `/action/showPdf?...` link from that HTML. Do not guess a PDF URL from the article identifier when the rendered page provides one.
3. Start a stealth Browserless `/function` session, visit the article to establish publisher state, and navigate to the extracted PDF with the article as referrer.
4. Intercept the `showPdf` response at the Chrome DevTools `Fetch` response stage. This captures the publisher bytes before Chrome's PDF extension substitutes its viewer document.
5. Require HTTP `200` and `%PDF-` magic before writing the file. Report the title, discovered URL, byte count, and SHA-256.

## Failure handling

- If `/content` reports that `TWO_CAPTCHA_API_KEY` is missing, recreate the Browserless container after updating its `--env-file`; `docker restart` does not load newly added environment variables.
- If the article succeeds but a plain PDF request returns `403`, do not retry plain HTTP repeatedly. Use the bundled CDP response capture.
- If the browser response is HTML with `application/pdf`, it is probably Chrome's PDF viewer wrapper, not the PDF. The `%PDF-` check must still pass.
- Preserve an existing output file unless the user explicitly permits replacement; choose a distinct filename for retests.
- A successful request with `solveCaptchas: true` proves the solving path was enabled, but not that Cell presented a challenge or that 2Captcha consumed a task. State that distinction in the result.
