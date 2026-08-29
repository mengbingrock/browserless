---
name: lacourt-case-document-fetch
description: Search a Los Angeles Superior Court civil case and download an available document preview PDF through a local or self-hosted Browserless session. Use for lacourt.ca.gov case-number workflows that pass through guest access and reCAPTCHA; do not use to purchase records or bypass restricted access.
---

# LA Court Case Document Fetch

Use one persistent Browserless browser session from case search through PDF capture. The court workflow depends on cookies and navigation state, so do not replace intermediate browser actions with independent HTTP requests.

## Requirements

- Use a local or user-controlled Browserless endpoint. Do not substitute Browserless cloud unless the user asks.
- Read the Browserless token from `BROWSERLESS_TOKEN`; never print or save it.
- CAPTCHA solving is a paid external action. Use it only when the user requested or approved it. The self-hosted Browserless server must hold `TWO_CAPTCHA_API_KEY`; never put that key in the client request or this skill.
- Access only case records the user is authorized to retrieve. Do not bypass login, payment, sealed-record, or other access controls. A court-provided preview may contain fewer pages than the listed document.
- Save the PDF but do not open it unless the user separately asks.

## Inputs

Collect or infer:

- the case number;
- the document name, such as `Complaint`;
- a writable output PDF path;
- a snapshot directory;
- the local or self-hosted Browserless endpoint.

Default search page:

`https://www.lacourt.ca.gov/pages/lp/access-a-case/tp/find-case-information/cp/os-civil-case-access`

## Browser workflow

1. Connect Puppeteer or CDP to the Browserless endpoint and create one page. Enable response interception before navigation so the later PDF response cannot be missed.
2. Navigate to the default search page and wait for the case-search form. Save a full-page snapshot.
3. Enter the case number in `CASE NUMBER`, leave `FILING COURTHOUSE` unchanged unless the user supplied one, and save a snapshot showing the entered value.
4. Click `Search`, wait for the case-information result, and verify that the displayed case number exactly matches the requested case. Save a snapshot. Stop with a clear message if no matching case appears.
5. Click `Click here to access document images for this case.` Wait for the `Public Access Online Services` page and save a snapshot.
6. Click `Continue as Guest`. On `Case Document Images`, verify the case number again and save a snapshot of the document list.
7. Find the row whose normalized document title exactly matches the requested document. Use that row's `Preview` button. Do not select the purchase checkbox or use `Submit` unless the user explicitly requests and authorizes a paid workflow.
8. Wait for `Case Document Images Preview`. If the page says `Please answer the CAPTCHA.`, save a pre-solve snapshot and follow the CAPTCHA procedure below. If no challenge appears, continue to PDF capture.
9. After successful CAPTCHA completion, wait for the browser PDF viewer or a PDF network response and save a post-solve snapshot. Capture and validate the PDF as described below.

Prefer labels and visible text over brittle CSS selectors. Re-read the rendered page after every navigation because the court uses multiple applications and origins during this sequence.

## CAPTCHA procedure

The observed preview challenge is Google reCAPTCHA v2, not Cloudflare Turnstile. Browserless's `solveCaptchas: true` page helper is Turnstile-specific, so do not assume it solves this page automatically.

1. Read the reCAPTCHA site key from the rendered widget (`data-sitekey`) or its iframe URL and retain the current preview-page URL as `websiteURL`.
2. POST a `RecaptchaV2TaskProxyless` task to the self-hosted Browserless `/captcha` endpoint, authenticated with `BROWSERLESS_TOKEN`. The server supplies its configured 2Captcha client key:

   ```json
   {
     "task": {
       "type": "RecaptchaV2TaskProxyless",
       "websiteURL": "<current preview URL>",
       "websiteKey": "<site key>"
     }
   }
   ```

3. Use the returned `solution.gRecaptchaResponse` in the same live page. Set the `g-recaptcha-response` field and invoke the widget's registered success callback; setting the hidden textarea alone may not advance the application.
4. Wait for navigation or the PDF request. If the page still shows the CAPTCHA, capture a failure snapshot and stop rather than repeatedly spending 2Captcha balance.

Do not report that a CAPTCHA was solved merely because solving was enabled. Confirm that the challenge disappeared and the PDF response arrived.

## PDF capture and validation

- At the CDP `Fetch` response stage, watch for the preview response that returns `application/pdf`. Continue unrelated paused responses promptly.
- Read the response body before allowing Chrome's PDF viewer to replace it with an extension page. Decode it if CDP marks it base64-encoded.
- Require HTTP `200` and `%PDF-` magic before writing the file. Do not save an HTML viewer shell as `.pdf`.
- Preserve an existing output file unless the user explicitly permits replacement. Create a distinct filename for retests.
- After writing, verify the file is non-empty and report its byte count, page count, and SHA-256.
- Describe the artifact as a court-provided preview. If the case list says the document has more pages than the downloaded PDF, report the mismatch; do not claim the preview is the complete filing.

## Snapshots and stopping conditions

Save a snapshot at each meaningful state, using ordered filenames such as:

```text
01-case-search-page.jpg
02-case-number-entered.jpg
03-case-search-result.jpg
04-document-images-portal.jpg
05-guest-document-list.jpg
06-document-preview-captcha.jpg
07-document-preview-solved.jpg
```

Also save the current page on unexpected errors. Stop without downloading when the case number does not match, the requested document is absent, the site requires credentials or payment not authorized by the user, CAPTCHA solving fails, or the captured body is not a valid PDF.

On success, return the case number, matched document title, output path, PDF byte and page counts, SHA-256, and snapshot directory. End after saving and verifying the file; do not open it.
