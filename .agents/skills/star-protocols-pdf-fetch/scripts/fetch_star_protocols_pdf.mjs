#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';

const { values } = parseArgs({
  options: {
    article: { type: 'string' },
    endpoint: { default: 'http://127.0.0.1:3000', type: 'string' },
    help: { default: false, short: 'h', type: 'boolean' },
    out: { type: 'string' },
    'solve-captchas': { default: false, type: 'boolean' },
    timeout: { default: '180000', type: 'string' },
  },
  strict: true,
});

const usage = `
Usage:
  BROWSERLESS_TOKEN=... node fetch_star_protocols_pdf.mjs \\
    --article 'https://www.cell.com/star-protocols/fulltext/ARTICLE_ID' \\
    --out output/pdf/ARTICLE_ID.pdf [--endpoint http://127.0.0.1:3000] \\
    [--solve-captchas] [--timeout 180000]
`;

if (values.help) {
  console.log(usage.trim());
  process.exit(0);
}

const token = process.env.BROWSERLESS_TOKEN;
if (!token) throw new Error('BROWSERLESS_TOKEN is required');
if (!values.article) throw new Error('--article is required');
if (!values.out) throw new Error('--out is required');

const articleURL = new URL(values.article);
if (
  !/(^|\.)cell\.com$/i.test(articleURL.hostname) ||
  !articleURL.pathname.includes('/star-protocols/')
) {
  throw new Error('--article must be a cell.com STAR Protocols URL');
}

const endpoint = new URL(values.endpoint);
const timeout = Number(values.timeout);
if (!Number.isInteger(timeout) || timeout < 1000) {
  throw new Error('--timeout must be an integer of at least 1000 milliseconds');
}

const request = async (url, init) => {
  const response = await fetch(url, {
    ...init,
    signal: AbortSignal.timeout(timeout + 10000),
  });
  if (!response.ok) {
    const message = (await response.text()).slice(0, 1000);
    throw new Error(
      `${url.pathname} failed with HTTP ${response.status}: ${message}`,
    );
  }
  return response;
};

const contentURL = new URL('/content', endpoint);
contentURL.searchParams.set('token', token);
contentURL.searchParams.set('timeout', String(timeout));

const contentResponse = await request(contentURL, {
  body: JSON.stringify({
    gotoOptions: {
      timeout: Math.min(timeout, 120000),
      waitUntil: 'networkidle2',
    },
    solveCaptchas: values['solve-captchas'],
    url: articleURL.href,
    waitForTimeout: 5000,
  }),
  headers: { 'content-type': 'application/json' },
  method: 'POST',
});
const html = await contentResponse.text();

const decodeHTMLAttribute = (value) =>
  value
    .replaceAll('&amp;', '&')
    .replaceAll('&#38;', '&')
    .replaceAll('&#x26;', '&');

const pdfMatch = html.match(/href=["']([^"']*\/action\/showPdf\?[^"']+)["']/i);
if (!pdfMatch?.[1]) {
  throw new Error(
    'The rendered article did not contain an /action/showPdf link',
  );
}
const pdfURL = new URL(decodeHTMLAttribute(pdfMatch[1]), articleURL);

const title =
  html.match(
    /<meta\s+name=["']citation_title["']\s+content=["']([^"']+)/i,
  )?.[1] ??
  html.match(/<title>([^<]+)/i)?.[1] ??
  null;

const functionCode = String.raw`
export default async ({ page, context }) => {
  await page.goto(context.articleURL, {
    waitUntil: 'networkidle2',
    timeout: context.navigationTimeout,
  });

  const client = await page.createCDPSession();
  await client.send('Fetch.enable', {
    patterns: [{ requestStage: 'Response', urlPattern: '*action/showPdf*' }],
  });

  const captured = new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('Timed out capturing the PDF response')),
      context.navigationTimeout,
    );

    client.on('Fetch.requestPaused', async (event) => {
      try {
        if (!event.responseStatusCode) {
          await client.send('Fetch.continueRequest', {
            requestId: event.requestId,
          });
          return;
        }
        if (event.responseStatusCode !== 200) {
          throw new Error(
            'PDF navigation failed with HTTP ' + event.responseStatusCode,
          );
        }
        const response = await client.send('Fetch.getResponseBody', {
          requestId: event.requestId,
        });
        clearTimeout(timer);
        resolve(
          response.base64Encoded
            ? Uint8Array.from(atob(response.body), (char) => char.charCodeAt(0))
            : new TextEncoder().encode(response.body),
        );
      } catch (error) {
        clearTimeout(timer);
        reject(error);
      }
    });
  });

  page
    .goto(context.pdfURL, {
      referer: context.articleURL,
      waitUntil: 'domcontentloaded',
      timeout: context.navigationTimeout,
    })
    .catch(() => undefined);

  return await captured;
};
`;

const functionURL = new URL('/function', endpoint);
functionURL.searchParams.set('token', token);
functionURL.searchParams.set('timeout', String(timeout));
functionURL.searchParams.set(
  'launch',
  Buffer.from(JSON.stringify({ stealth: true })).toString('base64'),
);

const pdfResponse = await request(functionURL, {
  body: JSON.stringify({
    code: functionCode,
    context: {
      articleURL: articleURL.href,
      navigationTimeout: Math.min(timeout, 120000),
      pdfURL: pdfURL.href,
    },
  }),
  headers: { 'content-type': 'application/json' },
  method: 'POST',
});
const pdf = new Uint8Array(await pdfResponse.arrayBuffer());
const magic = new TextDecoder().decode(pdf.slice(0, 5));
if (!magic.startsWith('%PDF-')) {
  throw new Error(
    `Browserless returned ${pdfResponse.headers.get('content-type') ?? 'unknown content'} instead of PDF bytes`,
  );
}

const outputPath = path.resolve(values.out);
await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, pdf, { flag: 'wx' }).catch((error) => {
  if (error?.code === 'EEXIST') {
    throw new Error(`Refusing to overwrite existing file: ${outputPath}`);
  }
  throw error;
});

console.log(
  JSON.stringify(
    {
      articleURL: articleURL.href,
      bytes: pdf.byteLength,
      output: outputPath,
      pdfURL: pdfURL.href,
      sha256: createHash('sha256').update(pdf).digest('hex'),
      solveCaptchas: values['solve-captchas'],
      title,
    },
    null,
    2,
  ),
);
