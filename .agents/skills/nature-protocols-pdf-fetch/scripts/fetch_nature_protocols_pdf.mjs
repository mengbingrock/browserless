#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';

const subscriptionMessage = 'Access through your institution';

const { values } = parseArgs({
  options: {
    article: { type: 'string' },
    endpoint: { default: 'http://127.0.0.1:3000', type: 'string' },
    help: { default: false, short: 'h', type: 'boolean' },
    out: { type: 'string' },
    residential: { default: false, type: 'boolean' },
    'residential-city': { type: 'string' },
    'residential-country': { type: 'string' },
    'residential-region': { type: 'string' },
    'residential-rotation': { default: 'session', type: 'string' },
    timeout: { default: '180000', type: 'string' },
  },
  strict: true,
});

const usage = `
Usage:
  BROWSERLESS_TOKEN=... node fetch_nature_protocols_pdf.mjs \\
    --article 'https://www.nature.com/articles/s41596-ARTICLE_ID' \\
    --out output/pdf/s41596-ARTICLE_ID.pdf \\
    [--endpoint http://127.0.0.1:3000] [--timeout 180000]

Optional residential routing:
  --residential [--residential-country US] [--residential-region CA] \\
    [--residential-city 'Los Angeles'] \\
    [--residential-rotation session|connection]
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
  !/(^|\.)nature\.com$/i.test(articleURL.hostname) ||
  !/^\/articles\/s41596-/i.test(articleURL.pathname)
) {
  throw new Error(
    '--article must be a nature.com Nature Protocols article URL',
  );
}

const endpoint = new URL(values.endpoint);
const timeout = Number(values.timeout);
if (!Number.isInteger(timeout) || timeout < 1000) {
  throw new Error('--timeout must be an integer of at least 1000 milliseconds');
}
if (!['connection', 'session'].includes(values['residential-rotation'])) {
  throw new Error('--residential-rotation must be session or connection');
}

const functionURL = new URL('/function', endpoint);
functionURL.searchParams.set('token', token);
functionURL.searchParams.set('timeout', String(timeout));
functionURL.searchParams.set(
  'launch',
  Buffer.from(JSON.stringify({ stealth: true })).toString('base64'),
);

if (values.residential) {
  functionURL.searchParams.set('residentialProxy', 'true');
  functionURL.searchParams.set(
    'residentialProxyRotation',
    values['residential-rotation'],
  );
  for (const [option, parameter] of [
    ['residential-country', 'residentialProxyCountry'],
    ['residential-region', 'residentialProxyRegion'],
    ['residential-city', 'residentialProxyCity'],
  ]) {
    const value = values[option];
    if (value) functionURL.searchParams.set(parameter, value);
  }
}

const functionCode = String.raw`
export default async ({ page, context }) => {
  await page.goto(context.articleURL, {
    waitUntil: 'networkidle2',
    timeout: context.navigationTimeout,
  });

  const state = await page.evaluate((articleHref) => {
    const article = new URL(articleHref);
    const expectedPDFPath = article.pathname + '.pdf';
    const bodyText = document.body?.innerText ?? '';
    const anchors = [...document.querySelectorAll('a[href]')];
    const mainPDFLink = anchors.find((anchor) => {
      try {
        const candidate = new URL(anchor.href, location.href);
        return (
          /(^|\.)nature\.com$/i.test(candidate.hostname) &&
          candidate.pathname === expectedPDFPath
        );
      } catch {
        return false;
      }
    });

    if (mainPDFLink) {
      mainPDFLink.removeAttribute('target');
      mainPDFLink.dataset.browserlessMainPdf = 'true';
    }

    return {
      accessThroughInstitutionVisible:
        /access through your institution/i.test(bodyText),
      citationPDFURL:
        document.querySelector('meta[name="citation_pdf_url"]')?.content ?? null,
      journalTitle:
        document.querySelector('meta[name="citation_journal_title"]')?.content ??
        null,
      mainPDFURL: mainPDFLink?.href ?? null,
      title:
        document.querySelector('meta[name="citation_title"]')?.content ??
        document.title,
    };
  }, context.articleURL);

  if (
    state.journalTitle &&
    state.journalTitle.toLowerCase() !== 'nature protocols'
  ) {
    return {
      message: 'The rendered article is not from Nature Protocols',
      status: 'wrong-journal',
    };
  }

  if (state.accessThroughInstitutionVisible) {
    return {
      message: context.subscriptionMessage,
      status: 'subscription-required',
    };
  }

  if (!state.mainPDFURL) {
    return {
      citationPDFURL: state.citationPDFURL,
      message:
        'No visible main-article PDF link was found; entitlement is ambiguous',
      status: 'pdf-link-missing',
    };
  }

  const client = await page.createCDPSession();
  await client.send('Fetch.enable', {
    patterns: [{ requestStage: 'Response', urlPattern: '*' }],
  });

  const captured = new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('Timed out capturing the Nature PDF response')),
      context.navigationTimeout,
    );

    client.on('Fetch.requestPaused', async (event) => {
      try {
        const headers = Object.fromEntries(
          (event.responseHeaders ?? []).map(({ name, value }) => [
            name.toLowerCase(),
            value,
          ]),
        );
        const status = event.responseStatusCode ?? 0;
        const locationHeader = headers.location;

        if (status >= 300 && status < 400 && locationHeader) {
          const redirect = new URL(locationHeader, event.request.url);
          if (redirect.pathname === new URL(context.articleURL).pathname) {
            clearTimeout(timer);
            await client.send('Fetch.continueResponse', {
              requestId: event.requestId,
            });
            resolve({ subscriptionRequired: true });
            return;
          }
        }

        const isPDF =
          status === 200 &&
          (headers['content-type'] ?? '')
            .toLowerCase()
            .includes('application/pdf');
        if (!isPDF) {
          await client.send('Fetch.continueResponse', {
            requestId: event.requestId,
          });
          return;
        }

        const response = await client.send('Fetch.getResponseBody', {
          requestId: event.requestId,
        });
        clearTimeout(timer);
        resolve({
          bytes: response.base64Encoded
            ? Uint8Array.from(atob(response.body), (char) => char.charCodeAt(0))
            : new TextEncoder().encode(response.body),
          pdfURL: event.request.url,
        });
      } catch (error) {
        clearTimeout(timer);
        reject(error);
      }
    });
  });

  page.click('[data-browserless-main-pdf="true"]').catch(() => undefined);
  const result = await captured;
  if (result.subscriptionRequired) {
    return {
      message: context.subscriptionMessage,
      status: 'subscription-required',
    };
  }

  return result.bytes;
};
`;

const response = await fetch(functionURL, {
  body: JSON.stringify({
    code: functionCode,
    context: {
      articleURL: articleURL.href,
      navigationTimeout: Math.min(timeout, 120000),
      subscriptionMessage,
    },
  }),
  headers: { 'content-type': 'application/json' },
  method: 'POST',
  signal: AbortSignal.timeout(timeout + 10000),
});

if (!response.ok) {
  const message = (await response.text()).slice(0, 2000);
  throw new Error(`/function failed with HTTP ${response.status}: ${message}`);
}

const contentType = response.headers.get('content-type') ?? '';
if (contentType.toLowerCase().includes('application/json')) {
  const result = await response.json();
  if (result.status === 'subscription-required') {
    console.log(subscriptionMessage);
    process.exit(3);
  }
  throw new Error(result.message ?? `Nature fetch stopped: ${result.status}`);
}

const pdf = new Uint8Array(await response.arrayBuffer());
const magic = new TextDecoder().decode(pdf.slice(0, 5));
if (
  !contentType.toLowerCase().includes('application/pdf') ||
  !magic.startsWith('%PDF-')
) {
  throw new Error(
    `Browserless returned ${contentType || 'unknown content'} instead of PDF bytes`,
  );
}

const outputPath = path.resolve(values.out);
const pdfURL = new URL(`${articleURL.pathname}.pdf`, articleURL).href;
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
      pdfURL,
      sha256: createHash('sha256').update(pdf).digest('hex'),
    },
    null,
    2,
  ),
);
