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
    'residential-proxy': { default: false, type: 'boolean' },
    'residential-proxy-city': { type: 'string' },
    'residential-proxy-country': { type: 'string' },
    'residential-proxy-region': { type: 'string' },
    'residential-proxy-rotation': { default: 'session', type: 'string' },
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
    [--solve-captchas] [--timeout 180000] [--residential-proxy] \\
    [--residential-proxy-country US] [--residential-proxy-region CA] \\
    [--residential-proxy-city 'Los Angeles']
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
if (!['connection', 'session'].includes(values['residential-proxy-rotation'])) {
  throw new Error(
    '--residential-proxy-rotation must be "connection" or "session"',
  );
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

const functionCode = String.raw`
export default async ({ page, context, goto }) => {
  await goto(context.articleURL, {
    waitUntil: 'networkidle2',
    timeout: context.navigationTimeout,
  });

  const article = await page.evaluate(() => ({
    pdfLink: [...document.querySelectorAll('a[href]')]
      .map(link => link.href)
      .find(href => /\/action\/showPdf\?/i.test(href)),
    title:
      document.querySelector('meta[name="citation_title"]')?.content ||
      document.title ||
      null,
  }));
  const { pdfLink, title } = article;
  if (!pdfLink) {
    throw new Error('The rendered article did not contain an /action/showPdf link');
  }

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
        if (event.responseStatusCode === 403) {
          // Let the challenged PDF navigation render in this same page. The
          // Browserless goto helper will solve it, and this interceptor will
          // capture the subsequent successful PDF response without losing the
          // article session's cookies or browser fingerprint.
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
        const bytes = response.base64Encoded
          ? Uint8Array.from(atob(response.body), char => char.charCodeAt(0))
          : new TextEncoder().encode(response.body);
        let binary = '';
        for (let offset = 0; offset < bytes.length; offset += 0x8000) {
          binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
        }
        resolve({
          pdfBase64: btoa(binary),
          pdfURL: event.request.url,
          title,
        });
      } catch (error) {
        clearTimeout(timer);
        reject(error);
      }
    });
  });

  goto(pdfLink, {
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
if (values['residential-proxy']) {
  functionURL.searchParams.set('residentialProxy', 'true');
  functionURL.searchParams.set(
    'residentialProxyRotation',
    values['residential-proxy-rotation'],
  );
  if (values['residential-proxy-country']) {
    functionURL.searchParams.set(
      'residentialProxyCountry',
      values['residential-proxy-country'],
    );
  }
  if (values['residential-proxy-region']) {
    functionURL.searchParams.set(
      'residentialProxyRegion',
      values['residential-proxy-region'],
    );
  }
  if (values['residential-proxy-city']) {
    functionURL.searchParams.set(
      'residentialProxyCity',
      values['residential-proxy-city'],
    );
  }
}

const pdfResponse = await request(functionURL, {
  body: JSON.stringify({
    code: functionCode,
    context: {
      articleURL: articleURL.href,
      navigationTimeout: Math.min(timeout, 120000),
    },
    solveCaptchas: values['solve-captchas'],
  }),
  headers: { 'content-type': 'application/json' },
  method: 'POST',
});
const result = await pdfResponse.json();
if (
  !result ||
  typeof result.pdfBase64 !== 'string' ||
  typeof result.pdfURL !== 'string'
) {
  throw new Error('Browserless returned an invalid STAR Protocols result');
}
const pdf = new Uint8Array(Buffer.from(result.pdfBase64, 'base64'));
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
      pdfURL: result.pdfURL,
      residentialProxy: values['residential-proxy'],
      sha256: createHash('sha256').update(pdf).digest('hex'),
      solveCaptchas: values['solve-captchas'],
      title: result.title ?? null,
    },
    null,
    2,
  ),
);
