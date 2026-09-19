import {
  Logger,
  Request,
  TwoCaptchaClient,
  TwoCaptchaPageSolver,
  TwoCaptchaTask,
  TwoCaptchaTaskResult,
  chromeExecutablePath,
} from '@browserless.io/browserless';
import { expect } from 'chai';
import puppeteer from 'puppeteer-core';
import ChromiumContentPostRoute from '../shared/content.http.js';

describe('TwoCaptchaPageSolver', function () {
  this.timeout(15_000);

  it('enables stealth when CAPTCHA solving is requested', () => {
    const route = new ChromiumContentPostRoute(
      undefined as never,
      undefined as never,
      undefined as never,
      undefined as never,
      undefined as never,
      undefined as never,
      undefined as never,
    );
    const launchOptions = (
      route.defaultLaunchOptions as (req: Request) => { stealth?: boolean }
    )({ body: { solveCaptchas: true } } as Request);

    expect(launchOptions).to.deep.equal({ stealth: true });
  });

  it('intercepts Turnstile and submits the solved token', async () => {
    const browser = await puppeteer.launch({
      executablePath: chromeExecutablePath(),
      headless: true,
    });
    try {
      const page = await browser.newPage();
      let submittedTask: TwoCaptchaTask | undefined;
      const client = {
        solve: async (task: TwoCaptchaTask): Promise<TwoCaptchaTaskResult> => {
          submittedTask = task;
          return {
            errorId: 0,
            solution: { token: '2captcha-token' },
            status: 'ready',
          };
        },
      } as TwoCaptchaClient;
      const solver = new TwoCaptchaPageSolver(
        page,
        client,
        new Logger('captcha-test'),
        1_000,
        50,
      );
      await solver.prepare();
      await page.goto(
        `data:text/html,${encodeURIComponent(`
          <body></body>
          <script>
            window.turnstile = {
              render: function (_container, _options) {
                document.body.dataset.rendered = 'true';
                return 'original';
              }
            };
            let onloadCalls = 0;
            window.khCN8 = () => {
              onloadCalls += 1;
              if (onloadCalls === 1) return;
              window.turnstile.render(null, {
                action: 'managed',
                callback: token => document.body.dataset.token = token,
                cData: 'captured-data',
                chlPageData: 'captured-page-data',
                sitekey: 'captured-site-key'
              });
            };
            window.khCN8();
            window.khCN8();
          </script>
        `)}`,
      );

      await solver.solveIfPresent();

      expect(submittedTask).to.include({
        action: 'managed',
        data: 'captured-data',
        pagedata: 'captured-page-data',
        type: 'TurnstileTaskProxyless',
        websiteKey: 'captured-site-key',
      });
      expect(await page.evaluate(() => document.body.dataset.token)).to.equal(
        '2captcha-token',
      );
      expect(
        await page.evaluate(() => document.body.dataset.rendered),
      ).to.equal('true');

      await page.evaluate(() => {
        delete (
          window as Window & {
            __browserlessTwoCaptchaCallback?: unknown;
          }
        ).__browserlessTwoCaptchaCallback;
        document.title = 'Search results';
      });
      await solver.solveIfPresent();
    } finally {
      await browser.close();
    }
  });
});
