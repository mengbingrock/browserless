import { Browser, Page } from 'puppeteer-core';
import { BrowserWebSocketTransport } from 'puppeteer-core/internal/common/BrowserWebSocketTransport.js';
import { _connectToCdpBrowser as connect } from 'puppeteer-core/internal/cdp/BrowserConnector.js';

type codeHandler = (params: {
  context: unknown;
  goto: Page['goto'];
  page: Page;
}) => Promise<unknown>;

declare global {
  interface Window {
    __browserlessWaitForCaptcha?: () => Promise<void>;
  }
}

// puppeteer-core >= 25.6 requires an explicit Logger on these internals.
const logger = () => undefined;

export class FunctionRunner {
  protected browser?: Browser;
  protected page?: Page;

  public log() {
    return console.log.bind(console);
  }

  public async start(data: {
    browserWSEndpoint: string;
    code: codeHandler;
    context: unknown;
    options: {
      downloadPath?: string;
      protocolTimeout?: number;
      solveCaptchas?: boolean;
    };
  }) {
    console.log(`/function.js: Got endpoint: "${data.browserWSEndpoint}"`);
    const { browserWSEndpoint, code, context, options } = data;
    const connectionTransport = await BrowserWebSocketTransport.create(
      browserWSEndpoint,
      undefined,
      logger,
    );
    const cdpOptions = {
      headers: {
        Host: '127.0.0.1',
      },
      protocolTimeout: options.protocolTimeout,
    };

    this.browser = (await connect(
      connectionTransport,
      browserWSEndpoint,
      cdpOptions,
      logger,
    )) as unknown as Browser;
    this.browser.once('disconnected', () => this.stop());
    this.page = await this.browser.newPage();

    let goto = this.page.goto.bind(this.page);
    if (options.solveCaptchas) {
      const waitForCaptcha = async () => {
        for (let attempt = 0; attempt < 10; attempt += 1) {
          try {
            await this.page!.waitForFunction(
              () => typeof window.__browserlessWaitForCaptcha === 'function',
              { timeout: options.protocolTimeout },
            );
            await this.page!.evaluate(() =>
              window.__browserlessWaitForCaptcha?.(),
            );
            return;
          } catch (error) {
            const message =
              error instanceof Error ? error.message : String(error);
            const contextWasReplaced =
              /Execution context was destroyed|Cannot find context|detached Frame/i.test(
                message,
              );
            if (!contextWasReplaced || attempt === 9) throw error;
          }
        }
      };

      await this.page.waitForFunction(
        () => typeof window.__browserlessWaitForCaptcha === 'function',
        { timeout: options.protocolTimeout },
      );
      const browserGoto = goto;
      goto = async (...args: Parameters<Page['goto']>) => {
        const response = await browserGoto(...args);
        await waitForCaptcha();
        return response;
      };
    }

    if (options.downloadPath) {
      console.debug(
        `_browserless_function_client_: Setting downloads for page to "${options.downloadPath}"`,
      );
      // @ts-ignore
      const client = this.page._client.call(this.page);
      await client.send('Page.setDownloadBehavior', {
        behavior: 'allow',
        downloadPath: options.downloadPath,
      });
    }

    const response = await code({ context, goto, page: this.page }).catch(
      (e) => {
        console.error(`Error running code: ${e}`);
        this.browser?.disconnect();
        throw e;
      },
    );
    console.debug(
      `_browserless_function_client_: Code is finished executing, closing page.`,
    );
    this.page.close().catch(this.log);

    if (response instanceof Uint8Array) {
      return {
        contentType: 'uint8array',
        payload: Array.from(response),
      };
    }

    if (typeof response === 'string') {
      return {
        contentType: response.startsWith('<') ? 'text/html' : 'text/plain',
        payload: response,
      };
    }

    if (typeof response === 'object') {
      return {
        contentType: 'application/json',
        payload: JSON.stringify(response, null, '  '),
      };
    }

    return {
      contentType: 'text/plain',
      payload: response,
    };
  }

  public stop() {
    if (this.browser) this.browser.disconnect();
  }
}

// Set this as an immutable property on window so our handler's
// can call it downstream
Object.defineProperty(window, 'BrowserlessFunctionRunner', {
  configurable: false,
  enumerable: false,
  value: FunctionRunner,
  writable: false,
});
