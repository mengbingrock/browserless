import {
  BadGateway,
  Config,
  Logger,
  ServiceUnavailable,
  Timeout,
  TwoCaptchaClient,
  TwoCaptchaError,
  TwoCaptchaTask,
  TwoCaptchaTimeoutError,
  sleep,
} from '@browserless.io/browserless';
import { CDPSession, HTTPResponse, Page } from 'puppeteer-core';

interface TurnstileCapture extends TwoCaptchaTask {
  action?: string;
  data?: string;
  pagedata?: string;
  type: 'TurnstileTaskProxyless';
  userAgent: string;
  websiteKey: string;
  websiteURL: string;
}

type CapturingWindow = Window & {
  __browserlessTwoCaptchaCallback?: (token: string) => unknown;
};

/**
 * Intercepts Cloudflare Turnstile's render call before page scripts run, sends
 * the captured task to 2Captcha, then invokes Turnstile's original callback.
 */
export class TwoCaptchaPageSolver {
  protected capture?: TurnstileCapture;
  protected captureResolver?: (task: TurnstileCapture) => void;
  protected readonly capturePromise = new Promise<TurnstileCapture>(
    (resolve) => {
      this.captureResolver = resolve;
    },
  );
  protected debuggerClient?: CDPSession;
  protected renderBreakpointId?: string;
  protected prepared = false;

  constructor(
    protected readonly page: Page,
    protected readonly client: TwoCaptchaClient,
    protected readonly logger: Logger,
    protected readonly detectionTimeoutMs: number,
    protected readonly navigationTimeoutMs: number,
  ) {}

  public async prepare(): Promise<void> {
    if (this.prepared) return;
    this.prepared = true;

    const installOnloadHook = (name: string) => {
      const pageWindow = window as unknown as Window & Record<string, unknown>;
      const marker = `__browserlessTurnstileOnload_${name}`;
      if (pageWindow[marker]) return;
      pageWindow[marker] = true;
      let callback = pageWindow[name];
      try {
        Object.defineProperty(pageWindow, name, {
          configurable: true,
          get: () =>
            function browserlessTurnstileOnload(
              this: unknown,
              ...args: unknown[]
            ) {
              debugger;
              return typeof callback === 'function'
                ? callback.apply(this, args)
                : undefined;
            },
          set: (value: unknown) => {
            callback = value;
          },
        });
      } catch {
        // A non-configurable callback cannot be wrapped safely.
      }
    };

    await this.page.evaluateOnNewDocument(installOnloadHook, 'khCN8');
    this.page.on('request', (request) => {
      try {
        const url = new URL(request.url());
        if (
          url.hostname !== 'challenges.cloudflare.com' ||
          !url.pathname.includes('/turnstile/') ||
          !url.pathname.endsWith('/api.js')
        ) {
          return;
        }
        const onload = url.searchParams.get('onload');
        if (!onload) return;
        this.page.evaluate(installOnloadHook, onload).catch(() => {});
      } catch {
        // Ignore malformed and non-HTTP request URLs.
      }
    });

    const client = await this.page.createCDPSession();
    this.debuggerClient = client;
    await client.send('Debugger.enable');
    client.on('Debugger.paused', async (event) => {
      const frame = event.callFrames[0];
      this.logger.debug(
        `Turnstile debugger paused in ${frame?.functionName || 'anonymous'}`,
      );
      if (!frame) {
        await client.send('Debugger.resume').catch(() => {});
        return;
      }

      try {
        if (this.renderBreakpointId) {
          const evaluated = await client.send('Debugger.evaluateOnCallFrame', {
            callFrameId: frame.callFrameId,
            expression: `(() => {
              const options = arguments[1] || {};
              window.__browserlessTwoCaptchaCallback = options.callback;
              return {
                action: options.action,
                data: options.cData,
                pagedata: options.chlPageData,
                type: 'TurnstileTaskProxyless',
                userAgent: navigator.userAgent,
                websiteKey: options.sitekey,
                websiteURL: location.href,
              };
            })()`,
            returnByValue: true,
          });
          const task = evaluated.result.value as TurnstileCapture | undefined;
          this.logger.debug(
            `Turnstile render capture ${task?.websiteKey ? 'contained a site key' : 'was incomplete'}`,
          );
          if (task?.websiteKey && !this.capture) {
            this.capture = task;
            this.captureResolver?.(task);
          }
          await client
            .send('Debugger.removeBreakpoint', {
              breakpointId: this.renderBreakpointId,
            })
            .catch(() => {});
          this.renderBreakpointId = undefined;
        } else {
          const evaluated = await client.send('Debugger.evaluateOnCallFrame', {
            callFrameId: frame.callFrameId,
            expression: 'window.turnstile && window.turnstile.render',
          });
          if (evaluated.result.objectId) {
            const breakpoint = await client.send(
              'Debugger.setBreakpointOnFunctionCall',
              { objectId: evaluated.result.objectId },
            );
            this.renderBreakpointId = breakpoint.breakpointId;
            this.logger.debug('Turnstile render breakpoint installed');
          }
        }
      } finally {
        await client.send('Debugger.resume').catch(() => {});
      }
    });
  }

  public async solveIfPresent(
    response?: HTTPResponse | null | void,
  ): Promise<HTTPResponse | null | undefined> {
    const headers = response?.headers() ?? {};
    const isChallenge =
      headers['cf-mitigated'] === 'challenge' || response?.status() === 403;
    const capture = await Promise.race([
      this.capturePromise,
      sleep(isChallenge ? this.detectionTimeoutMs : 500).then(() => null),
    ]);

    if (!capture) return response ?? undefined;
    let target = 'the current page';
    try {
      target = new URL(capture.websiteURL).origin;
    } catch {
      // Keep the safe generic label for non-standard URLs.
    }
    this.logger.info(
      `Solving ${capture.type} CAPTCHA on ${target} with 2Captcha`,
    );

    let result;
    try {
      result = await this.client.solve(capture);
    } catch (error) {
      if (error instanceof TwoCaptchaError) {
        if (error instanceof TwoCaptchaTimeoutError) {
          throw new Timeout(error.message);
        }
        throw new BadGateway(
          `${error.errorCode ? `${error.errorCode}: ` : ''}${error.message}`,
        );
      }
      throw error;
    }

    const token = result.solution?.token;
    if (typeof token !== 'string' || !token) {
      throw new BadGateway(
        '2Captcha returned a Turnstile result without a token',
      );
    }
    const solvedUserAgent = result.solution?.userAgent;
    if (typeof solvedUserAgent === 'string' && solvedUserAgent) {
      await this.page.setUserAgent(solvedUserAgent);
    }

    const navigation = this.page
      .waitForNavigation({
        timeout: this.navigationTimeoutMs,
        waitUntil: 'networkidle2',
      })
      .catch(() => null);
    await this.page.evaluate((solution: string) => {
      const callback = (window as CapturingWindow)
        .__browserlessTwoCaptchaCallback;
      if (typeof callback !== 'function') {
        throw new Error('Turnstile callback is no longer available');
      }
      callback(solution);
    }, token);

    const solvedResponse = await Promise.race([
      navigation,
      sleep(Math.min(this.navigationTimeoutMs, 10_000)).then(() => null),
    ]);
    this.logger.info('2Captcha Turnstile solution submitted');
    return solvedResponse ?? response ?? undefined;
  }
}

export const createTwoCaptchaPageSolver = async (
  enabled: boolean | undefined,
  page: Page,
  config: Config,
  logger: Logger,
): Promise<TwoCaptchaPageSolver | null> => {
  if (!enabled) return null;
  const apiKey = config.getTwoCaptchaAPIKey();
  if (!apiKey) {
    throw new ServiceUnavailable(
      'CAPTCHA solving requires TWO_CAPTCHA_API_KEY to be configured',
    );
  }
  const solver = new TwoCaptchaPageSolver(
    page,
    new TwoCaptchaClient({
      apiBaseURL: config.getTwoCaptchaAPIBaseURL(),
      apiKey,
      pollingIntervalMs: config.getTwoCaptchaPollingInterval(),
      timeoutMs: config.getTwoCaptchaTimeout(),
    }),
    logger,
    config.getTwoCaptchaDetectionTimeout(),
    config.getTwoCaptchaTimeout(),
  );
  await solver.prepare();
  return solver;
};
