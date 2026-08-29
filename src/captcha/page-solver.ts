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
import { HTTPResponse, Page } from 'puppeteer-core';

interface TurnstileCapture extends TwoCaptchaTask {
  action?: string;
  data?: string;
  pagedata?: string;
  type: 'TurnstileTaskProxyless';
  userAgent: string;
  websiteKey: string;
  websiteURL: string;
}

const captureFunctionName = '__browserlessTwoCaptchaCapture';

type CapturingWindow = Window & {
  __browserlessTwoCaptchaCallback?: (token: string) => unknown;
  __browserlessTwoCaptchaCapture?: (task: TurnstileCapture) => void;
  turnstile?: {
    render: (
      container: unknown,
      options: {
        action?: string;
        callback?: (token: string) => unknown;
        cData?: string;
        chlPageData?: string;
        sitekey: string;
      },
    ) => string;
  };
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

    await this.page.exposeFunction(
      captureFunctionName,
      (task: TurnstileCapture) => {
        if (this.capture) return;
        this.capture = task;
        this.captureResolver?.(task);
      },
    );

    await this.page.evaluateOnNewDocument((detectionTimeout: number) => {
      const pageWindow = window as CapturingWindow;
      const intercept = (
        turnstile: NonNullable<CapturingWindow['turnstile']>,
      ) => {
        if (turnstile.render.name === 'browserlessTurnstileRender') return;
        turnstile.render = function browserlessTurnstileRender(
          _container,
          options,
        ) {
          pageWindow.__browserlessTwoCaptchaCallback = options.callback;
          pageWindow.__browserlessTwoCaptchaCapture?.({
            action: options.action,
            data: options.cData,
            pagedata: options.chlPageData,
            type: 'TurnstileTaskProxyless',
            userAgent: navigator.userAgent,
            websiteKey: options.sitekey,
            websiteURL: window.location.href,
          });
          return 'browserless-turnstile';
        };
      };

      let turnstileValue = pageWindow.turnstile;
      try {
        Object.defineProperty(pageWindow, 'turnstile', {
          configurable: true,
          get: () => turnstileValue,
          set: (value: NonNullable<CapturingWindow['turnstile']>) => {
            turnstileValue = value;
            if (value) intercept(value);
          },
        });
      } catch {
        // The polling fallback below also covers non-configurable globals.
      }
      const timer = window.setInterval(() => {
        if (!pageWindow.turnstile) return;
        window.clearInterval(timer);
        intercept(pageWindow.turnstile);
      }, 10);
      window.setTimeout(() => window.clearInterval(timer), detectionTimeout);
    }, this.detectionTimeoutMs);
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
