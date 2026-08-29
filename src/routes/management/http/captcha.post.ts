import {
  APITags,
  BadGateway,
  BadRequest,
  BrowserlessRoutes,
  HTTPRoute,
  HTTPRoutes,
  Methods,
  Request,
  ServiceUnavailable,
  Timeout,
  TwoCaptchaClient,
  TwoCaptchaError,
  TwoCaptchaTask,
  TwoCaptchaTaskResult,
  TwoCaptchaTimeoutError,
  contentTypes,
  jsonResponse,
} from '@browserless.io/browserless';
import { ServerResponse } from 'http';

export interface BodySchema {
  /** Any 2Captcha API v2 task object. The server supplies clientKey. */
  task: TwoCaptchaTask;
  /** Worker language pool for image- and text-based tasks. */
  languagePool?: 'en' | 'ru';
  /** Optional registered 2Captcha software id. */
  softId?: number;
}

export type ResponseSchema = TwoCaptchaTaskResult;

export default class CaptchaPostRoute extends HTTPRoute {
  name = BrowserlessRoutes.CaptchaPostRoute;
  accepts = [contentTypes.json];
  auth = true;
  browser = null;
  // Solving is external I/O and should not consume a browser concurrency slot.
  concurrency = false;
  contentTypes = [contentTypes.json];
  description = `Submits any 2Captcha API v2 task and waits for its solution. Configure the server with TWO_CAPTCHA_API_KEY; the key is never accepted from or returned to API callers.`;
  method = Methods.post;
  path = HTTPRoutes.captcha;
  tags = [APITags.browserAPI];

  async handler(req: Request, res: ServerResponse): Promise<void> {
    const body = req.body as BodySchema | undefined;
    if (!body?.task || typeof body.task.type !== 'string') {
      throw new BadRequest(`A "task" object with a "type" is required.`);
    }

    const config = this.config();
    const apiKey = config.getTwoCaptchaAPIKey();
    if (!apiKey) {
      throw new ServiceUnavailable(
        'CAPTCHA solving requires TWO_CAPTCHA_API_KEY to be configured',
      );
    }

    const abortController = new AbortController();
    req.once('aborted', () => abortController.abort());
    const client = new TwoCaptchaClient({
      apiBaseURL: config.getTwoCaptchaAPIBaseURL(),
      apiKey,
      pollingIntervalMs: config.getTwoCaptchaPollingInterval(),
      timeoutMs: config.getTwoCaptchaTimeout(),
    });

    try {
      const result = await client.solve(body.task, {
        languagePool: body.languagePool,
        signal: abortController.signal,
        softId: body.softId,
      });
      return jsonResponse(res, 200, result);
    } catch (error) {
      if (!(error instanceof TwoCaptchaError)) throw error;
      if (error instanceof TwoCaptchaTimeoutError) {
        throw new Timeout(error.message);
      }
      throw new BadGateway(
        `${error.errorCode ? `${error.errorCode}: ` : ''}${error.message}`,
      );
    }
  }
}
