export const twoCaptchaAPIBaseURL = 'https://api.2captcha.com';

export interface TwoCaptchaTask {
  type: string;
  [key: string]: unknown;
}

export interface TwoCaptchaCreateTaskOptions {
  callbackUrl?: string;
  languagePool?: 'en' | 'ru';
  softId?: number;
}

export interface TwoCaptchaCreateTaskResponse {
  errorId: number;
  taskId: number;
}

export interface TwoCaptchaTaskResult {
  cost?: string;
  createTime?: number;
  endTime?: number;
  errorCode?: string;
  errorDescription?: string;
  errorId: number;
  ip?: string;
  solution?: Record<string, unknown>;
  solveCount?: number;
  status?: 'processing' | 'ready';
}

export interface TwoCaptchaClientOptions {
  apiBaseURL?: string;
  apiKey: string;
  fetch?: typeof globalThis.fetch;
  pollingIntervalMs?: number;
  timeoutMs?: number;
}

export interface TwoCaptchaSolveOptions extends TwoCaptchaCreateTaskOptions {
  signal?: AbortSignal;
}

export class TwoCaptchaError extends Error {
  constructor(
    message: string,
    public readonly errorId?: number,
    public readonly errorCode?: string,
  ) {
    super(message);
    this.name = 'TwoCaptchaError';
  }
}

export class TwoCaptchaTimeoutError extends TwoCaptchaError {
  constructor(message: string) {
    super(message);
    this.name = 'TwoCaptchaTimeoutError';
  }
}

const assertRecord = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TwoCaptchaError('2Captcha returned an invalid JSON response');
  }
  return value as Record<string, unknown>;
};

const delay = (time: number, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, time);
    signal?.addEventListener('abort', onAbort, { once: true });
  });

/** A small dependency-free client for the 2Captcha JSON API v2. */
export class TwoCaptchaClient {
  protected readonly apiBaseURL: string;
  protected readonly apiKey: string;
  protected readonly fetchImpl: typeof globalThis.fetch;
  protected readonly pollingIntervalMs: number;
  protected readonly timeoutMs: number;

  constructor({
    apiBaseURL = twoCaptchaAPIBaseURL,
    apiKey,
    fetch: fetchImpl = globalThis.fetch,
    pollingIntervalMs = 5_000,
    timeoutMs = 120_000,
  }: TwoCaptchaClientOptions) {
    if (!apiKey.trim()) {
      throw new TwoCaptchaError('A 2Captcha API key is required');
    }
    if (!Number.isFinite(pollingIntervalMs) || pollingIntervalMs < 1) {
      throw new TwoCaptchaError('2Captcha polling interval must be positive');
    }
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1) {
      throw new TwoCaptchaError('2Captcha timeout must be positive');
    }

    this.apiBaseURL = apiBaseURL.replace(/\/$/, '');
    this.apiKey = apiKey;
    this.fetchImpl = fetchImpl;
    this.pollingIntervalMs = pollingIntervalMs;
    this.timeoutMs = timeoutMs;
  }

  protected async post(
    path: string,
    body: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<Record<string, unknown>> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.apiBaseURL}/${path}`, {
        body: JSON.stringify(body),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
        signal,
      });
    } catch (error) {
      if (signal?.aborted) throw error;
      throw new TwoCaptchaError(
        `Unable to reach 2Captcha: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    if (!response.ok) {
      throw new TwoCaptchaError(
        `2Captcha returned HTTP ${response.status} ${response.statusText}`.trim(),
      );
    }

    let payload: Record<string, unknown>;
    try {
      payload = assertRecord(await response.json());
    } catch (error) {
      if (error instanceof TwoCaptchaError) throw error;
      throw new TwoCaptchaError('2Captcha returned an invalid JSON response');
    }

    const errorId = Number(payload.errorId ?? 0);
    if (errorId !== 0) {
      const errorCode =
        typeof payload.errorCode === 'string' ? payload.errorCode : undefined;
      const description =
        typeof payload.errorDescription === 'string'
          ? payload.errorDescription
          : '2Captcha could not complete the request';
      throw new TwoCaptchaError(description, errorId, errorCode);
    }

    return payload;
  }

  public async createTask(
    task: TwoCaptchaTask,
    options: TwoCaptchaCreateTaskOptions = {},
    signal?: AbortSignal,
  ): Promise<TwoCaptchaCreateTaskResponse> {
    if (!task || typeof task.type !== 'string' || !task.type.trim()) {
      throw new TwoCaptchaError('A 2Captcha task with a type is required');
    }

    const payload = await this.post(
      'createTask',
      {
        clientKey: this.apiKey,
        task,
        ...(options.callbackUrl ? { callbackUrl: options.callbackUrl } : {}),
        ...(options.languagePool ? { languagePool: options.languagePool } : {}),
        ...(options.softId !== undefined ? { softId: options.softId } : {}),
      },
      signal,
    );
    const taskId = Number(payload.taskId);
    if (!Number.isSafeInteger(taskId) || taskId <= 0) {
      throw new TwoCaptchaError('2Captcha did not return a valid task id');
    }

    return { errorId: 0, taskId };
  }

  public async getTaskResult(
    taskId: number,
    signal?: AbortSignal,
  ): Promise<TwoCaptchaTaskResult> {
    if (!Number.isSafeInteger(taskId) || taskId <= 0) {
      throw new TwoCaptchaError('A valid 2Captcha task id is required');
    }
    return (await this.post(
      'getTaskResult',
      { clientKey: this.apiKey, taskId },
      signal,
    )) as unknown as TwoCaptchaTaskResult;
  }

  public async solve(
    task: TwoCaptchaTask,
    { signal, ...createOptions }: TwoCaptchaSolveOptions = {},
  ): Promise<TwoCaptchaTaskResult> {
    if (createOptions.callbackUrl) {
      throw new TwoCaptchaError(
        'callbackUrl cannot be used when waiting for a 2Captcha result',
      );
    }

    const { taskId } = await this.createTask(task, createOptions, signal);
    const deadline = Date.now() + this.timeoutMs;

    while (Date.now() < deadline) {
      await delay(
        Math.min(this.pollingIntervalMs, deadline - Date.now()),
        signal,
      );
      const result = await this.getTaskResult(taskId, signal);
      if (result.status === 'ready') return result;
      if (result.status !== 'processing') {
        throw new TwoCaptchaError(
          `2Captcha returned an unknown task status: ${String(result.status)}`,
        );
      }
    }

    throw new TwoCaptchaTimeoutError(
      `2Captcha did not solve the task within ${this.timeoutMs}ms`,
    );
  }
}
