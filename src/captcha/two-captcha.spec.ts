import {
  TwoCaptchaClient,
  TwoCaptchaError,
  TwoCaptchaTimeoutError,
} from '@browserless.io/browserless';
import { expect } from 'chai';

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    headers: { 'content-type': 'application/json' },
    status,
  });

describe('TwoCaptchaClient', () => {
  it('creates, polls, and returns a solved API v2 task', async () => {
    const requests: Array<{ body: Record<string, unknown>; url: string }> = [];
    const responses = [
      jsonResponse({ errorId: 0, taskId: 123 }),
      jsonResponse({ errorId: 0, status: 'processing' }),
      jsonResponse({
        cost: '0.00145',
        errorId: 0,
        solution: { token: 'solved-token' },
        status: 'ready',
      }),
    ];
    const fetch = async (input: string | URL | Request, init?: RequestInit) => {
      requests.push({
        body: JSON.parse(String(init?.body)),
        url: String(input),
      });
      return responses.shift()!;
    };
    const client = new TwoCaptchaClient({
      apiBaseURL: 'https://captcha.test/',
      apiKey: 'secret-key',
      fetch,
      pollingIntervalMs: 1,
      timeoutMs: 100,
    });

    const result = await client.solve(
      {
        type: 'TurnstileTaskProxyless',
        websiteKey: 'site-key',
        websiteURL: 'https://example.com',
      },
      { languagePool: 'en', softId: 42 },
    );

    expect(result.solution).to.deep.equal({ token: 'solved-token' });
    expect(requests.map(({ url }) => url)).to.deep.equal([
      'https://captcha.test/createTask',
      'https://captcha.test/getTaskResult',
      'https://captcha.test/getTaskResult',
    ]);
    expect(requests[0].body).to.deep.equal({
      clientKey: 'secret-key',
      languagePool: 'en',
      softId: 42,
      task: {
        type: 'TurnstileTaskProxyless',
        websiteKey: 'site-key',
        websiteURL: 'https://example.com',
      },
    });
  });

  it('surfaces 2Captcha API errors with their code', async () => {
    const client = new TwoCaptchaClient({
      apiKey: 'secret-key',
      fetch: async () =>
        jsonResponse({
          errorCode: 'ERROR_ZERO_BALANCE',
          errorDescription: 'Account has zero balance',
          errorId: 10,
        }),
    });

    let error: unknown;
    try {
      await client.createTask({ type: 'ImageToTextTask', body: 'abc' });
    } catch (caught) {
      error = caught;
    }

    expect(error).to.be.instanceOf(TwoCaptchaError);
    expect(error).to.include({
      errorCode: 'ERROR_ZERO_BALANCE',
      errorId: 10,
      message: 'Account has zero balance',
    });
  });

  it('rejects malformed tasks before sending a request', async () => {
    let called = false;
    const client = new TwoCaptchaClient({
      apiKey: 'secret-key',
      fetch: async () => {
        called = true;
        return jsonResponse({});
      },
    });

    let error: unknown;
    try {
      await client.createTask({ type: '' });
    } catch (caught) {
      error = caught;
    }
    expect(error).to.be.instanceOf(TwoCaptchaError);
    expect((error as Error).message).to.include('task with a type');
    expect(called).to.equal(false);
  });

  it('times out when a task remains in processing', async () => {
    let calls = 0;
    const client = new TwoCaptchaClient({
      apiKey: 'secret-key',
      fetch: async () =>
        ++calls === 1
          ? jsonResponse({ errorId: 0, taskId: 123 })
          : jsonResponse({ errorId: 0, status: 'processing' }),
      pollingIntervalMs: 1,
      timeoutMs: 1,
    });

    let error: unknown;
    try {
      await client.solve({ type: 'TextCaptchaTask', comment: 'question' });
    } catch (caught) {
      error = caught;
    }

    expect(error).to.be.instanceOf(TwoCaptchaTimeoutError);
  });
});
