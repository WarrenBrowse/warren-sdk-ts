import { describe, expect, it } from 'vitest';
import { fetchTransport } from '../src/index.js';

/** A recording stand-in for the global fetch. */
function fakeFetch(status: number, body: string) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    return { status, text: async () => body } as Response;
  }) as typeof fetch;
  return { impl, calls };
}

describe('fetchTransport', () => {
  it('sends method, headers and body and maps status + text', async () => {
    const { impl, calls } = fakeFetch(201, '{"ok":1}');
    const res = await fetchTransport(impl).send({
      method: 'POST',
      url: 'https://api.example.com/v1/register',
      headers: { 'content-type': 'application/json' },
      body: '{"a":1}',
      useSni: true,
    });

    expect(res).toEqual({ status: 201, body: '{"ok":1}' });
    expect(calls[0]!.url).toBe('https://api.example.com/v1/register');
    expect(calls[0]!.init.method).toBe('POST');
    expect(calls[0]!.init.body).toBe('{"a":1}');
    expect(calls[0]!.init.headers).toEqual({ 'content-type': 'application/json' });
  });

  it('omits the body entirely on body-less requests (fetch rejects a GET body)', async () => {
    const { impl, calls } = fakeFetch(200, '');
    await fetchTransport(impl).send({
      method: 'GET',
      url: 'https://api.example.com/v1/exits',
      headers: {},
      body: '',
      useSni: true,
    });

    expect('body' in calls[0]!.init).toBe(false);
  });

  it('resolves (not rejects) on an error status so the fallback never advances', async () => {
    const { impl } = fakeFetch(503, 'unavailable');
    const res = await fetchTransport(impl).send({
      method: 'GET',
      url: 'https://api.example.com/v1/exits',
      headers: {},
      body: '',
      useSni: true,
    });

    expect(res).toEqual({ status: 503, body: 'unavailable' });
  });
});
