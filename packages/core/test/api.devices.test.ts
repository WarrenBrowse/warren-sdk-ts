import { hexToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  type DeviceRegistration,
  type HttpRequest,
  type HttpResponse,
  WarrenApiClient,
  WarrenApiError,
  parseDeviceId,
} from '../src/index.js';

const ID = parseDeviceId('AAECAwQFBgcICQoLDA0ODw');
const REGISTRATION: DeviceRegistration = {
  device_id: ID,
  name: 'calm heron',
  platform: 'browser',
  app_version: '0.1.8',
};

function client(answer: HttpResponse): { api: WarrenApiClient; requests: HttpRequest[] } {
  const requests: HttpRequest[] = [];
  const api = new WarrenApiClient({
    baseUrl: 'https://api.example.com',
    seed: hexToBytes('42'.repeat(32)),
    transport: {
      async send(req) {
        requests.push(req);
        return answer;
      },
    },
  });
  return { api, requests };
}

async function failure(promise: Promise<unknown>): Promise<WarrenApiError> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(WarrenApiError);
  return err as WarrenApiError;
}

describe('device routes', () => {
  it('reads a 409 on registration as the account device cap', async () => {
    const { api } = client({ status: 409, body: '' });

    const err = await failure(api.registerDevice(REGISTRATION));

    expect(err.code).toBe('device_limit_reached');
    expect(err.status).toBe(409);
  });

  it('reads a revoked device on registration', async () => {
    const { api } = client({ status: 403, body: '{"error":"device_revoked"}' });

    expect((await failure(api.registerDevice(REGISTRATION))).code).toBe('device_revoked');
  });

  it('leaves a server without the registry as a plain 404', async () => {
    const { api } = client({ status: 404, body: '' });

    const err = await failure(api.registerDevice(REGISTRATION));

    expect(err.code).toBe('server');
    expect(err.status).toBe(404);
  });

  it('leaves a 403 with another body as it came', async () => {
    const { api } = client({ status: 403, body: '{"error":"banned","reason_code":"abuse"}' });

    const err = await failure(api.issueTokens({ epochs: [] }));

    expect(err.code).toBe('server');
    expect(err.status).toBe(403);
  });

  it('revokes with a signed DELETE on the device path', async () => {
    const { api, requests } = client({ status: 204, body: '' });

    await api.revokeDevice(ID);

    expect(requests[0]?.method).toBe('DELETE');
    expect(requests[0]?.url).toBe('https://api.example.com/v1/devices/AAECAwQFBgcICQoLDA0ODw');
    expect(requests[0]?.headers['X-Warren-Sig']).toBeDefined();
  });

  it('reads a rename of a device the account does not have as a 404', async () => {
    const { api } = client({ status: 404, body: '' });

    expect((await failure(api.renameDevice(ID, 'kitchen laptop'))).status).toBe(404);
  });

  it('keeps the server body out of a refusal message', async () => {
    const { api } = client({ status: 403, body: '{"error":"device_revoked"}' });

    const err = await failure(api.revokeDevice(ID));

    expect(err.code).toBe('device_revoked');
    expect(err.message).not.toContain(ID);
    expect(err.body).toBeUndefined();
  });
});

describe('issuance transports', () => {
  it('types a device refusal on the browser-proxy lane too', async () => {
    const { api } = client({ status: 403, body: '{"error":"device_unregistered"}' });

    const err = await failure(api.browserProxyTokenTransport().issue({ epochs: [] }));

    expect(err.code).toBe('device_unregistered');
  });

  it('registers through either lane', async () => {
    const view = { ...REGISTRATION, registered_on: '2026-10-28', last_seen_on: '2026-10-29' };
    const answer = { status: 200, body: JSON.stringify({ ...view, this_device: true }) };
    for (const lane of ['tokenTransport', 'browserProxyTokenTransport'] as const) {
      const { api, requests } = client(answer);

      const registered = await api[lane]().registerDevice?.(REGISTRATION);

      expect(registered?.name).toBe('calm heron');
      expect(requests[0]?.url).toBe('https://api.example.com/v1/devices');
    }
  });
});
