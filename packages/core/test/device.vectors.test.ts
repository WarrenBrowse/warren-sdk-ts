import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  type DeviceId,
  type HttpRequest,
  type HttpResponse,
  WarrenApiClient,
  WarrenApiError,
  WarrenDeviceError,
  deviceIdBytes,
  deviceIdFromBytes,
  parseDeviceId,
  parseDevicePlatform,
  readDeviceList,
  readDeviceView,
} from '../src/index.js';

const vectorPath = fileURLToPath(
  new URL('../../../vectors/device_registry_v1.json', import.meta.url),
);
const v = JSON.parse(readFileSync(vectorPath, 'utf8'));

const SEED = hexToBytes('42'.repeat(32));
const ID = v.device_id.b64url as string;

/** A signed client over a transport answering `answer` and recording every request. */
function client(answer: HttpResponse): { api: WarrenApiClient; requests: HttpRequest[] } {
  const requests: HttpRequest[] = [];
  const api = new WarrenApiClient({
    baseUrl: 'https://api.example.com',
    seed: SEED,
    transport: {
      async send(req) {
        requests.push(req);
        return answer;
      },
    },
  });
  return { api, requests };
}

const ok = (json: unknown): HttpResponse => ({ status: 200, body: JSON.stringify(json) });

describe('device_registry_v1: the device id', () => {
  it('reads each listed id back to its bytes and spells the bytes the same way', () => {
    for (const entry of [v.device_id, v.device_id_url_alphabet]) {
      const id = parseDeviceId(entry.b64url);
      expect(bytesToHex(deviceIdBytes(id))).toBe(entry.bytes_hex);
      expect(deviceIdFromBytes(hexToBytes(entry.bytes_hex))).toBe(entry.b64url);
    }
  });

  it('refuses every spelling the contract refuses', () => {
    for (const { b64url, _why } of v.invalid_device_ids) {
      expect(() => parseDeviceId(b64url), _why).toThrow(WarrenDeviceError);
    }
  });
});

describe('device_registry_v1: platforms', () => {
  it('reads every platform of the closed set as itself', () => {
    for (const platform of v.platforms) expect(parseDevicePlatform(platform)).toBe(platform);
  });

  it('reads a platform outside the set as other', () => {
    expect(parseDevicePlatform(v.unknown_platform.json)).toBe(v.unknown_platform.reads_as);
  });
});

describe('device_registry_v1: the routes', () => {
  it('registers with the body the server reads, and reads its answer', async () => {
    const { api, requests } = client(ok(v.device_view.json));

    const view = await api.registerDevice(v.device_registration.json);

    expect(requests[0]?.method).toBe('POST');
    expect(requests[0]?.url).toBe('https://api.example.com/v1/devices');
    expect(JSON.parse(requests[0]?.body ?? '')).toEqual(v.device_registration.json);
    expect(view).toEqual(v.device_view.json);
  });

  it('lists the devices marking this one, with the older-client day', async () => {
    const { api, requests } = client(ok(v.device_list_response.json));

    const list = await api.listDevices(parseDeviceId(ID));

    expect(requests[0]?.method).toBe('GET');
    expect(requests[0]?.url).toBe(
      `https://api.example.com${v.device_list_response._endpoint.slice(4)}`,
    );
    expect(list).toEqual(v.device_list_response.json);
  });

  it('lists the devices without the older-client day when the server sends none', async () => {
    const { api, requests } = client(ok(v.device_list_response_without_older_client.json));

    const list = await api.listDevices();

    expect(requests[0]?.url).toBe('https://api.example.com/v1/devices');
    expect(list).toEqual(v.device_list_response_without_older_client.json);
    expect('older_client_seen_on' in list).toBe(false);
  });

  it('renames with the body the server reads', async () => {
    const { api, requests } = client({ status: 204, body: '' });

    await api.renameDevice(parseDeviceId(ID), v.device_rename.json.name);

    expect(requests[0]?.method).toBe('PATCH');
    expect(requests[0]?.url).toBe(`https://api.example.com/v1/devices/${ID}`);
    expect(JSON.parse(requests[0]?.body ?? '')).toEqual(v.device_rename.json);
  });

  it('names the device on an issue request only when it has one', async () => {
    const answer = ok({ epochs: [] });
    const anonymous = client(answer);
    const identified = client(answer);
    const { epochs } = v.token_issue_request_without_device.json;

    await anonymous.api.issueTokens({ epochs });
    await identified.api.issueTokens({ epochs, device_id: parseDeviceId(ID) });

    expect(JSON.parse(anonymous.requests[0]?.body ?? '')).toEqual(
      v.token_issue_request_without_device.json,
    );
    expect(JSON.parse(identified.requests[0]?.body ?? '')).toEqual(
      v.token_issue_request_with_device.json,
    );
  });

  it('types the two refusal bodies on an issuance', async () => {
    for (const [key, code] of [
      ['refusal_device_revoked', 'device_revoked'],
      ['refusal_device_unregistered', 'device_unregistered'],
    ] as const) {
      const { api } = client({ status: v[key]._status, body: JSON.stringify(v[key].json) });

      const err = await api.issueTokens({ epochs: [] }).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(WarrenApiError);
      expect((err as WarrenApiError).code).toBe(code);
      expect((err as WarrenApiError).status).toBe(403);
    }
  });
});

describe('device_registry_v1: reading answers', () => {
  it('reads a listed device of an unknown platform as other', () => {
    const json = { ...v.device_view.json, platform: v.unknown_platform.json };

    expect(readDeviceView(json).platform).toBe('other');
  });

  it('refuses a list whose devices are not an array', () => {
    expect(() => readDeviceList({ devices: v.device_view.json })).toThrow(WarrenApiError);
  });

  it('refuses a device whose id is not a device id', () => {
    const json = { ...v.device_view.json, device_id: v.invalid_device_ids[0].b64url };

    expect(() => readDeviceView(json)).toThrow(WarrenApiError);
  });
});

// Keeps the branded type honest: a plain string is not a DeviceId.
const _typed: DeviceId = parseDeviceId(ID);
void _typed;
