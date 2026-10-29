import { describe, expect, it } from 'vitest';
import {
  type DeviceId,
  type DeviceRegistration,
  type DeviceView,
  InMemoryTokenPersistence,
  type TokenIssueRequest,
  TokenManager,
  type TokenTransport,
  WarrenApiError,
  WarrenDeviceError,
  parseDeviceId,
} from '../src/index.js';
import { EPOCH, NOW, SESSION_KEY, fakeTransport } from './fixtures/fake-issuer.js';

const ID = parseDeviceId('AAECAwQFBgcICQoLDA0ODw');
const DEVICE: DeviceRegistration = {
  device_id: ID,
  name: 'calm heron',
  platform: 'browser',
  app_version: '0.1.8',
};

/** A fake registry in front of the fake issuer, recording what it was asked. */
class Registry {
  readonly known = new Set<DeviceId>();
  readonly revoked = new Set<DeviceId>();
  readonly registrations: DeviceRegistration[] = [];
  readonly issued: TokenIssueRequest[] = [];
  /** The account is at its device cap: a new device is refused. */
  full = false;
  /** A server that predates the registry: registration answers 404. */
  absent = false;
  /** The name the registry holds, when renamed from another device. */
  heldName: string | undefined;
  /** Issuance forgets the device this many times (a lost race). */
  forgetful = 0;
  /** Registrations past this many fail on the network. */
  reachableRegistrations = Number.POSITIVE_INFINITY;

  transport(epochs: number[] = [EPOCH]): TokenTransport {
    const base = fakeTransport({ epochs, counts: new Map() });
    return {
      getDirectory: () => base.getDirectory(),
      issue: async (request) => {
        this.issued.push(request);
        const id = request.device_id;
        if (id !== undefined && this.revoked.has(id)) throw refusal('device_revoked', 403);
        if (id !== undefined && (!this.known.has(id) || this.forgetful > 0)) {
          this.forgetful = Math.max(0, this.forgetful - 1);
          throw refusal('device_unregistered', 403);
        }
        return base.issue(request);
      },
      registerDevice: async (registration) => this.register(registration),
    };
  }

  private async register(registration: DeviceRegistration): Promise<DeviceView> {
    this.registrations.push({ ...registration });
    if (this.registrations.length > this.reachableRegistrations) {
      throw new TypeError('fetch failed');
    }
    const id = registration.device_id;
    if (this.absent) throw new WarrenApiError('server', 'status 404', { status: 404 });
    if (this.revoked.has(id)) throw refusal('device_revoked', 403);
    if (this.full && !this.known.has(id)) throw refusal('device_limit_reached', 409);
    this.known.add(id);
    return {
      ...registration,
      name: this.heldName ?? registration.name,
      registered_on: '2026-10-28',
      last_seen_on: '2026-10-29',
      this_device: false,
    };
  }
}

function refusal(
  code: 'device_revoked' | 'device_unregistered' | 'device_limit_reached',
  status: number,
) {
  return new WarrenApiError(code, code, { status });
}

async function rejection(promise: Promise<unknown>): Promise<WarrenApiError> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(WarrenApiError);
  return err as WarrenApiError;
}

function manager(
  transport: TokenTransport,
  opts: { persistence?: InMemoryTokenPersistence; onDeviceName?: (name: string) => void } = {},
): TokenManager {
  return new TokenManager(
    transport,
    opts.persistence ?? new InMemoryTokenPersistence(),
    SESSION_KEY,
    {
      device: DEVICE,
      ...(opts.onDeviceName ? { onDeviceName: opts.onDeviceName } : {}),
    },
  );
}

describe('TokenManager as a registered device', () => {
  it('registers before it mints, and names the device on every issue request', async () => {
    const registry = new Registry();
    const mgr = manager(registry.transport([EPOCH, EPOCH + 1]));

    await mgr.refresh(NOW);

    expect(registry.registrations).toEqual([DEVICE]);
    expect(registry.issued).toHaveLength(2);
    expect(registry.issued.every((r) => r.device_id === ID)).toBe(true);
    expect(mgr.available(EPOCH)).toBe(2);
  });

  it('takes the name the registry answers, and registers under it from then on', async () => {
    const registry = new Registry();
    registry.heldName = 'kitchen laptop';
    const names: string[] = [];
    const mgr = manager(registry.transport(), { onDeviceName: (name) => names.push(name) });

    await mgr.refresh(NOW);
    await mgr.refresh(NOW);

    expect(mgr.deviceName()).toBe('kitchen laptop');
    expect(names).toEqual(['kitchen laptop']);
    expect(registry.registrations[1]?.name).toBe('kitchen laptop');
  });

  it('registers under a rename made here from the next refresh on', async () => {
    const registry = new Registry();
    const mgr = manager(registry.transport());

    mgr.setDeviceName('desk');
    await mgr.refresh(NOW);

    expect(registry.registrations[0]?.name).toBe('desk');
  });

  it('registers again and asks once more when the issuer does not know it yet', async () => {
    const registry = new Registry();
    registry.forgetful = 1;
    const mgr = manager(registry.transport());

    await mgr.refresh(NOW);

    expect(registry.registrations).toHaveLength(2);
    expect(registry.issued).toHaveLength(2);
    expect(mgr.available(EPOCH)).toBe(2);
  });

  it('stops once an issuer still does not know it after one more registration', async () => {
    const registry = new Registry();
    registry.forgetful = 5;
    const mgr = manager(registry.transport([EPOCH, EPOCH + 1]));

    const err = await rejection(mgr.refresh(NOW));

    expect(err.code).toBe('device_unregistered');
    expect(registry.registrations).toHaveLength(2);
    expect(registry.issued).toHaveLength(2);
    expect(mgr.deviceRevoked).toBe(false);
  });

  it('registers again at most once per pass, even when that registration is lost', async () => {
    const registry = new Registry();
    registry.forgetful = 5;
    registry.reachableRegistrations = 1;
    const mgr = manager(registry.transport([EPOCH, EPOCH + 1]));

    const err = await rejection(mgr.refresh(NOW));

    expect(err.code).toBe('device_unregistered');
    expect(registry.registrations).toHaveLength(2);
  });

  it('drops its stock and stops for good once the registry reads it revoked', async () => {
    const registry = new Registry();
    const persistence = new InMemoryTokenPersistence();
    const mgr = manager(registry.transport(), { persistence });
    await mgr.refresh(NOW);
    expect(mgr.available(EPOCH)).toBe(2);

    registry.revoked.add(ID);
    const err = await rejection(mgr.refresh(NOW));

    expect(err.code).toBe('device_revoked');
    expect(mgr.deviceRevoked).toBe(true);
    expect(mgr.available(EPOCH)).toBe(0);
    expect(mgr.sessionStack(NOW)).toEqual([]);
    expect(JSON.parse(persistence.load() ?? '{}').epochs).toEqual({});

    const asked = registry.registrations.length + registry.issued.length;
    expect((await rejection(mgr.refresh(NOW))).code).toBe('device_revoked');
    expect(registry.registrations.length + registry.issued.length).toBe(asked);
  });

  it('drops its stock when an issuance reads it revoked', async () => {
    const registry = new Registry();
    const transport = registry.transport([EPOCH, EPOCH + 1]);
    const issue = transport.issue;
    // Revoked between the registration that opened the pass and its second epoch.
    transport.issue = async (request) => {
      if (registry.issued.length === 1) registry.revoked.add(ID);
      return issue(request);
    };
    const mgr = manager(transport);

    const err = await rejection(mgr.refresh(NOW));

    expect(err.code).toBe('device_revoked');
    expect(mgr.deviceRevoked).toBe(true);
    expect(mgr.epochs()).toEqual([]);
  });

  it('is issued nothing past the account device cap, and registers again next time', async () => {
    const registry = new Registry();
    registry.full = true;
    const mgr = manager(registry.transport());

    const err = await rejection(mgr.refresh(NOW));

    expect(err.code).toBe('device_limit_reached');
    expect(registry.issued).toEqual([]);
    expect(mgr.deviceRevoked).toBe(false);

    registry.full = false;
    await mgr.refresh(NOW);
    expect(mgr.available(EPOCH)).toBe(2);
  });

  it('still issues from a server without the registry', async () => {
    const registry = new Registry();
    registry.absent = true;
    registry.known.add(ID);
    const mgr = manager(registry.transport());

    await mgr.refresh(NOW);

    expect(mgr.available(EPOCH)).toBe(2);
    expect(registry.issued[0]?.device_id).toBe(ID);
  });

  it('sends the original body and registers nothing without a device', async () => {
    const registry = new Registry();
    const mgr = new TokenManager(registry.transport(), new InMemoryTokenPersistence(), SESSION_KEY);

    await mgr.refresh(NOW);

    expect(registry.registrations).toEqual([]);
    expect('device_id' in (registry.issued[0] ?? {})).toBe(false);
    expect(mgr.deviceName()).toBeUndefined();
  });

  it('refuses a device on a transport that cannot register one', () => {
    const transport = new Registry().transport();
    transport.registerDevice = undefined;

    expect(() => manager(transport)).toThrow(WarrenDeviceError);
  });
});
