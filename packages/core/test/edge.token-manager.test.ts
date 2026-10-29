import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { base64urlnopad } from '@scure/base';
import { describe, expect, it } from 'vitest';
import {
  BLINDING_PURPOSE_BROWSER_PROXY,
  BLINDING_PURPOSE_SESSION,
  InMemoryTokenPersistence,
  type TokenIssueRequest,
  type TokenIssueResponse,
  type TokenIssuerDirectory,
  TokenManager,
  type TokenPersistence,
  type TokenTransport,
  WarrenApiError,
  WarrenEdgeError,
  blindingKeyFromSeed,
} from '../src/index.js';
import {
  EPOCH,
  EPOCH_SECS,
  KEY_ID,
  NOW,
  SESSION_KEY,
  SPKI_HEX,
  fakeTransport,
} from './fixtures/fake-issuer.js';

/** A transport that fails on any call: proves a path needs no network. */
const offlineTransport: TokenTransport = {
  async getDirectory() {
    throw new Error('offline: getDirectory must not be called');
  },
  async issue() {
    throw new Error('offline: issue must not be called');
  },
};

describe('TokenManager mint timing (decorrelated from redemption)', () => {
  it('mints every published epoch ahead of need; takeCurrentStack pops without minting', async () => {
    const counts = new Map<number, number>();
    const mgr = new TokenManager(
      fakeTransport({ epochs: [EPOCH, EPOCH + 1], counts }),
      new InMemoryTokenPersistence(),
      SESSION_KEY,
    );

    await mgr.refresh(NOW);
    // Both the current and the prefetched next epoch were minted up front.
    expect(mgr.available(EPOCH)).toBe(2);
    expect(mgr.available(EPOCH + 1)).toBe(2);
    expect(counts.get(EPOCH)).toBe(1);
    expect(counts.get(EPOCH + 1)).toBe(1);

    const issueCallsBeforeTake = counts.get(EPOCH);
    const stack = mgr.takeCurrentStack(NOW);
    expect(stack).toHaveLength(1);
    expect(stack[0]!.length).toBe(354);
    expect(mgr.available(EPOCH)).toBe(1);
    // The redemption issued NO new mint: issuance is decorrelated from the dial.
    expect(counts.get(EPOCH)).toBe(issueCallsBeforeTake);
  });

  it('returns an empty stack (never mints) when the epoch is exhausted', async () => {
    const counts = new Map<number, number>();
    const mgr = new TokenManager(
      fakeTransport({ epochs: [EPOCH], quota: 1, counts }),
      new InMemoryTokenPersistence(),
      SESSION_KEY,
    );
    await mgr.refresh(NOW);
    expect(mgr.takeCurrentStack(NOW)).toHaveLength(1);
    // Exhausted: an empty stack, and still no mint at connect.
    expect(mgr.takeCurrentStack(NOW)).toEqual([]);
    expect(counts.get(EPOCH)).toBe(1);
  });

  it('takeCurrentStack yields nothing before the first refresh', () => {
    const mgr = new TokenManager(offlineTransport);
    expect(mgr.takeCurrentStack(NOW)).toEqual([]);
  });

  it('reports the epoch a moment falls in, so a caller can cache what it spent', async () => {
    const mgr = new TokenManager(
      fakeTransport({ epochs: [EPOCH], counts: new Map() }),
      new InMemoryTokenPersistence(),
      SESSION_KEY,
    );
    expect(mgr.epochAt(NOW)).toBeUndefined();
    await mgr.refresh(NOW);
    expect(mgr.epochAt(NOW)).toBe(EPOCH);
    expect(mgr.epochAt(NOW + EPOCH_SECS)).toBe(EPOCH + 1);
  });
});

describe('TokenManager settle ledger (matches the corrected core policy)', () => {
  it('settles an epoch on a definitive already_issued reject and stops asking', async () => {
    const counts = new Map<number, number>();
    const mgr = new TokenManager(
      fakeTransport({
        epochs: [EPOCH, EPOCH + 1],
        counts,
        behavior: (epoch) => (epoch === EPOCH + 1 ? 'already_issued' : 'sign'),
      }),
      new InMemoryTokenPersistence(),
      SESSION_KEY,
    );

    await mgr.refresh(NOW);
    expect(mgr.available(EPOCH)).toBe(2);
    expect(mgr.available(EPOCH + 1)).toBe(0);

    await mgr.refresh(NOW);
    // Both epochs are settled: the minted one and the already_issued one are
    // never re-asked, so each issue counter stays at exactly one.
    expect(counts.get(EPOCH)).toBe(1);
    expect(counts.get(EPOCH + 1)).toBe(1);
  });

  it('leaves an epoch retryable after a transient transport failure', async () => {
    const counts = new Map<number, number>();
    const mgr = new TokenManager(
      fakeTransport({
        epochs: [EPOCH],
        counts,
        behavior: (_epoch, call) => (call === 1 ? 'throw' : 'sign'),
      }),
      new InMemoryTokenPersistence(),
      SESSION_KEY,
    );

    await mgr.refresh(NOW);
    // The blip stored nothing and did NOT settle the epoch.
    expect(mgr.available(EPOCH)).toBe(0);
    expect(counts.get(EPOCH)).toBe(1);

    await mgr.refresh(NOW);
    // The next tick retried and minted, rather than downgrading the epoch.
    expect(counts.get(EPOCH)).toBe(2);
    expect(mgr.available(EPOCH)).toBe(2);
  });

  // Forum topic 219: a clock outside the server window was refused 401 on
  // every issue call, and the refusal read as one epoch's transient failure.
  // A refused signature answers every epoch alike: the pass ends and says so.
  it.each([
    ['clock_skew', 'clock_skew'],
    ['unauthorized', 'server'],
  ] as const)('ends the pass on a %s refusal and surfaces it', async (action, code) => {
    const counts = new Map<number, number>();
    const mgr = new TokenManager(
      fakeTransport({ epochs: [EPOCH, EPOCH + 1], counts, behavior: () => action }),
      new InMemoryTokenPersistence(),
      SESSION_KEY,
    );

    const refused = mgr.refresh(NOW);

    await expect(refused).rejects.toBeInstanceOf(WarrenApiError);
    await expect(refused).rejects.toMatchObject({ code, status: 401 });
    expect(counts.get(EPOCH)).toBe(1);
    expect(counts.get(EPOCH + 1)).toBeUndefined();
  });

  it('leaves an epoch retryable after a non-definitive reject (not_subscribed)', async () => {
    const counts = new Map<number, number>();
    const mgr = new TokenManager(
      fakeTransport({
        epochs: [EPOCH],
        counts,
        behavior: (_epoch, call) => (call === 1 ? 'not_subscribed' : 'sign'),
      }),
      new InMemoryTokenPersistence(),
      SESSION_KEY,
    );

    await mgr.refresh(NOW);
    expect(mgr.available(EPOCH)).toBe(0);

    await mgr.refresh(NOW);
    // not_subscribed can heal, so it must NOT settle the epoch.
    expect(counts.get(EPOCH)).toBe(2);
    expect(mgr.available(EPOCH)).toBe(2);
  });
});

describe('TokenManager persistence', () => {
  it('round-trips the store and survives a restart with no network', async () => {
    const counts = new Map<number, number>();
    const persistence = new InMemoryTokenPersistence();
    const mgr = new TokenManager(
      fakeTransport({ epochs: [EPOCH], counts }),
      persistence,
      SESSION_KEY,
    );
    await mgr.refresh(NOW);
    expect(mgr.available(EPOCH)).toBe(2);

    // Restart: a fresh manager over the SAME persisted bundle, with a transport
    // that throws if touched, proves tokens survive and are spent offline.
    const restarted = new TokenManager(offlineTransport, persistence);
    expect(restarted.available(EPOCH)).toBe(2);
    const stack = restarted.takeCurrentStack(NOW);
    expect(stack).toHaveLength(1);
    expect(stack[0]!.length).toBe(354);
    expect(restarted.available(EPOCH)).toBe(1);

    // The consuming pop is itself persisted, so a second restart sees one left.
    const again = new TokenManager(offlineTransport, persistence);
    expect(again.available(EPOCH)).toBe(1);
  });

  it('prunes spent epochs on refresh', async () => {
    const counts = new Map<number, number>();
    const mgr = new TokenManager(
      fakeTransport({ epochs: [EPOCH], counts }),
      new InMemoryTokenPersistence(),
      SESSION_KEY,
    );
    await mgr.refresh(NOW);
    expect(mgr.available(EPOCH)).toBe(2);

    // Advance a whole epoch: the previous epoch is spent time and is dropped.
    await mgr.refresh((EPOCH + 1) * EPOCH_SECS + 10);
    expect(mgr.available(EPOCH)).toBe(0);
    expect(mgr.epochs()).toEqual([]);
  });

  it('fails closed to an empty store on a corrupt persisted bundle', () => {
    const persistence: TokenPersistence = { load: () => 'not-json', save: () => {} };
    const mgr = new TokenManager(offlineTransport, persistence);
    expect(mgr.epochs()).toEqual([]);
    expect(mgr.takeCurrentStack(NOW)).toEqual([]);
  });
});

describe('recovering a lost store inside the epoch', () => {
  const KEY = blindingKeyFromSeed(new Uint8Array(32).fill(3), BLINDING_PURPOSE_BROWSER_PROXY);

  it('refuses to mint without a wallet blinding key, before any network call', async () => {
    // A batch drawn from the CSPRNG reserves the account's epoch at the issuer
    // and locks every other client of the wallet out of it for the epoch, so a
    // manager with no key must never send one.
    const counts = new Map<number, number>();
    const mgr = new TokenManager(fakeTransport({ epochs: [EPOCH], counts }));

    const err = await mgr.refresh(NOW).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(WarrenEdgeError);
    expect((err as WarrenEdgeError).code).toBe('no_blinding_key');
    expect(counts.size).toBe(0);
    expect(mgr.available(EPOCH)).toBe(0);
  });

  it('re-derives the very same credentials from the wallet, so a reinstall costs nothing', async () => {
    const cfg = { epochs: [EPOCH], counts: new Map<number, number>(), ledger: new Map() };
    const first = new TokenManager(fakeTransport(cfg), new InMemoryTokenPersistence(), KEY);
    await first.refresh(NOW);
    expect(first.available(EPOCH)).toBe(2);

    // A fresh install: same wallet, empty store, same hour.
    const reinstalled = new TokenManager(fakeTransport(cfg), new InMemoryTokenPersistence(), KEY);
    await reinstalled.refresh(NOW);
    expect(reinstalled.available(EPOCH)).toBe(2);
    expect(bytesToHex(reinstalled.takeCurrentStack(NOW)[0]!)).toBe(
      bytesToHex(first.takeCurrentStack(NOW)[0]!),
      'the recovered credential must be the one that already exists, not a new one',
    );
  });

  it('serves every session client of one wallet the same batch in the same epoch', async () => {
    // The desktop app and the Rust SDK mint this class from the same wallet
    // with the same label: whichever refreshes first, the other is re-served.
    const cfg = { epochs: [EPOCH], counts: new Map<number, number>(), ledger: new Map() };
    const seed = new Uint8Array(32).fill(9);
    const desktop = new TokenManager(
      fakeTransport(cfg),
      new InMemoryTokenPersistence(),
      blindingKeyFromSeed(seed, BLINDING_PURPOSE_SESSION),
    );
    const browser = new TokenManager(
      fakeTransport(cfg),
      new InMemoryTokenPersistence(),
      blindingKeyFromSeed(new Uint8Array(seed), BLINDING_PURPOSE_SESSION),
    );

    await desktop.refresh(NOW);
    await browser.refresh(NOW);

    expect(browser.available(EPOCH)).toBe(2);
    expect(browser.sessionStack(NOW).map(bytesToHex).sort()).toEqual(
      desktop.sessionStack(NOW).map(bytesToHex).sort(),
    );
  });

  it('is refused when another wallet holds the epoch, so the cap is not a door', async () => {
    const cfg = { epochs: [EPOCH], counts: new Map<number, number>(), ledger: new Map() };
    await new TokenManager(fakeTransport(cfg), new InMemoryTokenPersistence(), KEY).refresh(NOW);

    const other = blindingKeyFromSeed(new Uint8Array(32).fill(4), BLINDING_PURPOSE_BROWSER_PROXY);
    const intruder = new TokenManager(fakeTransport(cfg), new InMemoryTokenPersistence(), other);
    await intruder.refresh(NOW);
    expect(intruder.available(EPOCH)).toBe(0);
  });
});

describe('TokenManager session stack', () => {
  // Every client of a wallet holds the same batch in the same order, and an
  // exit leases a serial to one live session in the whole fleet, so a session
  // is handed the whole current epoch to walk rather than one popped token.

  /** A well-formed token whose nonce starts with `marker`, so each marker has
   * its own serial. */
  function token(marker: number): Uint8Array {
    const bytes = new Uint8Array(354);
    bytes[1] = 0x02;
    bytes[2] = marker;
    return bytes;
  }

  function stocked(
    byEpoch: Record<number, number[]>,
    options?: { rotation?: number },
  ): { mgr: TokenManager; persistence: InMemoryTokenPersistence } {
    const persistence = new InMemoryTokenPersistence();
    const epochs: Record<string, string[]> = {};
    for (const [epoch, markers] of Object.entries(byEpoch)) {
      epochs[epoch] = markers.map((m) => base64urlnopad.encode(token(m)));
    }
    persistence.save(JSON.stringify({ v: 1, epochSecs: EPOCH_SECS, epochs }));
    return {
      mgr: new TokenManager(offlineTransport, persistence, SESSION_KEY, options),
      persistence,
    };
  }

  const markers = (stack: Uint8Array[]) => stack.map((t) => t[2]);

  it('carries every current token and consumes none', () => {
    const { mgr, persistence } = stocked({ [EPOCH]: [1, 2, 3] }, { rotation: 0 });
    const before = persistence.load();

    expect(markers(mgr.sessionStack(NOW))).toEqual([1, 2, 3]);
    expect(markers(mgr.sessionStack(NOW))).toEqual([1, 2, 3]);
    expect(mgr.available(EPOCH)).toBe(3);
    expect(persistence.load()).toBe(before);
  });

  it('starts at the manager rotation', () => {
    const { mgr } = stocked({ [EPOCH]: [1, 2, 3] }, { rotation: 4 });

    expect(markers(mgr.sessionStack(NOW))).toEqual([2, 3, 1]);
  });

  it('does not send every manager of one wallet to the same lead token', () => {
    const leads = new Set<number | undefined>();
    for (let i = 0; i < 64; i++) {
      leads.add(stocked({ [EPOCH]: [1, 2, 3] }).mgr.sessionStack(NOW)[0]?.[2]);
    }

    expect(leads.size).toBeGreaterThan(1);
  });

  it('holds only the epoch the moment falls in', () => {
    const { mgr } = stocked({ [EPOCH]: [1, 2], [EPOCH + 1]: [7, 8] }, { rotation: 0 });

    expect(markers(mgr.sessionStack(NOW + EPOCH_SECS))).toEqual([7, 8]);
  });

  it('is empty before the manager knows the epoch length', () => {
    const mgr = new TokenManager(offlineTransport, new InMemoryTokenPersistence(), SESSION_KEY);

    expect(mgr.sessionStack(NOW)).toEqual([]);
  });

  it('leaves out a serial a live session holds until it is released', () => {
    const { mgr } = stocked({ [EPOCH]: [1, 2, 3] }, { rotation: 0 });
    const lease = mgr.claim(token(2));
    expect(lease).toBeDefined();

    expect(markers(mgr.sessionStack(NOW))).toEqual([1, 3]);
    lease?.release();
    expect(markers(mgr.sessionStack(NOW))).toEqual([1, 2, 3]);
  });

  it('claims a held serial again only once it is released, and a second release is inert', () => {
    const { mgr } = stocked({ [EPOCH]: [1] });
    const first = mgr.claim(token(1));

    expect(first).toBeDefined();
    expect(mgr.claim(token(1))).toBeUndefined();
    first?.release();
    const second = mgr.claim(token(1));
    expect(second).toBeDefined();
    first?.release();
    expect(mgr.claim(token(1))).toBeUndefined();
  });

  it('never claims bytes that are no token', () => {
    const { mgr } = stocked({ [EPOCH]: [1] });

    expect(mgr.claim(new Uint8Array(354))).toBeUndefined();
    expect(mgr.claim(token(1).subarray(0, 353))).toBeUndefined();
  });
});
