import { describe, expect, it, vi } from 'vitest';
import { TOKEN_BUNDLE_KEY, openTokenStore } from '../src/token-store.js';

/** A `chrome.storage` area stand-in: the boundary this module exists to cross. */
function fakeArea(initial: Record<string, unknown> = {}) {
  const items = { ...initial };
  return {
    items,
    get: vi.fn(async (key: string) => (key in items ? { [key]: items[key] } : {})),
    set: vi.fn(async (next: Record<string, unknown>) => {
      Object.assign(items, next);
    }),
  };
}

describe('openTokenStore', () => {
  it('hydrates load() from the bundle already in storage', async () => {
    const area = fakeArea({ [TOKEN_BUNDLE_KEY]: '{"v":1}' });

    const store = await openTokenStore(area);

    expect(store.persistence.load()).toBe('{"v":1}');
  });

  it('loads undefined when storage holds nothing', async () => {
    const store = await openTokenStore(fakeArea());

    expect(store.persistence.load()).toBeUndefined();
  });

  it('loads undefined when the stored value is not a string', async () => {
    const store = await openTokenStore(fakeArea({ [TOKEN_BUNDLE_KEY]: { corrupt: true } }));

    expect(store.persistence.load()).toBeUndefined();
  });

  it('writes a saved bundle through to storage', async () => {
    const area = fakeArea();
    const store = await openTokenStore(area);

    store.persistence.save('{"v":1,"epochs":{}}');
    await store.flush();

    expect(area.items[TOKEN_BUNDLE_KEY]).toBe('{"v":1,"epochs":{}}');
  });

  it('serves a saved bundle from memory without re-reading storage', async () => {
    const area = fakeArea();
    const store = await openTokenStore(area);
    area.get.mockClear();

    store.persistence.save('{"v":1,"fresh":true}');

    expect(store.persistence.load()).toBe('{"v":1,"fresh":true}');
    expect(area.get).not.toHaveBeenCalled();
  });

  it('keeps the value in memory when the write fails, so the next save retries it', async () => {
    const area = fakeArea();
    area.set.mockRejectedValueOnce(new Error('quota exceeded'));
    const store = await openTokenStore(area);

    store.persistence.save('{"v":1,"first":true}');
    await store.flush();
    expect(store.persistence.load()).toBe('{"v":1,"first":true}');

    // The bundle is always the full state, so the next write self-heals.
    store.persistence.save('{"v":1,"second":true}');
    await store.flush();
    expect(area.items[TOKEN_BUNDLE_KEY]).toBe('{"v":1,"second":true}');
  });

  it('never rejects into the caller when storage is broken', async () => {
    const area = fakeArea();
    area.set.mockRejectedValue(new Error('storage gone'));
    const store = await openTokenStore(area);

    expect(() => store.persistence.save('{"v":1}')).not.toThrow();
    await expect(store.flush()).resolves.toBeUndefined();
  });

  it('starts empty when the initial read throws', async () => {
    const area = fakeArea();
    area.get.mockRejectedValue(new Error('storage gone'));

    const store = await openTokenStore(area);

    expect(store.persistence.load()).toBeUndefined();
  });

  it('applies concurrent saves in order, so the last one wins on disk', async () => {
    const area = fakeArea();
    const store = await openTokenStore(area);

    store.persistence.save('{"v":1,"n":1}');
    store.persistence.save('{"v":1,"n":2}');
    store.persistence.save('{"v":1,"n":3}');
    await store.flush();

    expect(area.items[TOKEN_BUNDLE_KEY]).toBe('{"v":1,"n":3}');
  });
});
