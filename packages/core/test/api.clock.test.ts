import { describe, expect, it } from 'vitest';
import {
  MAX_FORWARD_CORRECTION_SECS,
  ServerClock,
  applicableOffset,
  clockOffsetSecs,
  correctedTimestamp,
} from '../src/index.js';

/** 2023-11-14 22:13:20 UTC. */
const SERVER_NOW = 1_700_000_000;
const SERVER_DATE = 'Tue, 14 Nov 2023 22:13:20 GMT';

// Mirrors warren-sdk-rs `warren_api::clock`: the same bounds, so every client
// of a wallet corrects its stamp the same way.
describe('server clock', () => {
  it('a device behind the server signs at the server clock', () => {
    const offset = clockOffsetSecs(SERVER_DATE, SERVER_NOW - 91);
    expect(offset).toBe(91);
    expect(correctedTimestamp(SERVER_NOW - 91, 91)).toBe(SERVER_NOW);
  });

  it('a device ahead of the server is pulled back', () => {
    // Forum topic 219: a clock 91 s fast, refused on every signed call.
    const offset = clockOffsetSecs(SERVER_DATE, SERVER_NOW + 91);
    expect(offset).toBe(-91);
    expect(correctedTimestamp(SERVER_NOW + 91, -91)).toBe(SERVER_NOW);
  });

  it('a date that does not parse measures nothing', () => {
    expect(clockOffsetSecs('not a date', SERVER_NOW)).toBeUndefined();
  });

  it('a device inside half the window is left alone', () => {
    expect(applicableOffset(30)).toBe(0);
    expect(applicableOffset(-30)).toBe(0);
    expect(applicableOffset(31)).toBe(31);
    expect(applicableOffset(-31)).toBe(-31);
  });

  it('an answer from further ahead than the bound does not move the stamp', () => {
    expect(applicableOffset(MAX_FORWARD_CORRECTION_SECS)).toBe(MAX_FORWARD_CORRECTION_SECS);
    expect(applicableOffset(MAX_FORWARD_CORRECTION_SECS + 1)).toBe(0);
  });

  it('a device running ahead is pulled back however far', () => {
    const aYear = 365 * 24 * 60 * 60;
    expect(correctedTimestamp(SERVER_NOW + aYear, -aYear)).toBe(SERVER_NOW);
  });

  it('a correction below the epoch keeps the device stamp', () => {
    expect(correctedTimestamp(10, -3_600)).toBe(10);
  });

  it('stamps with what the last readable answer said', () => {
    const clock = new ServerClock();
    expect(clock.stamp(SERVER_NOW + 91)).toBe(SERVER_NOW + 91);

    expect(clock.observeDate(SERVER_DATE, SERVER_NOW + 91)).toBe(-91);
    expect(clock.offsetSecs).toBe(-91);
    expect(clock.appliedOffsetSecs).toBe(-91);
    expect(clock.stamp(SERVER_NOW + 91)).toBe(SERVER_NOW);

    expect(clock.observeDate('garbage', SERVER_NOW)).toBeUndefined();
    expect(clock.offsetSecs).toBe(-91);

    clock.observeDate(SERVER_DATE, SERVER_NOW + 2);
    expect(clock.appliedOffsetSecs).toBe(0);
    expect(clock.stamp(SERVER_NOW + 2)).toBe(SERVER_NOW + 2);
  });
});
