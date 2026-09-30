/**
 * The server's clock, as the API's answers tell it, for stamping signed
 * requests. Mirrors warren-sdk-rs `warren_api::clock`, bound for bound, so
 * every client of a wallet corrects its stamp the same way.
 *
 * A server refuses a signature whose timestamp is further than
 * {@link SIGNATURE_WINDOW_SECS} from its own clock, so a device whose clock
 * drifted past that is refused on every signed call and nothing it can see
 * says why (forum topic 219: a clock 91 s fast lost its port forwarding and
 * its session tokens). Every answer carries a `Date` header, read over the same
 * TLS session as the answer, so the client learns the server's clock for free.
 *
 * No-log policy: only the offset (a duration) is worth logging, never the
 * request or the key.
 */

/**
 * How far, in seconds and either side of its own clock, a server accepts a
 * signed request's `X-Warren-Timestamp` (`warren_contract::auth::SIGNATURE_WINDOW_SECS`).
 */
export const SIGNATURE_WINDOW_SECS = 60;

/**
 * How far the stamp may be moved FORWARD, in seconds, at an answer's word.
 *
 * A stamp moved into the past is spent: a signature carrying an instant that
 * has gone by is replayable only at an instant that has gone by. A stamp moved
 * into the future is not: an answer claiming a `Date` months ahead would mint
 * signatures a hostile server could hold and present when they become current.
 * So a backward correction is unbounded and a forward one stops at a quarter of
 * an hour, past which the device clock is the more credible of the two.
 */
export const MAX_FORWARD_CORRECTION_SECS = 15 * 60;

/**
 * The server's clock minus the device's, in seconds, read off an answer's
 * `Date` header received at `deviceNow` (Unix seconds): positive when the
 * device is behind. `undefined` when the header does not parse.
 */
export function clockOffsetSecs(dateHeader: string, deviceNow: number): number | undefined {
  const serverMs = Date.parse(dateHeader.trim());
  if (!Number.isFinite(serverMs)) return undefined;
  return Math.floor(serverMs / 1000) - deviceNow;
}

/**
 * The part of a measured offset a stamp is actually moved by: zero for a device
 * already within half the window (the round trip and the header's one-second
 * resolution cannot push it out), and zero for a `Date` further ahead than
 * {@link MAX_FORWARD_CORRECTION_SECS}.
 */
export function applicableOffset(offsetSecs: number): number {
  if (Math.abs(offsetSecs) * 2 <= SIGNATURE_WINDOW_SECS) return 0;
  if (offsetSecs > MAX_FORWARD_CORRECTION_SECS) return 0;
  return offsetSecs;
}

/**
 * The timestamp to sign at: `deviceNow` shifted by the applicable part of
 * `offsetSecs`. A shift below the epoch keeps the device stamp.
 */
export function correctedTimestamp(deviceNow: number, offsetSecs: number): number {
  const corrected = deviceNow + applicableOffset(offsetSecs);
  return Number.isSafeInteger(corrected) && corrected >= 0 ? corrected : deviceNow;
}

/**
 * The offset learned from the API's answers, shared by every request a client
 * signs (pass one instance to several clients of the same wallet to share what
 * any of them read). Zero until an answer has been read: requests are then
 * stamped with the device clock.
 */
export class ServerClock {
  private offset = 0;

  /**
   * Records the offset an answer's `Date` header shows, received at
   * `deviceNow`, and returns it. An unparseable header records nothing.
   */
  observeDate(dateHeader: string, deviceNow: number): number | undefined {
    const offset = clockOffsetSecs(dateHeader, deviceNow);
    if (offset !== undefined) this.offset = offset;
    return offset;
  }

  /** The last measured offset (server minus device, seconds), applied or not. */
  get offsetSecs(): number {
    return this.offset;
  }

  /** The part of {@link offsetSecs} a stamp is moved by now. */
  get appliedOffsetSecs(): number {
    return applicableOffset(this.offset);
  }

  /** The timestamp to sign at when the device clock reads `deviceNow`. */
  stamp(deviceNow: number): number {
    return correctedTimestamp(deviceNow, this.offset);
  }
}
