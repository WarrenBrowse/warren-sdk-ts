/** Discriminator for {@link WarrenApiError}. */
export type WarrenApiErrorCode =
  /** A non-2xx HTTP response from the server. */
  | 'server'
  /** A non-connect transport failure (I/O after connect); never retried. */
  | 'transport'
  /** Every host (primary, alternatives, no-SNI) failed to connect. */
  | 'all_hosts_blocked'
  /** The response body could not be decoded into the expected shape. */
  | 'response'
  /** A signed call was attempted without an identity seed. */
  | 'no_identity'
  /** The system clock is before the Unix epoch. */
  | 'bad_clock'
  /**
   * The server refused a signed request's timestamp (`401`, status kept): this
   * device's clock is further off than the correction may follow, or the
   * answer carried no usable `Date`. The key is not in question; what a user
   * can do is set the clock right. {@link WarrenApiError.offsetSecs} says by
   * how much when the refusal carried a `Date`.
   */
  | 'clock_skew'
  /**
   * The device a registration, an issuance or a device route named was
   * revoked from another device of the account (`403
   * {"error":"device_revoked"}`). The client disconnects and forgets its
   * device identity; coming back takes the recovery phrase.
   */
  | 'device_revoked'
  /**
   * The device an issuance named is not registered (`403
   * {"error":"device_unregistered"}`): register it, then ask again.
   */
  | 'device_unregistered'
  /**
   * The account already holds as many active devices as the registry takes
   * (`409` on `POST /v1/devices`): this install is issued nothing until
   * another device of the account is revoked.
   */
  | 'device_limit_reached';

/**
 * A Warren API error.
 *
 * No-log discipline: the server response body may echo identity material (IP,
 * pubkey), so it is never placed in {@link Error.message}. It is kept on
 * {@link WarrenApiError.body} for programmatic inspection only; do not log it.
 */
export class WarrenApiError extends Error {
  readonly code: WarrenApiErrorCode;
  /** HTTP status, present when `code === 'server'`. */
  readonly status?: number;
  /** Raw response body, present when `code === 'server'`. Never log this. */
  readonly body?: string;
  /**
   * With `code === 'clock_skew'`: the server's clock minus this device's, in
   * seconds (positive when the device is behind), read off the refusal's
   * `Date`; absent when it carried none.
   */
  readonly offsetSecs?: number;

  constructor(
    code: WarrenApiErrorCode,
    message: string,
    options?: { status?: number; body?: string; offsetSecs?: number; cause?: unknown },
  ) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'WarrenApiError';
    this.code = code;
    if (options?.status !== undefined) this.status = options.status;
    if (options?.body !== undefined) this.body = options.body;
    if (options?.offsetSecs !== undefined) this.offsetSecs = options.offsetSecs;
  }
}
