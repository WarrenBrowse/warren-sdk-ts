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
  | 'bad_clock';

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

  constructor(
    code: WarrenApiErrorCode,
    message: string,
    options?: { status?: number; body?: string; cause?: unknown },
  ) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'WarrenApiError';
    this.code = code;
    if (options?.status !== undefined) this.status = options.status;
    if (options?.body !== undefined) this.body = options.body;
  }
}
