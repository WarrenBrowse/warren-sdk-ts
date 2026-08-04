/**
 * Transport seam for the Warren API client.
 *
 * The client is transport-agnostic so it stays portable (browser `fetch`, Node
 * `fetch`, a native FFI transport, or a fake in tests). This mirrors the Rust
 * `warren-api` split of a transport-agnostic core plus a concrete backend.
 */

/** An outgoing HTTP request, fully built by the client. */
export interface HttpRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  /** UTF-8 request body. Empty string for body-less requests. */
  readonly body: string;
  /**
   * Whether to send the TLS SNI extension. The anti-censorship fallback retries
   * the primary host with `useSni: false`. Browser `fetch` cannot control SNI
   * and ignores this; a native transport can honor it.
   */
  readonly useSni: boolean;
}

/** A received HTTP response. */
export interface HttpResponse {
  readonly status: number;
  /** UTF-8 response body. Empty string when there is no body. */
  readonly body: string;
}

/**
 * A transport-level failure, mirroring the Rust `TransportError` split.
 *
 * `connect: true` marks a connect-establishment failure (DNS, TCP, TLS), the
 * only case the anti-censorship fallback retries on another host or without
 * SNI. Any other transport failure (I/O after connect, protocol error)
 * propagates immediately as a `WarrenApiError` with code `'transport'`.
 *
 * No-log discipline: never put a hostname, IP or URL in the message.
 */
export class WarrenTransportError extends Error {
  readonly connect: boolean;

  constructor(message: string, options: { connect: boolean; cause?: unknown }) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'WarrenTransportError';
    this.connect = options.connect;
  }
}

/**
 * Sends a request and resolves with the response.
 *
 * Any received HTTP status, including 4xx/5xx, MUST resolve: the client never
 * advances the host fallback on a connected response. A rejection with
 * `WarrenTransportError { connect: true }` (or any non-`WarrenTransportError`
 * rejection, the conservative default for backends like `fetch` that cannot
 * tell connect from post-connect failures) advances the fallback; a
 * `WarrenTransportError { connect: false }` stops it immediately.
 */
export interface HttpTransport {
  send(req: HttpRequest): Promise<HttpResponse>;
}

/**
 * Default {@link HttpTransport} backed by the global `fetch`. Isomorphic on
 * Node >= 20 and evergreen browsers. Ignores `useSni`.
 */
export function fetchTransport(fetchImpl: typeof fetch = fetch): HttpTransport {
  return {
    async send(req: HttpRequest): Promise<HttpResponse> {
      const init: RequestInit = { method: req.method, headers: { ...req.headers } };
      // A body on GET/DELETE is rejected by fetch; only attach when present.
      if (req.body.length > 0) init.body = req.body;
      const res = await fetchImpl(req.url, init);
      return { status: res.status, body: await res.text() };
    },
  };
}
