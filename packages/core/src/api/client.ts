import { randomNonceHex } from '../crypto/random.js';
import type {
  TokenIssueRequest,
  TokenIssueResponse,
  TokenIssuerDirectory,
  TokenTransport,
} from '../edge/token-acquire.js';
import { type WarrenKeyPair, keyPairFromSeed, wipeKeyPair } from '../identity/derivation.js';
import { signWithKeyPair, signatureHeaders } from '../identity/signing.js';
import type * as dto from './dto.js';
import { WarrenApiError } from './errors.js';
import {
  type HttpResponse,
  type HttpTransport,
  WarrenTransportError,
  fetchTransport,
} from './transport.js';

/**
 * The product `User-Agent` every Warren client sends on API calls: one shared
 * versionless token (the production app's proven value, mirrored from
 * `warren_contract::product::USER_AGENT`) so the API cannot distinguish client
 * kinds or builds. Browser `fetch` silently drops the header (forbidden header
 * name); setting it is still correct there and takes effect on Node.
 */
export const USER_AGENT = 'warren-app';

/** Options for {@link WarrenApiClient}. */
export interface WarrenApiClientOptions {
  /** API base URL, e.g. `https://api.warrenbrowse.com`. A trailing slash is trimmed. */
  baseUrl: string;
  /** Identity seed (32 bytes) used to sign requests. Required for signed calls. */
  seed?: Uint8Array;
  /** Transport backend. Defaults to the global `fetch`. */
  transport?: HttpTransport;
  /** Anti-censorship fallback hostnames, tried in order after the primary host. */
  alternativeHosts?: string[];
  /** Clock for the signing timestamp, unix epoch seconds. Defaults to wall clock. */
  now?: () => number;
  /** Nonce source, 32 lowercase hex chars. Defaults to a CSPRNG. */
  nonce?: () => string;
}

/** Replaces the hostname of a base URL, preserving scheme, explicit port and path. */
function replaceHost(baseUrl: string, hostname: string): string {
  const u = new URL(baseUrl);
  u.hostname = hostname;
  // origin alone would drop a path-bearing base URL (https://x/gateway), and
  // every fallback attempt would then hit the wrong path.
  return u.origin + (u.pathname === '/' ? '' : u.pathname);
}

/**
 * Signed HTTP client for the Warren `/v1/*` account API.
 *
 * Transport-agnostic and isomorphic. Signed calls attach the four `X-Warren-*`
 * headers derived from the identity seed; unsigned calls do not. Requests are
 * tried against the primary host, then any alternative hosts, then the primary
 * host with SNI disabled, advancing only on connect-level failures.
 */
export class WarrenApiClient {
  private readonly baseUrl: string;
  private readonly transport: HttpTransport;
  private readonly alternativeHosts: readonly string[];
  private keyPair: WarrenKeyPair | undefined;
  private readonly now: () => number;
  private readonly nonce: () => string;

  constructor(options: WarrenApiClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.transport = options.transport ?? fetchTransport();
    this.alternativeHosts = options.alternativeHosts ?? [];
    this.keyPair = options.seed ? keyPairFromSeed(options.seed) : undefined;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.nonce = options.nonce ?? randomNonceHex;
  }

  /**
   * Zeroizes the client's signing key. Signed calls afterwards throw
   * `no_identity`; unsigned calls keep working.
   */
  dispose(): void {
    if (this.keyPair) {
      wipeKeyPair(this.keyPair);
      this.keyPair = undefined;
    }
  }

  /** `GET /v1/exits` (unsigned). Returns the raw server-signed relay list JSON. */
  async exits(): Promise<string> {
    return this.expectOk(await this.request('GET', '/v1/exits', { signed: false })).body;
  }

  /** `POST /v1/register` (unsigned). Redeems a voucher to create or extend an account. */
  async register(req: dto.RegisterAccountRequest): Promise<dto.RegisterAccountResponse> {
    const res = await this.request('POST', '/v1/register', {
      body: JSON.stringify(req),
      signed: false,
    });
    return this.json<dto.RegisterAccountResponse>(this.expectOk(res));
  }

  /** `GET /v1/subscription` (signed). Returns the account expiry. */
  async subscription(): Promise<dto.SubscriptionResponse> {
    return this.json<dto.SubscriptionResponse>(
      this.expectOk(await this.request('GET', '/v1/subscription', { signed: true })),
    );
  }

  /** `GET /v1/check` (signed). Backend-authoritative egress check. */
  async check(): Promise<dto.CheckResponse> {
    return this.json<dto.CheckResponse>(
      this.expectOk(await this.request('GET', '/v1/check', { signed: true })),
    );
  }

  /** `DELETE /v1/account` (signed). Irreversibly deletes the account. */
  async deleteAccount(): Promise<void> {
    this.expectOk(await this.request('DELETE', '/v1/account', { signed: true }));
  }

  /** `POST /v1/incidents/exit-down` (signed). Failover telemetry. */
  async reportExitDown(req: dto.IncidentExitDownRequest): Promise<void> {
    this.expectOk(
      await this.request('POST', '/v1/incidents/exit-down', {
        body: JSON.stringify(req),
        signed: true,
      }),
    );
  }

  /** `GET /v1/checkout/{id}/voucher` (unsigned). Polls a pending checkout; `null` until ready. */
  async pullPendingVoucher(pendingId: string): Promise<string | null> {
    const res = await this.request('GET', `/v1/checkout/${encodeURIComponent(pendingId)}/voucher`, {
      signed: false,
    });
    if (res.status === 404) return null;
    return this.json<{ voucher_secret: string }>(this.expectOk(res)).voucher_secret;
  }

  /** `POST /v1/session/open` (signed). Device-lease admission. */
  async sessionOpen(req: dto.SessionOpenRequest): Promise<dto.SessionOpenResponse> {
    const res = await this.request('POST', '/v1/session/open', {
      body: JSON.stringify(req),
      signed: true,
    });
    return this.json<dto.SessionOpenResponse>(this.expectOk(res));
  }

  /** `POST /v1/session/close` (signed). Releases a device lease. */
  async sessionClose(req: dto.SessionCloseRequest): Promise<void> {
    this.expectOk(
      await this.request('POST', '/v1/session/close', { body: JSON.stringify(req), signed: true }),
    );
  }

  /** `POST /v1/payments/apple/init` (signed, empty body). */
  async initApplePayment(): Promise<dto.InitApplePaymentResponse> {
    return this.json<dto.InitApplePaymentResponse>(
      this.expectOk(await this.request('POST', '/v1/payments/apple/init', { signed: true })),
    );
  }

  /** `POST /v1/payments/apple/check` (signed). Credits a StoreKit transaction. */
  async checkApplePayment(req: dto.CheckApplePaymentRequest): Promise<dto.MobilePaymentResponse> {
    return this.json<dto.MobilePaymentResponse>(
      this.expectOk(
        await this.request('POST', '/v1/payments/apple/check', {
          body: JSON.stringify(req),
          signed: true,
        }),
      ),
    );
  }

  /** `POST /v1/incidents/pubkey-mismatch` (signed). Reports an exit key substitution. */
  async reportPubkeyMismatch(req: dto.IncidentPubkeyMismatchRequest): Promise<void> {
    const body = JSON.stringify({
      exit_id_hex: req.exitIdHex,
      old_pubkey_hex: req.oldPubkeyHex,
      new_pubkey_hex: req.newPubkeyHex,
      country_code: req.countryCode ?? '',
      city: req.city ?? '',
      ts_unix: req.tsUnix,
    });
    this.expectOk(
      await this.request('POST', '/v1/incidents/pubkey-mismatch', { body, signed: true }),
    );
  }

  /** `GET /v1/multihop/directory` (unsigned). The signed directory JSON, or null if unpublished. */
  async multihopDirectory(): Promise<string | null> {
    const res = await this.request('GET', '/v1/multihop/directory', { signed: false });
    if (res.status === 404) return null;
    return this.expectOk(res).body;
  }

  /** `GET /v1/tokens/keys` (unsigned). The anonymous session-token issuer
   * directory (per-epoch public keys + policy) an EdgeConnect client uses to
   * mint v7 tokens. */
  async getTokenDirectory(): Promise<TokenIssuerDirectory> {
    return this.json(
      this.expectOk(await this.request('GET', '/v1/tokens/keys', { signed: false })),
    );
  }

  /** `POST /v1/tokens/issue` (signed). Blind-signs the requested epochs; this is
   * the one wallet-named step of the anonymous-credential flow. */
  async issueTokens(req: TokenIssueRequest): Promise<TokenIssueResponse> {
    return this.json(
      this.expectOk(
        await this.request('POST', '/v1/tokens/issue', {
          body: JSON.stringify(req),
          signed: true,
        }),
      ),
    );
  }

  /** A {@link TokenTransport} bound to this client, ready to hand to
   * `acquireTokens` to mint v7 session tokens for the EdgeConnect tier. */
  tokenTransport(): TokenTransport {
    return {
      getDirectory: () => this.getTokenDirectory(),
      issue: (req) => this.issueTokens(req),
    };
  }

  /**
   * A {@link TokenTransport} for the BROWSER-PROXY credential class
   * (`/v1/browser-proxy/*`, warren-core doc 103).
   *
   * A separate lane, not a convenience: issuance is once per account, class and
   * epoch and always delivers the whole batch, so a browser minting through
   * {@link tokenTransport} would find every epoch already taken by whichever
   * client refreshed first (typically the desktop app) and never obtain a
   * credential. The two lanes also use different issuer keys, so a credential
   * minted here cannot admit a tunnel session.
   */
  browserProxyTokenTransport(): TokenTransport {
    return {
      getDirectory: async () =>
        this.json(
          this.expectOk(await this.request('GET', '/v1/browser-proxy/keys', { signed: false })),
        ),
      issue: async (req) =>
        this.json(
          this.expectOk(
            await this.request('POST', '/v1/browser-proxy/issue', {
              body: JSON.stringify(req),
              signed: true,
            }),
          ),
        ),
    };
  }

  private async request(
    method: string,
    path: string,
    opts: { body?: string; signed: boolean },
  ): Promise<HttpResponse> {
    const body = opts.body ?? '';
    const headers = this.buildHeaders(method, path, body, opts.signed);
    let lastError: unknown;
    for (const candidate of this.candidates(path)) {
      try {
        return await this.transport.send({
          method,
          url: candidate.url,
          headers,
          body,
          useSni: candidate.useSni,
        });
      } catch (error) {
        // Only a connect-level failure advances the fallback (Rust reference:
        // TransportError::is_connect). A post-connect transport failure stops
        // the sequence: the request may have reached the server, so retrying
        // another host could replay the signed nonce.
        if (error instanceof WarrenTransportError && !error.connect) {
          throw new WarrenApiError('transport', 'transport failed after connect', { cause: error });
        }
        lastError = error;
      }
    }
    throw new WarrenApiError('all_hosts_blocked', 'all hosts failed to connect', {
      cause: lastError,
    });
  }

  private buildHeaders(
    method: string,
    path: string,
    body: string,
    signed: boolean,
  ): Record<string, string> {
    const headers: Record<string, string> = {
      accept: 'application/json',
      'user-agent': USER_AGENT,
    };
    if (body.length > 0) headers['content-type'] = 'application/json';
    if (signed) {
      if (!this.keyPair) {
        throw new WarrenApiError('no_identity', 'signed request requires an identity seed');
      }
      const timestamp = this.now();
      if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
        throw new WarrenApiError('bad_clock', 'system clock is not a valid unix time');
      }
      const sig = signWithKeyPair(this.keyPair, method, path, body, timestamp, this.nonce());
      for (const [name, value] of signatureHeaders(sig)) headers[name] = value;
    }
    return headers;
  }

  private candidates(path: string): Array<{ url: string; useSni: boolean }> {
    const list: Array<{ url: string; useSni: boolean }> = [
      { url: this.baseUrl + path, useSni: true },
    ];
    for (const host of this.alternativeHosts) {
      list.push({ url: replaceHost(this.baseUrl, host) + path, useSni: true });
    }
    list.push({ url: this.baseUrl + path, useSni: false });
    return list;
  }

  private expectOk(res: HttpResponse): HttpResponse {
    if (res.status < 200 || res.status >= 300) {
      throw new WarrenApiError('server', `server returned status ${res.status}`, {
        status: res.status,
        body: res.body,
      });
    }
    return res;
  }

  private json<T>(res: HttpResponse): T {
    try {
      return JSON.parse(res.body) as T;
    } catch (error) {
      throw new WarrenApiError('response', 'invalid JSON response body', { cause: error });
    }
  }
}
