import {
  type HttpTransport,
  type RegisterAccountRequest,
  type RegisterAccountResponse,
  WarrenApiClient,
} from '@warrenbrowse/sdk-core';

/** Options for a {@link WarrenWebClient}. */
export interface WarrenWebClientOptions {
  /** API base URL, e.g. `https://api.warrenbrowse.com`. */
  baseUrl: string;
  /** Transport backend. Defaults to the global `fetch`. */
  transport?: HttpTransport;
  /** Anti-censorship fallback hostnames. */
  alternativeHosts?: string[];
}

/**
 * Browser-safe Warren account client: the UNSIGNED `/v1/*` endpoints only.
 *
 * It never holds an identity seed, so it cannot make signed calls (subscription,
 * session, payments, account deletion). Those carry the user's signing key and
 * belong on a backend using `@warrenbrowse/sdk-node` or `@warrenbrowse/sdk-core`.
 * This enforces the rule that a web page must not carry the identity seed.
 */
export class WarrenWebClient {
  private readonly api: WarrenApiClient;

  constructor(options: WarrenWebClientOptions) {
    this.api = new WarrenApiClient({
      baseUrl: options.baseUrl,
      ...(options.transport ? { transport: options.transport } : {}),
      ...(options.alternativeHosts ? { alternativeHosts: options.alternativeHosts } : {}),
    });
  }

  /** `GET /v1/exits` (unsigned). The raw server-signed relay list JSON. */
  exits(): Promise<string> {
    return this.api.exits();
  }

  /** `POST /v1/register` (unsigned). Redeems a voucher to create or extend an account. */
  register(req: RegisterAccountRequest): Promise<RegisterAccountResponse> {
    return this.api.register(req);
  }

  /** `GET /v1/checkout/{id}/voucher` (unsigned). Polls a pending checkout; `null` until ready. */
  pullPendingVoucher(pendingId: string): Promise<string | null> {
    return this.api.pullPendingVoucher(pendingId);
  }

  /** `GET /v1/multihop/directory` (unsigned). The signed directory JSON, or `null`. */
  multihopDirectory(): Promise<string | null> {
    return this.api.multihopDirectory();
  }
}
