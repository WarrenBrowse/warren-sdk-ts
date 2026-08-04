/** A resolved, dialable Warren relay (one node of a verified signed list). */
export interface Relay {
  /** 64-char lowercase hex of the 32-byte node id. */
  readonly endpointIdHex: string;
  /** 32-char lowercase hex of the 16-byte exit id. */
  readonly exitIdHex: string;
  /** ISO 3166-1 alpha-2 country code. */
  readonly country: string;
  readonly city: string;
  /** Selection weight (0 disables weighted selection). */
  readonly weight: number;
  /** Whether the node is enabled. */
  readonly active: boolean;
  /** Node-level capability: a working IPv6 egress source. */
  readonly ipv6Egress: boolean;
  /** True if the node has at least one IPv4 dial endpoint. */
  readonly hasIpv4: boolean;
  /** True if the node has at least one IPv6 dial endpoint. */
  readonly hasIpv6: boolean;
  /** Dialable QUIC socket addresses, e.g. `50.7.46.90:443` or `[2001:db8::1]:443`. */
  readonly addrs: readonly string[];
  /**
   * v6 X.509 cover-domain SNI to dial this exit (wg-0005): the hostname on its
   * real certificate, validated via WebPKI instead of pinning the RPK. Absent
   * on RPK nodes (dial in raw-public-key mode).
   */
  readonly coverDomain?: string;
}

/**
 * A verified signed relay list.
 *
 * The signature, version and validity-window cap have already been checked. The
 * caller MUST still enforce two time-dependent rules the verifier cannot:
 * anti-rollback (reject a `generation` lower than the last seen) and expiry
 * (reject once {@link isExpired} is true).
 */
export interface VerifiedRelayList {
  /** Monotonic content version; the anti-rollback high-water mark. */
  readonly generation: number;
  /** Unix epoch seconds the list was signed at. */
  readonly signedAt: number;
  /** Unix epoch seconds the list expires at. */
  readonly expiresAt: number;
  readonly relays: readonly Relay[];
  /** The verified list signer (64-char lowercase hex), for TOFU pinning. */
  readonly serverPubkeyHex: string;
}

/** Returns whether the list is expired at the given wall-clock time. */
export function isExpired(list: VerifiedRelayList, nowUnixSecs: number): boolean {
  return nowUnixSecs >= list.expiresAt;
}
