/**
 * Extension <-> native-host protocol (version 2).
 *
 * Chrome's native messaging carries whole JSON values, so these shapes are the
 * entire wire contract. The mnemonic crosses it only inside a connect or
 * account request, and the host does not keep it.
 *
 * Version 2 is the version whose host listeners demand credentials: the
 * connect answer carries them, and a version 1 peer on either side, which
 * would route a browser through listeners it cannot authenticate to, is
 * refused at `hello`.
 */

/** Protocol version spoken by this package. */
export const EXTENSION_PROTOCOL_VERSION = 2;

/** Default native messaging host name the browser resolves to the local binary. */
export const DEFAULT_HOST_NAME = 'com.warrenbrowse.host';

/** Tunnel lifecycle states relayed from the host (superset of the engine's). */
export type ExtensionVpnState =
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'draining'
  | 'failed'
  | 'disconnected';

/** Exit selection carried by a connect request. */
export interface ExtensionExitQuery {
  exitPubkeyHex?: string;
  country?: string;
  city?: string;
}

/**
 * Multihop entry-hop selection: which country/city the circuit enters the
 * fleet through. The entry is always a node distinct from the exit; a query
 * only matching the exit's own node fails the connect (unlinkability rule).
 */
export interface ExtensionEntryQuery {
  country?: string;
  city?: string;
}

/** One selectable exit location from the verified relay list. */
export interface ExtensionExitLocation {
  /** ISO 3166-1 alpha-2 country code. */
  country: string;
  city: string;
  active: boolean;
}

/** Requests the extension sends to the host. */
export type HostRequest =
  | { id: number; type: 'hello'; protocol: number }
  | { id: number; type: 'status' }
  | {
      id: number;
      type: 'connect';
      /**
       * The account mnemonic, held encrypted in the extension and handed to the
       * local host only for this connect. The host uses it for the datapath and
       * does not persist it. Never logged on either side.
       */
      mnemonic: string;
      selector?: ExtensionExitQuery;
      /** Multihop entry-hop selection; omit for the default circuit. */
      entrySelector?: ExtensionEntryQuery;
      httpProxy?: boolean;
      /** Enables the DAITA uplink traffic-analysis defense on the tunnel. */
      daita?: boolean;
    }
  | { id: number; type: 'disconnect' }
  | { id: number; type: 'exits' }
  | {
      id: number;
      type: 'account';
      /** Same per-request handling as connect: used to sign, never persisted. */
      mnemonic: string;
    };

/** Local proxy listener addresses reported by the host once connected. */
export interface ExtensionEndpoints {
  socks5: string;
  http?: string;
}

/**
 * The credentials both listeners demand (RFC 1929 on SOCKS5,
 * `Proxy-Authorization: Basic` on HTTP), fresh for each tunnel. A per-session
 * secret: it crosses this channel once, in the connect answer, and lives in
 * the extension's memory only as long as the host that minted it.
 */
export interface ExtensionProxyAuth {
  username: string;
  password: string;
}

/** Responses the host sends back, correlated by `id`. */
export type HostResponse =
  // The host is identity-less: it reports only the protocol version. The
  // account address is derived in the extension from its own vault.
  | { id: number; ok: true; type: 'hello'; protocol: number }
  | {
      id: number;
      ok: true;
      type: 'status';
      state: ExtensionVpnState;
      endpoints?: ExtensionEndpoints;
    }
  | {
      id: number;
      ok: true;
      type: 'connect';
      endpoints: ExtensionEndpoints;
      auth: ExtensionProxyAuth;
    }
  | { id: number; ok: true; type: 'disconnect' }
  | { id: number; ok: true; type: 'exits'; locations: ExtensionExitLocation[] }
  | {
      id: number;
      ok: true;
      type: 'account';
      /** Subscription expiry, unix epoch seconds. */
      expiresAt: number;
    }
  | { id: number; ok: false; code: string; message: string };

/** Unsolicited events pushed by the host. */
export interface HostStateEvent {
  type: 'state';
  state: ExtensionVpnState;
}

/** Any message the host emits. */
export type HostMessage = HostResponse | HostStateEvent;

/** Narrows an unknown decoded value to a {@link HostMessage}, or null. */
export function parseHostMessage(value: unknown): HostMessage | null {
  if (typeof value !== 'object' || value === null) return null;
  const m = value as Record<string, unknown>;
  if (m.type === 'state' && typeof m.state === 'string') {
    return { type: 'state', state: m.state as ExtensionVpnState };
  }
  if (typeof m.id === 'number' && typeof m.ok === 'boolean') {
    return m as unknown as HostResponse;
  }
  return null;
}
