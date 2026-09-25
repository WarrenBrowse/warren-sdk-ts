/**
 * Extension <-> native-host protocol (version 3).
 *
 * Chrome's native messaging carries whole JSON values, so these shapes are the
 * entire wire contract. The mnemonic crosses it only inside a connect or
 * account request, and the host does not keep it.
 *
 * Version 2 made the host listeners demand credentials: the connect answer
 * carries them. Version 3 has the extension name its release channel in
 * `hello`, and the host reaches that channel's API whatever channel its own
 * build defaults to. An older peer on either side is refused at `hello`: a
 * version 2 host would ignore the channel and answer a beta extension from the
 * prod API.
 *
 * The hello answer may also carry `datapath`, the state of the host's native
 * addon, which is built apart from the host's scripts and can lag them. A peer
 * that omits it is read as not saying, so the field needs no version bump.
 *
 * The connect answer, and the status answer while a tunnel is up, may carry
 * `exit`: the country and city of the exit the tunnel lands on (with an entry
 * selector, still the exit, never the entry). Additive in the same way: an
 * older extension ignores it, and a newer one reads its absence, or a value
 * of the wrong shape, as an unknown exit.
 */
import type { ProductChannel } from '@warrenbrowse/sdk-core';

/** Protocol version spoken by this package. */
export const EXTENSION_PROTOCOL_VERSION = 3;

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

/**
 * Whether the host's native datapath addon can carry a tunnel: `missing` when
 * it is not built, `outdated` when it was built from another SDK version.
 */
export type HostDatapath = 'ready' | 'missing' | 'outdated';

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

/** The exit a live tunnel lands on, as the verified relay list names it. */
export interface ExtensionTunnelExit {
  /** ISO 3166-1 alpha-2 country code, upper-case. */
  country: string;
  city: string;
}

/**
 * Reads an `exit` field from the host, or `undefined` when it is absent or not
 * a two-letter country with a city. The country comes back upper-case.
 */
export function parseTunnelExit(value: unknown): ExtensionTunnelExit | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const { country, city } = value as Record<string, unknown>;
  if (typeof country !== 'string' || !/^[A-Za-z]{2}$/.test(country)) return undefined;
  if (typeof city !== 'string') return undefined;
  return { country: country.toUpperCase(), city };
}

/** Requests the extension sends to the host. */
export type HostRequest =
  | {
      id: number;
      type: 'hello';
      protocol: number;
      /** The extension's release channel: the host reaches this channel's API. */
      channel?: ProductChannel;
    }
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
  | {
      id: number;
      ok: true;
      type: 'hello';
      protocol: number;
      /** The native addon's state; absent from a host that predates the field. */
      datapath?: HostDatapath;
    }
  | {
      id: number;
      ok: true;
      type: 'status';
      state: ExtensionVpnState;
      endpoints?: ExtensionEndpoints;
      /** The live tunnel's exit; absent with no tunnel or an unknown exit. */
      exit?: ExtensionTunnelExit;
    }
  | {
      id: number;
      ok: true;
      type: 'connect';
      endpoints: ExtensionEndpoints;
      auth: ExtensionProxyAuth;
      /** The exit the tunnel lands on; absent from a host that does not know it. */
      exit?: ExtensionTunnelExit;
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
