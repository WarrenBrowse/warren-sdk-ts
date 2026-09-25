import type { Buffer } from 'node:buffer';
import process from 'node:process';
import {
  API_BASE_URL_BY_CHANNEL,
  type ProductChannel,
  WarrenApiClient,
  apiBaseUrl,
  seedFromMnemonic,
  verifySignedRelayList,
} from '@warrenbrowse/sdk-core';
import { ProxyTunnel, proxyDatapathStatus } from '@warrenbrowse/sdk-node';
import type { HostRequest } from '../protocol.js';
import { NativeFrameDecoder, encodeNativeFrame } from './framing.js';
import { HostSession } from './session.js';

/**
 * Configuration of the native host process. The host is identity-less: the
 * account mnemonic arrives per-connect from the extension's vault, never here.
 */
export interface NativeHostConfig {
  /** An explicit API base (`WARREN_API_BASE`), which wins over any channel. */
  apiBase?: string;
  /** Pinned discovery signer (64-hex). When empty, the host TOFUs the list signer. */
  serverPubkeyPin?: string;
  multihopRootPinHex?: string;
  stateDir?: string;
}

/** Reads the host configuration from the environment. No secrets are read here. */
export function configFromEnv(env: NodeJS.ProcessEnv = process.env): NativeHostConfig {
  return {
    ...(env.WARREN_API_BASE ? { apiBase: env.WARREN_API_BASE } : {}),
    ...(env.WARREN_SERVER_PUBKEY_PIN ? { serverPubkeyPin: env.WARREN_SERVER_PUBKEY_PIN } : {}),
    ...(env.WARREN_MULTIHOP_ROOT_PIN ? { multihopRootPinHex: env.WARREN_MULTIHOP_ROOT_PIN } : {}),
    ...(env.WARREN_STATE_DIR ? { stateDir: env.WARREN_STATE_DIR } : {}),
  };
}

/**
 * The API the host reaches for an extension of `channel`. The extension is the
 * channel authority: the host's own build may target the other channel, and a
 * beta extension served by a prod-built host would otherwise get the prod
 * API's 410 on every request. The build's channel only answers an extension
 * that named none.
 */
export function hostApiBase(config: NativeHostConfig, channel: ProductChannel | undefined): string {
  if (config.apiBase) return config.apiBase;
  return channel ? API_BASE_URL_BY_CHANNEL[channel] : apiBaseUrl;
}

/**
 * Resolves the discovery pin: the configured one, or the signer of the current
 * signed relay list on first use (TOFU). Fetched over the public unsigned
 * `/v1/exits` endpoint so no account is needed just to learn the pin.
 */
export async function resolveServerPin(config: NativeHostConfig, apiBase: string): Promise<string> {
  if (config.serverPubkeyPin) return config.serverPubkeyPin;
  const client = new WarrenApiClient({ baseUrl: apiBase });
  return verifySignedRelayList(await client.exits()).serverPubkeyHex;
}

/**
 * Verifies the browser-supplied caller identity. Chromium passes the calling
 * extension's origin as argv; Firefox passes the manifest path plus the gecko
 * extension id. The native-messaging manifest is per-browser, so this is the
 * only per-caller gate the host can apply.
 *
 * `allowed`: extension origins (`chrome-extension://<id>/`), bare Chromium
 * ids, or gecko ids (`name@domain`). Empty or unset means any caller the
 * browser manifest admitted.
 */
export function callerAllowed(argv: readonly string[], allowed: readonly string[]): boolean {
  if (allowed.length === 0) return true;
  return argv.some((arg) =>
    allowed.some((entry) => {
      if (arg === entry) return true;
      const origin = entry.startsWith('chrome-extension://')
        ? entry
        : `chrome-extension://${entry}/`;
      return arg === origin || arg === origin.replace(/\/$/, '');
    }),
  );
}

/**
 * Runs the native messaging host on this process's stdio until the browser
 * disconnects (stdin EOF). The tunnel dies with the process: fail-closed.
 *
 * Set `WARREN_ALLOWED_ORIGINS` (comma-separated extension ids or origins) to
 * additionally pin which extension may drive this host.
 */
export function runNativeHost(config: NativeHostConfig): Promise<void> {
  const allowed = (process.env.WARREN_ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (!callerAllowed(process.argv, allowed)) {
    return Promise.reject(new Error('caller extension is not in WARREN_ALLOWED_ORIGINS'));
  }
  const session = new HostSession({
    listExits: async (channel) => {
      const client = new WarrenApiClient({ baseUrl: hostApiBase(config, channel) });
      const verified = verifySignedRelayList(
        await client.exits(),
        config.serverPubkeyPin ? [config.serverPubkeyPin] : undefined,
      );
      return verified.relays.map((relay) => ({
        country: relay.country,
        city: relay.city,
        active: relay.active,
      }));
    },
    accountStatus: async (mnemonic, channel) => {
      const seed = seedFromMnemonic(mnemonic);
      const client = new WarrenApiClient({ baseUrl: hostApiBase(config, channel), seed });
      seed.fill(0);
      try {
        const { expires_at } = await client.subscription();
        return { expiresAt: expires_at };
      } finally {
        client.dispose();
      }
    },
    createTunnel: async (mnemonic, onState, init) => {
      const apiBase = hostApiBase(config, init?.channel);
      const serverPubkeyPin = await resolveServerPin(config, apiBase);
      return ProxyTunnel.create({
        mnemonic,
        apiBase,
        serverPubkeyPin,
        ...(init?.daita !== undefined ? { daita: init.daita } : {}),
        ...(config.multihopRootPinHex ? { multihopRootPinHex: config.multihopRootPinHex } : {}),
        ...(config.stateDir ? { stateDir: config.stateDir } : {}),
        onState: (state) => onState(state),
      });
    },
    datapathStatus: proxyDatapathStatus,
    send: (message) => process.stdout.write(encodeNativeFrame(message)),
  });

  const decoder = new NativeFrameDecoder();
  return new Promise((resolve) => {
    const finish = async () => {
      await session.close();
      resolve();
    };
    process.stdin.on('data', (chunk: Buffer) => {
      let messages: unknown[];
      try {
        messages = decoder.push(chunk);
      } catch {
        // A corrupt frame is unrecoverable on this stream; die fail-closed.
        void finish();
        return;
      }
      for (const message of messages) void session.handle(message as HostRequest);
    });
    process.stdin.on('end', () => void finish());
    process.on('SIGINT', () => void finish());
    process.on('SIGTERM', () => void finish());
  });
}
