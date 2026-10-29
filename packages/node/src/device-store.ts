/**
 * File-backed device identity for the Node SDK (warren-core doc 115), kept
 * next to the token store under `~/.config/warren`, in the Rust SDK's own file
 * format so the native engine (`ProxyTunnel`'s `device` option) registers the
 * very identity the TypeScript control plane keeps.
 *
 * The file names an install of a wallet to its own account: a random id and a
 * generated name, nothing from the wallet or the hardware. It is written 0600
 * in a 0700 directory, whole (a side file renamed over it), because a torn
 * write would still read as another identity.
 */

import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import type { DeviceIdentityPersistence, RegistrablePlatform } from '@warrenbrowse/sdk-core';

/**
 * Default device identity path: `$WARREN_DEVICE_IDENTITY` when set, else
 * `~/.config/warren/device.json`, beside the default token store.
 */
export function defaultDeviceIdentityPath(
  env: Record<string, string | undefined> = process.env,
  home: string = homedir(),
): string {
  return env.WARREN_DEVICE_IDENTITY ?? join(home, '.config', 'warren', 'device.json');
}

/**
 * A {@link DeviceIdentityPersistence} over one file. A missing or unreadable
 * file reads as none kept (the caller then draws one).
 */
export function fileDeviceIdentityPersistence(
  path: string = defaultDeviceIdentityPath(),
): DeviceIdentityPersistence {
  return {
    load(): string | undefined {
      try {
        return readFileSync(path, 'utf8');
      } catch {
        return undefined;
      }
    },
    save(serialized: string): void {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      const partial = `${path}.partial`;
      writeFileSync(partial, serialized, { mode: 0o600 });
      renameSync(partial, path);
    },
    remove(): void {
      rmSync(path, { force: true });
    },
  };
}

/**
 * The platform a Node process registers as: its operating system, and `cli`
 * for one outside the registry's set (it has no generic desktop entry, and a
 * Node consumer there is closest to a command-line client).
 */
export function nodeDevicePlatform(platform: string = process.platform): RegistrablePlatform {
  switch (platform) {
    case 'darwin':
      return 'macos';
    case 'win32':
      return 'windows';
    case 'linux':
      return 'linux';
    case 'android':
      return 'android';
    default:
      return 'cli';
  }
}
