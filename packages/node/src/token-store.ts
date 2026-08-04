/**
 * File-backed {@link TokenPersistence} for the Node SDK: persists a
 * {@link TokenManager}'s pre-minted anonymous tokens under `~/.config/warren` so
 * they survive a process restart, matching where wclaude keeps its config.
 *
 * The file holds ONLY redeemable-but-unlinkable bearer tokens (base64url
 * serialized `SessionToken`s) plus the published epoch length. It NEVER contains
 * the wallet mnemonic or pubkey: the blind-RSA construction already unlinks the
 * tokens from the account, so at worst a leaked file lets someone spend those
 * bounded, anonymous credentials, never impersonate the wallet. The file is
 * written mode 0600 and its directory 0700 for defence in depth.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import type { TokenPersistence } from '@warrenbrowse/sdk-core';

/**
 * Default token-store path: `$WARREN_TOKEN_STORE` when set, else
 * `~/.config/warren/tokens.json` (the same `~/.config/warren` directory wclaude
 * uses for `wclaude.json`).
 */
export function defaultTokenStorePath(
  env: Record<string, string | undefined> = process.env,
  home: string = homedir(),
): string {
  return env.WARREN_TOKEN_STORE ?? join(home, '.config', 'warren', 'tokens.json');
}

/**
 * A {@link TokenPersistence} backed by a single JSON file. Reads return
 * `undefined` when the file is missing or unreadable (fail closed to empty, the
 * manager then re-mints); writes create the parent directory 0700 and the file
 * 0600.
 */
export function fileTokenPersistence(path: string = defaultTokenStorePath()): TokenPersistence {
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
      writeFileSync(path, serialized, { mode: 0o600 });
    },
  };
}
