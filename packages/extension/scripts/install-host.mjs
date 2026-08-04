#!/usr/bin/env node
// Registers the Warren native messaging host manifest for Chromium browsers
// (Chrome, Chromium, Brave, Edge) and, with --gecko-id, for Firefox.
// Usage: node install-host.mjs [--extension-id <chromium id>]... [--gecko-id <id@domain>]... [--host-command <path>]
import { mkdirSync, writeFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const HOST_NAME = 'com.warrenbrowse.host';

function arg(name) {
  const index = process.argv.indexOf(name);
  return index > -1 ? process.argv[index + 1] : undefined;
}

// Repeatable: several extensions (e.g. the product and the SDK example) may
// share the one host manifest, which carries an allowlist array.
function args(name) {
  const values = [];
  for (let i = 0; i < process.argv.length - 1; i++) {
    if (process.argv[i] === name) values.push(process.argv[i + 1]);
  }
  return values;
}

const extensionIds = args('--extension-id');
const geckoIds = args('--gecko-id');
const extensionId = extensionIds[0];
const geckoId = geckoIds[0];
if (!extensionId && !geckoId) {
  console.error(
    'usage: install-host.mjs [--extension-id <chromium extension id>] [--gecko-id <id@domain>] [--host-command <path>]',
  );
  process.exit(1);
}

const defaultLauncher = resolve(dirname(fileURLToPath(import.meta.url)), 'warren-host-launcher.sh');
const hostCommand = arg('--host-command') ?? defaultLauncher;

const base = {
  name: HOST_NAME,
  description: 'Warren VPN native host (local SOCKS5 tunnel)',
  path: hostCommand,
  type: 'stdio',
};
// Chromium and Firefox use different caller-allowlist schemas.
const chromiumManifest = {
  ...base,
  allowed_origins: extensionIds.map((id) => `chrome-extension://${id}/`),
};
const firefoxManifest = { ...base, allowed_extensions: geckoIds };

function chromiumDirs(home) {
  switch (platform()) {
    case 'darwin':
      return [
        join(home, 'Library/Application Support/Google/Chrome/NativeMessagingHosts'),
        join(home, 'Library/Application Support/Chromium/NativeMessagingHosts'),
        join(home, 'Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts'),
        join(home, 'Library/Application Support/Microsoft Edge/NativeMessagingHosts'),
      ];
    case 'linux':
      return [
        join(home, '.config/google-chrome/NativeMessagingHosts'),
        join(home, '.config/chromium/NativeMessagingHosts'),
        join(home, '.config/BraveSoftware/Brave-Browser/NativeMessagingHosts'),
        join(home, '.config/microsoft-edge/NativeMessagingHosts'),
      ];
    default:
      return undefined;
  }
}

function firefoxDirs(home) {
  switch (platform()) {
    case 'darwin':
      return [join(home, 'Library/Application Support/Mozilla/NativeMessagingHosts')];
    case 'linux':
      return [join(home, '.mozilla/native-messaging-hosts')];
    default:
      return undefined;
  }
}

function write(dirs, manifest) {
  for (const dir of dirs) {
    mkdirSync(dir, { recursive: true });
    const file = join(dir, `${HOST_NAME}.json`);
    writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`wrote ${file}`);
  }
}

function windowsHelp() {
  // Windows requires registry keys pointing at the manifest; print them
  // instead of guessing the hive. Brave has NO Chrome-key fallback and needs
  // its own key; Edge falls back to the Chrome key but registering its own
  // avoids the first-manifest-found trap. Firefox uses the Mozilla hive.
  const lines = [
    'On Windows, write each manifest JSON to a file and register it (file path as the default value) under:',
  ];
  if (extensionId) {
    lines.push(
      `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}`,
      `HKCU\\Software\\BraveSoftware\\Brave\\NativeMessagingHosts\\${HOST_NAME}`,
      `HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\${HOST_NAME}`,
      JSON.stringify(chromiumManifest, null, 2),
    );
  }
  if (geckoId) {
    lines.push(
      `HKCU\\Software\\Mozilla\\NativeMessagingHosts\\${HOST_NAME}`,
      JSON.stringify(firefoxManifest, null, 2),
    );
  }
  console.error(lines.join('\n'));
  process.exit(2);
}

const home = homedir();
const chromium = chromiumDirs(home);
if (chromium === undefined) windowsHelp();
if (extensionId) write(chromium, chromiumManifest);
if (geckoId) write(firefoxDirs(home), firefoxManifest);
console.log(`host command: ${hostCommand}`);
