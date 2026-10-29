import { existsSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  defaultDeviceIdentityPath,
  fileDeviceIdentityPersistence,
  forgetDeviceIdentity,
  keptDeviceIdentity,
  nodeDevicePlatform,
} from '../src/index.js';

describe('fileDeviceIdentityPersistence', () => {
  it('keeps the identity across a restart, the directory 0700 and the file 0600', () => {
    const dir = mkdtempSync(join(tmpdir(), 'warren-device-'));
    const path = join(dir, 'warren', 'device.json');

    const drawn = keptDeviceIdentity(fileDeviceIdentityPersistence(path));

    expect(keptDeviceIdentity(fileDeviceIdentityPersistence(path))).toEqual(drawn);
    // The Rust SDK's file format: the helper and the engine read this file.
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({
      device_id: drawn.deviceId,
      name: drawn.name,
    });
    if (process.platform !== 'win32') {
      expect(statSync(path).mode & 0o777).toBe(0o600);
      expect(statSync(join(dir, 'warren')).mode & 0o777).toBe(0o700);
    }
  });

  it('forgets the identity by removing the file, and forgetting twice is fine', () => {
    const dir = mkdtempSync(join(tmpdir(), 'warren-device-'));
    const path = join(dir, 'device.json');
    const persistence = fileDeviceIdentityPersistence(path);
    keptDeviceIdentity(persistence);

    forgetDeviceIdentity(persistence);
    forgetDeviceIdentity(persistence);

    expect(existsSync(path)).toBe(false);
    expect(persistence.load()).toBeUndefined();
  });

  it('leaves no partial file behind a write', () => {
    const dir = mkdtempSync(join(tmpdir(), 'warren-device-'));
    const path = join(dir, 'device.json');

    keptDeviceIdentity(fileDeviceIdentityPersistence(path));

    expect(existsSync(`${path}.partial`)).toBe(false);
  });
});

describe('defaultDeviceIdentityPath', () => {
  it('defaults next to the token store and honors WARREN_DEVICE_IDENTITY', () => {
    const home = join('home', 'user');
    expect(defaultDeviceIdentityPath({}, home)).toBe(
      join(home, '.config', 'warren', 'device.json'),
    );
    expect(defaultDeviceIdentityPath({ WARREN_DEVICE_IDENTITY: '/custom/d.json' }, home)).toBe(
      '/custom/d.json',
    );
  });
});

describe('nodeDevicePlatform', () => {
  it('names the desktop operating systems by their registry platform', () => {
    expect(nodeDevicePlatform('darwin')).toBe('macos');
    expect(nodeDevicePlatform('win32')).toBe('windows');
    expect(nodeDevicePlatform('linux')).toBe('linux');
    expect(nodeDevicePlatform('android')).toBe('android');
  });

  it('registers any other system as a command-line client', () => {
    expect(nodeDevicePlatform('freebsd')).toBe('cli');
  });
});
