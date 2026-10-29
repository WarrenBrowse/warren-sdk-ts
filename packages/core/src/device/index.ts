/**
 * This install's identity in the account's device registry (warren-core doc
 * 115): a random identifier and a generated name, kept where the install keeps
 * its token state, and the readers of what the registry answers.
 *
 * The name is drawn from the same two word lists as the Rust SDK
 * (`warren-sdk-rs` `crates/warren-api/src/device.rs`), so every Warren client
 * names its devices the same way. Nothing here is derived from the wallet or
 * the hardware.
 */

import { randomBytes } from '@noble/hashes/utils';
import { base64urlnopad } from '@scure/base';
import type {
  DeviceId,
  DeviceListResponse,
  DevicePlatform,
  DeviceRegistration,
  DeviceView,
  RegistrablePlatform,
} from '../api/dto.js';
import { WarrenApiError } from '../api/errors.js';

/** Length in bytes of a device id. */
export const DEVICE_ID_LEN = 16;

/** Discriminator for {@link WarrenDeviceError}. */
export type WarrenDeviceErrorCode =
  /** Not 16 bytes of base64url without padding. */
  | 'invalid_device_id'
  /** A platform outside the registry's closed set (or `other`) was asked to register. */
  | 'invalid_platform'
  /** A token manager was given a device but its transport cannot register one. */
  | 'no_registrar';

/** A typed device-registry error. Its message never carries the id or the name. */
export class WarrenDeviceError extends Error {
  readonly code: WarrenDeviceErrorCode;

  constructor(code: WarrenDeviceErrorCode, message: string) {
    super(message);
    this.name = 'WarrenDeviceError';
    this.code = code;
  }
}

/**
 * Reads a device id as the wire spells it.
 *
 * @throws {WarrenDeviceError} `invalid_device_id` unless `value` is exactly 16
 * bytes of url-safe base64 without padding (non-zero trailing bits included,
 * as the contract refuses them).
 */
export function parseDeviceId(value: string): DeviceId {
  let bytes: Uint8Array;
  try {
    bytes = base64urlnopad.decode(value);
  } catch {
    throw invalidId();
  }
  if (bytes.length !== DEVICE_ID_LEN) throw invalidId();
  return value as DeviceId;
}

/**
 * The id spelling `bytes`.
 *
 * @throws {WarrenDeviceError} `invalid_device_id` unless `bytes` is 16 bytes long.
 */
export function deviceIdFromBytes(bytes: Uint8Array): DeviceId {
  if (bytes.length !== DEVICE_ID_LEN) throw invalidId();
  return base64urlnopad.encode(bytes) as DeviceId;
}

/** The 16 bytes `id` spells. */
export function deviceIdBytes(id: DeviceId): Uint8Array {
  return base64urlnopad.decode(id);
}

function invalidId(): WarrenDeviceError {
  return new WarrenDeviceError(
    'invalid_device_id',
    `a device id is ${DEVICE_ID_LEN} bytes as base64url without padding`,
  );
}

/** The platforms a device can register as. */
export const DEVICE_PLATFORMS: readonly RegistrablePlatform[] = [
  'android',
  'ios',
  'macos',
  'windows',
  'linux',
  'cli',
  'browser',
];

/** Reads a platform off the wire: anything outside the closed set reads as `other`. */
export function parseDevicePlatform(value: unknown): DevicePlatform {
  return DEVICE_PLATFORMS.find((p) => p === value) ?? 'other';
}

/** The first word of a generated device name. */
export const DEVICE_NAME_ADJECTIVES: readonly string[] = [
  'amber',
  'bold',
  'brave',
  'bright',
  'calm',
  'clever',
  'cosy',
  'crisp',
  'curious',
  'dapper',
  'eager',
  'fair',
  'gentle',
  'glad',
  'golden',
  'happy',
  'honest',
  'jolly',
  'keen',
  'kind',
  'lively',
  'lucky',
  'merry',
  'mighty',
  'nimble',
  'noble',
  'patient',
  'plucky',
  'proud',
  'quick',
  'quiet',
  'rapid',
  'shy',
  'silver',
  'sleek',
  'steady',
  'sunny',
  'swift',
  'tidy',
  'witty',
];

/** The second word of a generated device name. */
export const DEVICE_NAME_ANIMALS: readonly string[] = [
  'badger',
  'beaver',
  'bison',
  'crane',
  'deer',
  'dolphin',
  'eagle',
  'falcon',
  'ferret',
  'finch',
  'fox',
  'gecko',
  'hare',
  'hedgehog',
  'heron',
  'ibis',
  'jackal',
  'koala',
  'lemur',
  'lynx',
  'marten',
  'mole',
  'moose',
  'newt',
  'otter',
  'owl',
  'panda',
  'puffin',
  'rabbit',
  'raven',
  'robin',
  'seal',
  'sparrow',
  'squirrel',
  'stoat',
  'swan',
  'tapir',
  'toad',
  'walrus',
  'wolf',
];

/**
 * A device name from `nextU32` (a source of uniform 32-bit draws): an
 * adjective then an animal, lowercase, one space apart, each word indexed by
 * its draw modulo the list length as the Rust SDK does (the bias over lists
 * this short is below one in a hundred million).
 */
export function deviceNameFrom(nextU32: () => number): string {
  const adjective = DEVICE_NAME_ADJECTIVES[nextU32() % DEVICE_NAME_ADJECTIVES.length];
  const animal = DEVICE_NAME_ANIMALS[nextU32() % DEVICE_NAME_ANIMALS.length];
  return `${adjective} ${animal}`;
}

/** A device name drawn from the platform CSPRNG. */
export function generateDeviceName(): string {
  return deviceNameFrom(() => new DataView(randomBytes(4).buffer).getUint32(0));
}

/**
 * This install's identity in the account's registry: drawn once, kept with
 * the install's token state, and sent with every registration and issuance.
 * Both values name an install of a wallet: keep them out of every log.
 */
export interface DeviceIdentity {
  deviceId: DeviceId;
  name: string;
}

/** A new identity: 16 bytes from the platform CSPRNG and a generated name. */
export function generateDeviceIdentity(): DeviceIdentity {
  return { deviceId: deviceIdFromBytes(randomBytes(DEVICE_ID_LEN)), name: generateDeviceName() };
}

/**
 * The registration `identity` sends from `platform`, running `appVersion`.
 *
 * @throws {WarrenDeviceError} `invalid_platform` for a platform outside the
 * registry's closed set, which the server would refuse.
 */
export function deviceRegistration(
  identity: DeviceIdentity,
  platform: RegistrablePlatform,
  appVersion: string,
): DeviceRegistration {
  if (!DEVICE_PLATFORMS.includes(platform)) {
    throw new WarrenDeviceError('invalid_platform', 'a device registers on a platform it names');
  }
  return {
    device_id: identity.deviceId,
    name: identity.name,
    platform,
    app_version: appVersion,
  };
}

/**
 * `identity` as the Rust SDK keeps it on disk (`{"device_id","name"}`), so
 * the helper and the Node engine read the identity this SDK keeps, and the
 * other way round.
 */
export function encodeDeviceIdentity(identity: DeviceIdentity): string {
  return JSON.stringify({ device_id: identity.deviceId, name: identity.name });
}

/** Reads a kept identity, or `undefined` when `text` is not one. */
export function parseDeviceIdentity(text: string): DeviceIdentity | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null) return undefined;
  const { device_id, name } = parsed as Record<string, unknown>;
  if (typeof device_id !== 'string' || typeof name !== 'string' || name.length === 0) {
    return undefined;
  }
  try {
    return { deviceId: parseDeviceId(device_id), name };
  } catch {
    return undefined;
  }
}

/**
 * Persistence seam for the device identity, beside the token state: a file
 * on Node (`@warrenbrowse/sdk-node` `fileDeviceIdentityPersistence`), the
 * extension's storage in a browser. Synchronous, like `TokenPersistence`.
 */
export interface DeviceIdentityPersistence {
  /** The kept identity's text, or `undefined` when none is kept. */
  load(): string | undefined;
  /** Create-or-replace the kept identity with `serialized`. */
  save(serialized: string): void;
  /** Erase the kept identity. Erasing an absent one is not an error. */
  remove(): void;
}

/** In-memory persistence: the process's own RAM, lost on restart. */
export class InMemoryDeviceIdentityPersistence implements DeviceIdentityPersistence {
  private text: string | undefined;

  load(): string | undefined {
    return this.text;
  }

  save(serialized: string): void {
    this.text = serialized;
  }

  remove(): void {
    this.text = undefined;
  }
}

/**
 * The identity kept in `persistence`, or a new one drawn and kept there on
 * first use. The account lists an install by it, so a new draw at every start
 * would add a device at every start. An unreadable one is replaced.
 */
export function keptDeviceIdentity(persistence: DeviceIdentityPersistence): DeviceIdentity {
  const kept = readKept(persistence);
  if (kept) return kept;
  const drawn = generateDeviceIdentity();
  persistence.save(encodeDeviceIdentity(drawn));
  return drawn;
}

/**
 * Keeps `name` as the kept identity's name (a rename, or the name the
 * registry answered a registration with). `false`, and nothing written, when
 * no identity is kept: a name is never kept without the id it names.
 */
export function keepDeviceName(persistence: DeviceIdentityPersistence, name: string): boolean {
  const kept = readKept(persistence);
  if (!kept) return false;
  persistence.save(encodeDeviceIdentity({ ...kept, name }));
  return true;
}

/**
 * Erases the kept identity once the device was revoked or logged out: the
 * next {@link keptDeviceIdentity} draws a new one, a new line in the list.
 */
export function forgetDeviceIdentity(persistence: DeviceIdentityPersistence): void {
  persistence.remove();
}

function readKept(persistence: DeviceIdentityPersistence): DeviceIdentity | undefined {
  const text = persistence.load();
  return text === undefined ? undefined : parseDeviceIdentity(text);
}

/**
 * Reads one listed device from a decoded answer, its platform through
 * {@link parseDevicePlatform}.
 *
 * @throws {WarrenApiError} `response` when a field is missing or of the wrong type.
 */
export function readDeviceView(value: unknown): DeviceView {
  if (typeof value !== 'object' || value === null) throw badAnswer();
  const v = value as Record<string, unknown>;
  const strings = ['device_id', 'name', 'app_version', 'registered_on', 'last_seen_on'] as const;
  if (strings.some((k) => typeof v[k] !== 'string') || typeof v.this_device !== 'boolean') {
    throw badAnswer();
  }
  let deviceId: DeviceId;
  try {
    deviceId = parseDeviceId(v.device_id as string);
  } catch {
    throw badAnswer();
  }
  return {
    device_id: deviceId,
    name: v.name as string,
    platform: parseDevicePlatform(v.platform),
    app_version: v.app_version as string,
    registered_on: v.registered_on as string,
    last_seen_on: v.last_seen_on as string,
    this_device: v.this_device,
  };
}

/**
 * Reads a device list from a decoded answer.
 *
 * @throws {WarrenApiError} `response` when it is not one.
 */
export function readDeviceList(value: unknown): DeviceListResponse {
  if (typeof value !== 'object' || value === null) throw badAnswer();
  const { devices, older_client_seen_on } = value as Record<string, unknown>;
  if (!Array.isArray(devices)) throw badAnswer();
  // A null reads as absent, as the Rust contract's Option does.
  if (older_client_seen_on != null && typeof older_client_seen_on !== 'string') {
    throw badAnswer();
  }
  return {
    devices: devices.map(readDeviceView),
    ...(typeof older_client_seen_on === 'string' ? { older_client_seen_on } : {}),
  };
}

function badAnswer(): WarrenApiError {
  return new WarrenApiError('response', 'the device registry answered in an unexpected shape');
}
