/**
 * Wire DTOs for the Warren `/v1/*` account API.
 *
 * Field names are snake_case to match the warren-core JSON byte-for-byte: these
 * objects are serialized and parsed directly, so the property names ARE the wire
 * contract. Do not rename without rotating the API schema.
 */

/** `POST /v1/register` (unsigned) request. */
export interface RegisterAccountRequest {
  pubkey_ss58: string;
  /** Bearer credential. Never log it. */
  voucher_secret: string;
  /** Omitted from JSON when undefined. */
  referral_code?: string;
}

/** `POST /v1/register` response. */
export interface RegisterAccountResponse {
  /** Unix epoch seconds. */
  expires_at: number;
}

/** `GET /v1/subscription` (signed) response. */
export interface SubscriptionResponse {
  /** Unix epoch seconds. */
  expires_at: number;
}

/** `GET /v1/check` (signed) response. */
export interface CheckResponse {
  ip: string;
  is_exit: boolean;
  exit_country?: string;
  exit_city?: string;
}

/** `POST /v1/session/open` (signed) request. */
export interface SessionOpenRequest {
  pubkey_ss58: string;
  /** 32 lowercase hex chars (16 bytes). */
  device_id_hex: string;
  exit_id: string;
  max_devices?: number;
}

/** `POST /v1/session/open` response. */
export interface SessionOpenResponse {
  admitted: boolean;
  max: number;
  current: number;
}

/** Reason an exit was reported down. Serialized SCREAMING_SNAKE_CASE on the wire. */
export type IncidentReason = 'TIMEOUT' | 'HANDSHAKE_FAIL' | 'AUTH_FAIL';

/** `POST /v1/incidents/exit-down` (signed) request. */
export interface IncidentExitDownRequest {
  /** 64 lowercase hex chars (32-byte pubkey). */
  exit_pubkey_hex: string;
  reason_code: IncidentReason;
  /** Unix epoch seconds (server overwrites). */
  ts_unix: number;
}

/** `POST /v1/session/close` (signed) request. */
export interface SessionCloseRequest {
  pubkey_ss58: string;
  /** 32 lowercase hex chars (16 bytes). */
  device_id_hex: string;
}

/** `POST /v1/payments/apple/init` (signed) response. */
export interface InitApplePaymentResponse {
  /** UUID v4 (lowercase, hyphenated) to pass to StoreKit as `appAccountToken`. */
  app_account_token: string;
}

/** `POST /v1/payments/apple/check` (signed) request. */
export interface CheckApplePaymentRequest {
  /** StoreKit 2 JWS (`Transaction.jwsRepresentation`). Bearer credential; never log it. */
  jws_transaction: string;
}

/** Shared response for the mobile payment endpoints. */
export interface MobilePaymentResponse {
  /** Unix epoch seconds at which the subscription now expires. */
  expires_at: number;
}

/** `POST /v1/incidents/pubkey-mismatch` (signed) request. `countryCode`/`city` default to empty. */
export interface IncidentPubkeyMismatchRequest {
  /** 32-char hex stable exit identifier. */
  exitIdHex: string;
  /** Pubkey hex previously pinned. */
  oldPubkeyHex: string;
  /** Pubkey hex observed on the failed connect. */
  newPubkeyHex: string;
  /** ISO 3166 alpha-2, lowercase. Optional. */
  countryCode?: string;
  /** Free-form city label. Optional. */
  city?: string;
  /** Unix epoch seconds (server overwrites). */
  tsUnix: number;
}

/**
 * A device id: 16 random bytes as base64url without padding (warren-core doc
 * 115). Branded so only {@link parseDeviceId} or {@link deviceIdFromBytes}
 * make one. It names an install to its own account: keep it out of every log.
 */
export type DeviceId = string & { readonly __brand: 'DeviceId' };

/**
 * The platform a device runs on, as its list line shows it. `other` is how a
 * platform this build does not know reads, so a newer server's list still
 * parses; nothing registers as `other`.
 */
export type DevicePlatform =
  | 'android'
  | 'ios'
  | 'macos'
  | 'windows'
  | 'linux'
  | 'cli'
  | 'browser'
  | 'other';

/** A platform a device can register as: the registry's closed set. */
export type RegistrablePlatform = Exclude<DevicePlatform, 'other'>;

/** `POST /v1/devices` (signed) request: registers the install, or refreshes it. */
export interface DeviceRegistration {
  device_id: DeviceId;
  /** Generated at install time from the shared word lists, renamable. */
  name: string;
  platform: RegistrablePlatform;
  /** The app version, `[0-9A-Za-z.+-]`, at most 32 characters. */
  app_version: string;
}

/**
 * One device of an account, as `GET /v1/devices` lists it and
 * `POST /v1/devices` answers it. Dates are `YYYY-MM-DD` (UTC).
 */
export interface DeviceView {
  device_id: DeviceId;
  name: string;
  platform: DevicePlatform;
  app_version: string;
  registered_on: string;
  last_seen_on: string;
  /** Whether it is the device the list was asked for. */
  this_device: boolean;
}

/** `GET /v1/devices` (signed) response. */
export interface DeviceListResponse {
  /** The account's active devices. */
  devices: DeviceView[];
  /**
   * The last day an older client of the account (one that does not register)
   * had its token reservation superseded. Absent when none ever was.
   */
  older_client_seen_on?: string;
}

/** `PATCH /v1/devices/{device_id}` (signed) request. */
export interface DeviceRename {
  name: string;
}
