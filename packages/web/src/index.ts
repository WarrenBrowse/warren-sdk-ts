/**
 * `@warrenbrowse/sdk-web`: the browser control-plane entry for the Warren VPN SDK.
 *
 * A web page cannot be a VPN (no raw sockets, no TUN), so this exposes only the
 * browser-safe control plane: the unsigned account API via {@link WarrenWebClient},
 * address codecs, and signed-list / directory verification plus exit selection.
 *
 * It intentionally does NOT re-export the signing surface (seed derivation,
 * request signing, the seed-bearing `WarrenApiClient`): a web page must not hold
 * the identity seed, and signed calls belong on a backend. An advanced
 * non-custodial wallet that knows what it is doing can import `@warrenbrowse/sdk-core`
 * directly.
 */
export { WarrenWebClient, type WarrenWebClientOptions } from './web-client.js';

export {
  // Address codecs (public-key only).
  encodeAddress,
  decodeAddress,
  WARREN_SS58_PREFIX,
  // Discovery: verify signed lists / directory and select an exit.
  verifySignedRelayList,
  selectExit,
  selectExitWeighted,
  selectExitForAttempt,
  relayMatches,
  isExpired,
  verifyMultihopDirectory,
  isDirectoryExpired,
  acceptSignedRelayList,
  acceptMultihopDirectory,
  InMemoryGenerationStore,
  InMemoryServerKeyStore,
  NoRelayMatchError,
  // Errors and DTO types.
  WarrenApiError,
  WarrenDiscoveryError,
  WarrenDirectoryError,
  type HttpTransport,
  type GenerationStore,
  type ServerKeyStore,
  type AcceptOptions,
  type AcceptDirectoryOptions,
  type Relay,
  type VerifiedRelayList,
  type ExitQuery,
  type LocationConstraint,
  type IpAvailability,
  type VerifiedDirectory,
  type VerifiedExit,
  type RegisterAccountRequest,
  type RegisterAccountResponse,
} from '@warrenbrowse/sdk-core';
