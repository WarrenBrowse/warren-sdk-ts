/**
 * EdgeConnect: the browser-side Warren multi-hop client wire layer.
 *
 * Seals `WarrenMultihopFrame`s an exit can HPKE-open (`./seal.ts`, `./hpke.ts`)
 * and the postcard frame codec (`./frame.ts`), all byte-for-byte compatible with
 * the Rust `warrenguard-multihop` and pinned by the shared golden vectors plus a
 * cross-language open test. The WebTransport transport that carries these frames
 * lives in `@warrenbrowse/sdk-extension` (browser-only APIs).
 */
export {
  decodeMultihopFrame,
  encodeMultihopFrame,
  WARREN_HPKE_VERSION,
  type WarrenMultihopFrame,
} from './frame.js';
export {
  decodeMultihopFrameV2,
  encodeMultihopFrameV2,
  WARREN_HPKE_VERSION_V2,
  type WarrenMultihopFrameV2,
} from './frame-v2.js';
export { WarrenClientSession } from './seal.js';
export { WarrenPqClientSession, WarrenPqExitSession } from './pq-seal.js';
export {
  type ExitDescriptorPq,
  exitDescriptorSigningPayloadPq,
  MLKEM768_ENCAPS_KEY_LEN,
  negotiatePq,
  parseExitDescriptorPqJson,
  PqAvailability,
  verifyExitDescriptorPq,
  WARREN_PKI_OPERATIONAL_EXIT_PQ_V1,
  WarrenPqError,
  type WarrenPqErrorCode,
} from './pq-descriptor.js';
export {
  XWING_CT_LEN,
  XWING_LABEL,
  XWING_MLKEM_CT_LEN,
  XWING_MLKEM_EK_LEN,
  XWING_X25519_LEN,
  type XWingCiphertext,
  xwingCombiner,
  xwingDecapsulate,
  xwingEncapsulate,
  xwingEncapsulateRandom,
  type XWingEncapsulation,
  type XWingRecipientKeypair,
  xwingRecipientFromComponentSeeds,
  xwingRecipientFromParts,
  xwingRecipientFromXwingSeed,
  xwingRecipientPublicFromDescriptor,
  type XWingRecipientPublicKey,
  type XWingRecipientSecretKey,
  type XWingReferenceOutput,
  xwingReferenceFlow,
} from './xwing.js';
export {
  CONTROL_FIRST_BYTE,
  CONTROL_VERSION_V3,
  type ControlMessage,
  type DaitaConfig,
  decodeControlMessage,
  encodeIpRequestV7,
  type ExitDraining,
  type IpAssign,
  type IpExhausted,
  ipv4ToString,
  type Rejected,
} from './control.js';
export {
  acquireTokens,
  currentEpoch,
  issuerKeyForEpoch,
  mintEpoch,
  type TokenIssueRequest,
  type TokenIssueResponse,
  type TokenIssuerDirectory,
  type TokenIssuerKey,
  type TokenTransport,
} from './token-acquire.js';
export {
  BLINDING_PURPOSE_BROWSER_PROXY,
  BLINDING_PURPOSE_SESSION,
  blindingKeyFromSeed,
  deterministicTokenRandom,
  type TokenRandom,
} from './token-blinding.js';
export {
  INDEPENDENT_SESSION_PLACEMENT,
  type SessionAttempt,
  type SessionWalkResult,
  walkSessionTokens,
} from './session-walk.js';
export {
  InMemoryTokenPersistence,
  type SessionTokenLease,
  TokenManager,
  type TokenManagerOptions,
  type TokenPersistence,
} from './token-manager.js';
export {
  AUTHENTICATOR_LEN,
  blindToken,
  challengeDigestForEpoch,
  finalizeToken,
  type IssuerPublicKey,
  issuerPublicKey,
  issuerPublicKeyFromSpki,
  redemptionContextForEpoch,
  serializeTokenChallenge,
  Token,
  TOKEN_LEN,
  TOKEN_TYPE_BLIND_RSA,
  type TokenClientState,
  tokenChallengeDigest,
  tokenSerial,
} from './token.js';
export {
  FEATURE_MULTIPATH,
  FEATURE_PORT_FORWARD,
  MAX_SESSION_TOKENS,
  PROTOCOL_VERSION_V7,
  SESSION_TOKEN_LEN,
} from './setup.js';
export { decodeLeb128, encodeLeb128 } from './varint.js';
export { WARREN_EDGE_PORT } from './well-known.js';
export { WarrenEdgeError, type WarrenEdgeErrorCode } from './errors.js';
export {
  decodeQuicVarint,
  decodeWtDatagram,
  encodeBidiStreamHeader,
  encodeQuicVarint,
  encodeUniStreamHeader,
  encodeWtDatagram,
  quarterStreamId,
  WEBTRANSPORT_STREAM_BIDI,
  WEBTRANSPORT_STREAM_UNI,
} from './webtransport.js';
