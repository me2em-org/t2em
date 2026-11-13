/**
 * @t2em/protocol — cryptographic core of t2em.com.
 *
 * Protocol v1 constants and envelope shapes (ТЗ docs/TZ_t2em.md §4).
 * Implementation of the envelope algorithms lands in Этап 1–2;
 * this module already fixes the wire-level constants so that the
 * relay, CLI, SDK and MCP server share a single source of truth.
 */

/** Envelope / protocol version. Changes only via a new `/v2` (§4.5). */
export const T2EM_PROTOCOL_VERSION = 1 as const;

/** Drop lifetime bounds in seconds (ТЗ §4, §6.1). */
export const MIN_TTL_SECONDS = 60;
export const MAX_TTL_SECONDS = 900;

/**
 * HKDF info string for drop key derivation (ТЗ §4.2 step 5).
 *
 * FREEZE RULE (§4.5): this string feeds HKDF key derivation. It may
 * never be edited in place — key rotation happens through a new
 * `/v2` info string and a new `envelope.v`.
 */
export const HKDF_INFO_DROP_V1 = 'me2em/crypto/v1/t2em-drop';

/** base64url (RFC 4648 §5, no padding) encoded byte string. */
export type Base64Url = string;

/** 8-char recipient fingerprint: base64url(sha256(pubkey))[0..8] (§4.2.1). */
export type Fingerprint = string;

/** Mode A envelope — asymmetric E2EE on X25519 (ТЗ §4.2). */
export interface ModeAEnvelope {
  v: typeof T2EM_PROTOCOL_VERSION;
  mode: 'x25519';
  /** Ephemeral sender X25519 public key, base64url, 32 bytes. */
  ephemeralPubKey: Base64Url;
  /** AES-256-GCM ciphertext + 16-byte tag, base64url. */
  ciphertext: Base64Url;
  /** 12-byte IV, base64url. */
  iv: Base64Url;
  /** Optional Ed25519 sender signature, base64url, 64 bytes. */
  senderSignature?: Base64Url;
  /** Optional Ed25519 sender public key, base64url, 32 bytes. */
  senderPubKey?: Base64Url;
}

/** Mode B envelope — symmetric #fragment bootstrap (ТЗ §4.3). */
export interface ModeBEnvelope {
  v: typeof T2EM_PROTOCOL_VERSION;
  mode: 'sym';
  /** AES-256-GCM ciphertext + 16-byte tag, base64url. */
  ciphertext: Base64Url;
  /** 12-byte IV, base64url. */
  iv: Base64Url;
}

/** Wire type stored (opaque) by the relay in `drop:{id}`. */
export type Envelope = ModeAEnvelope | ModeBEnvelope;

// NOTE: envelope validation lives exclusively in `./envelope.js`
// (`validateEnvelope`, `isEnvelope`, `EnvelopeValidationError`,
// `safeJsonParse`) — re-exported below. Do not add inline copies here.

// ---------------------------------------------------------------------------
// Phase 1A — Mode B crypto core, validation, shared primitives (ТЗ §4.3–§4.5)
// ---------------------------------------------------------------------------

export * from './base64url.js';
export * from './hash.js';
export * from './fingerprint.js';
export * from './envelope.js';
export * from './mode-b.js';

// ---------------------------------------------------------------------------
// Этап 2 — Mode A crypto (X25519 E2EE, ТЗ §4.2)
// ---------------------------------------------------------------------------

export * from './mode-a.js';
