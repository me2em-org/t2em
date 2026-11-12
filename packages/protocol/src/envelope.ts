/**
 * Envelope validation (server-side, crypto-agnostic) — ТЗ §5.2 errors,
 * §4.5 taxonomy (`UNSUPPORTED_VERSION`, `MALFORMED`), §11.4 injection
 * protection (`safeJsonParse`).
 */
import { T2EM_PROTOCOL_VERSION, type Envelope } from './index.js';
import { isB64uOfLength, b64uDecodeStrict } from './base64url.js';

export const MAX_IV_BYTES = 12;
export const MAX_EPHEMERAL_PUBKEY_BYTES = 32;
export const MAX_ED25519_SIG_BYTES = 64; // Ed25519 signature size
export const MAX_ED25519_PUBKEY_BYTES = 32; // Ed25519 public key size

/** Validation failure carrying a taxonomy code (§4.5). */
export class EnvelopeValidationError extends Error {
  constructor(
    public readonly code: 'UNSUPPORTED_VERSION' | 'MALFORMED',
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = 'EnvelopeValidationError';
  }
}

/** Structural field checks shared by both modes. */
function checkCommonFields(v: Record<string, unknown>): void {
  if (typeof v.ciphertext !== 'string' || v.ciphertext.length === 0) {
    throw new EnvelopeValidationError('MALFORMED', 'ciphertext must be a non-empty base64url string');
  }
  if (typeof v.iv !== 'string' || !isB64uOfLength(v.iv, MAX_IV_BYTES)) {
    throw new EnvelopeValidationError('MALFORMED', `iv must be base64url of exactly ${MAX_IV_BYTES} bytes`);
  }
  // Ciphertext = AES-GCM output + 16-byte tag ⇒ decodes to ≥ 16 bytes.
  let ctBytes: number;
  try {
    ctBytes = b64uDecodeStrict(v.ciphertext).length;
  } catch {
    throw new EnvelopeValidationError('MALFORMED', 'ciphertext is not valid base64url');
  }
  if (ctBytes < 16) {
    throw new EnvelopeValidationError('MALFORMED', 'ciphertext shorter than GCM tag (16 bytes)');
  }
}

/**
 * Validate an unknown value as a protocol-v1 envelope. Throws
 * `EnvelopeValidationError` on any deviation; returns the narrowed
 * envelope otherwise. Mode A additionally requires `ephemeralPubKey`.
 */
export function validateEnvelope(value: unknown): Envelope {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new EnvelopeValidationError('MALFORMED', 'envelope must be a JSON object');
  }
  const v = value as Record<string, unknown>;

  if (v.v !== T2EM_PROTOCOL_VERSION) {
    // Distinguish "wrong version" from "missing/invalid field" (§4.5).
    if (typeof v.v === 'number') {
      throw new EnvelopeValidationError('UNSUPPORTED_VERSION', `envelope.v=${v.v}`);
    }
    throw new EnvelopeValidationError('MALFORMED', 'envelope.v must be a number');
  }

  checkCommonFields(v);

  if (v.mode === 'sym') {
    return {
      v: T2EM_PROTOCOL_VERSION,
      mode: 'sym',
      ciphertext: v.ciphertext as string,
      iv: v.iv as string,
    };
  }

  if (v.mode === 'x25519') {
    if (typeof v.ephemeralPubKey !== 'string' || !isB64uOfLength(v.ephemeralPubKey, MAX_EPHEMERAL_PUBKEY_BYTES)) {
      throw new EnvelopeValidationError(
        'MALFORMED',
        `ephemeralPubKey must be base64url of exactly ${MAX_EPHEMERAL_PUBKEY_BYTES} bytes`,
      );
    }
    const env: Envelope = {
      v: T2EM_PROTOCOL_VERSION,
      mode: 'x25519',
      ephemeralPubKey: v.ephemeralPubKey,
      ciphertext: v.ciphertext as string,
      iv: v.iv as string,
    };
    if (v.senderSignature !== undefined) {
      if (typeof v.senderSignature !== 'string' || !isB64uOfLength(v.senderSignature, MAX_ED25519_SIG_BYTES)) {
        throw new EnvelopeValidationError('MALFORMED', 'senderSignature must be base64url of exactly 64 bytes');
      }
      env.senderSignature = v.senderSignature;
    }
    if (v.senderPubKey !== undefined) {
      if (typeof v.senderPubKey !== 'string' || !isB64uOfLength(v.senderPubKey, MAX_ED25519_PUBKEY_BYTES)) {
        throw new EnvelopeValidationError('MALFORMED', 'senderPubKey must be base64url of exactly 32 bytes');
      }
      env.senderPubKey = v.senderPubKey;
    }
    return env;
  }

  throw new EnvelopeValidationError('MALFORMED', `unknown envelope.mode: ${String(v.mode)}`);
}

/**
 * Prototype-safe JSON parse (ТЗ §11.4 Injection): rejects payloads
 * containing `__proto__` / `constructor.prototype` keys outright.
 */
export function safeJsonParse(text: string): unknown {
  const parsed: unknown = JSON.parse(text, (key, value) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new EnvelopeValidationError('MALFORMED', `forbidden key: ${key}`);
    }
    return value;
  });
  return parsed;
}
